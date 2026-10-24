import hashlib
import json
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path

from raptorq import Encoder

from hybolt.audit.audit import PacketLocation
from hybolt.encryption.block import Block
from hybolt.encryption.decoding_strategy import RaptorQDecodingStrategy
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import (
    COMPACT_SCHEME,
    DisabledRetrievabilityProof,
)
from hybolt.logger.logger import execution_logger
from hybolt.server.server import Server


@dataclass(frozen=True)
class MovedPacket:
    chunk_index: int
    packet_index: int
    from_server: str
    to_server: str


@dataclass
class RedistributionReport:
    moved: list[MovedPacket] = field(default_factory=list)
    failed_chunks: dict[int, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return not self.failed_chunks


class Redistribution:
    """Hy-SAIL Redistribution phase for packets an audit found corrupted.

    Online Codes can rebuild a check block from other check blocks; RaptorQ
    repair symbols cannot, so the affected chunk (not the whole file) is decoded
    from its verified packets first. RaptorQ is deterministic, so re-encoding
    the chunk and taking the corrupted packet's ESI reproduces the original
    packet: its stored SHA-256 confirms the rebuild and its MACs stay valid.
    The packet is then stored on a different server.
    """

    def __init__(self, metadata_file, server_file, corrupted: list[PacketLocation]):
        self._metadata_file = Path(metadata_file)
        self._metadata = EncodingMetadata.load(self._metadata_file)
        self._servers = self._load_servers(server_file)
        self._corrupted = corrupted
        self._random = secrets.SystemRandom()
        if self._metadata.chunks is None:
            raise ValueError("Redistribution requires chunked RaptorQ metadata")

    def run(self) -> RedistributionReport:
        report = RedistributionReport()
        chunks = {chunk.chunk_index: chunk for chunk in self._metadata.chunks}
        by_chunk = {}
        for location in self._corrupted:
            by_chunk.setdefault(location.chunk_index, []).append(location)

        for chunk_index, locations in sorted(by_chunk.items()):
            try:
                report.moved.extend(
                    self._redistribute_chunk(chunks[chunk_index], locations)
                )
            except ValueError as error:
                execution_logger.error(
                    f"Could not redistribute chunk {chunk_index}: {error}"
                )
                report.failed_chunks[chunk_index] = str(error)

        self._metadata.packet_root_hash = self._metadata.compute_packet_root()
        self._metadata.save(self._metadata_file)
        return report

    def _redistribute_chunk(self, chunk, locations):
        if chunk.codec != RaptorQDecodingStrategy.codec:
            raise ValueError(f"unsupported codec {chunk.codec}")

        corrupted_indices = {location.packet_index for location in locations}
        healthy = replace(
            chunk,
            packets=[
                packet
                for packet in chunk.packets
                if packet.packet_index not in corrupted_indices
            ],
        )
        data = RaptorQDecodingStrategy(
            healthy, self._servers, DisabledRetrievabilityProof()
        ).decode()
        packets = Encoder.with_defaults(data, chunk.symbol_size).get_encoded_packets(
            chunk.repair_packets
        )

        moved = []
        for packet in chunk.packets:
            if packet.packet_index not in corrupted_indices:
                continue

            packet_data = packets[packet.packet_index]
            if hashlib.sha256(packet_data).hexdigest() != packet.packet_sha256:
                raise ValueError(
                    f"rebuilt packet {packet.packet_index} does not match its hash"
                )

            source = self._servers[packet.server]
            target = self._pick_target(packet.server)
            block = Block(packet.packet_index, 0, [], packet_data)
            if self._metadata.proof_scheme == COMPACT_SCHEME:
                block.tag = self._metadata.compact_keys.tag(
                    chunk.chunk_index, packet.packet_index, packet_data
                )
            block.set_server(target)
            target.store_packet(block, packet.packet_file)
            if target is not source:
                source.remove_packet(packet.packet_file)

            moved.append(
                MovedPacket(
                    chunk_index=chunk.chunk_index,
                    packet_index=packet.packet_index,
                    from_server=packet.server,
                    to_server=target._storage_location,
                )
            )
            packet.server = target._storage_location
            execution_logger.debug(
                f"Redistributed packet {packet.packet_index} of chunk "
                f"{chunk.chunk_index} from {moved[-1].from_server} to "
                f"{moved[-1].to_server}"
            )
        return moved

    def _pick_target(self, failed_server):
        candidates = [
            server
            for location, server in self._servers.items()
            if location != failed_server
        ]
        if not candidates:
            return self._servers[failed_server]
        return self._random.choice(candidates)

    def _load_servers(self, server_file):
        with open(server_file, "r") as file:
            data = json.load(file)
        servers = [
            Server(server_dict["storage_location"])
            for server_dict in data.get("servers", [])
        ]
        return {server._storage_location: server for server in servers}
