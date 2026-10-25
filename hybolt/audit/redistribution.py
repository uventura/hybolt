import hashlib
import json
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path

from hybolt.audit.audit import PacketLocation
from hybolt.encryption import raptor
from hybolt.encryption.block import Block
from hybolt.encryption.decoding_strategy import Raptor10DecodingStrategy
from hybolt.encryption.encoding_metadata import EncodingMetadata, PacketMetadata
from hybolt.encryption.retrievability import (
    BOUNDED_SCHEME,
    COMPACT_SCHEME,
    DisabledRetrievabilityProof,
    PolynomialRetrievabilityProof,
)
from hybolt.logger.logger import execution_logger
from hybolt.server.server import Server


@dataclass(frozen=True)
class ReplacedPacket:
    chunk_index: int
    old_packet_index: int
    new_packet_index: int
    from_server: str
    to_server: str


@dataclass(frozen=True)
class AddedPacket:
    chunk_index: int
    packet_index: int
    server: str


@dataclass
class RedistributionReport:
    replaced: list[ReplacedPacket] = field(default_factory=list)
    added: list[AddedPacket] = field(default_factory=list)
    failed_chunks: dict[int, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return not self.failed_chunks


class Redistribution:
    """Hy-SAIL Redistribution phase for packets an audit found corrupted or lost.

    The affected chunk (not the whole file) is decoded from its verified
    packets first. Being a fountain code, R10 can then
    emit as many new repair packets as needed: each lost packet is replaced by a
    packet with a fresh, never used ESI, stored on another server, and
    `extra_repair` further packets can be added to widen the chunk's margin.
    Re-encoding is checked by regenerating a healthy packet and comparing it
    with its stored SHA-256.
    """

    def __init__(
        self,
        metadata_file,
        server_file,
        corrupted: list[PacketLocation],
        extra_repair=0,
    ):
        if extra_repair < 0:
            raise ValueError("extra_repair must not be negative")

        self._metadata_file = Path(metadata_file)
        self._metadata = EncodingMetadata.load(self._metadata_file)
        self._servers = self._load_servers(server_file)
        self._corrupted = corrupted
        self._extra_repair = extra_repair
        self._random = secrets.SystemRandom()
        if self._metadata.chunks is None:
            raise ValueError("Redistribution requires chunked R10 metadata")

    def run(self) -> RedistributionReport:
        report = RedistributionReport()
        chunks = {chunk.chunk_index: chunk for chunk in self._metadata.chunks}
        by_chunk = {}
        for location in self._corrupted:
            by_chunk.setdefault(location.chunk_index, []).append(location)

        for chunk_index, locations in sorted(by_chunk.items()):
            try:
                self._repair_chunk(chunks[chunk_index], locations, report)
            except ValueError as error:
                execution_logger.error(
                    f"Could not redistribute chunk {chunk_index}: {error}"
                )
                report.failed_chunks[chunk_index] = str(error)

        self._metadata.packet_root_hash = self._metadata.compute_packet_root()
        self._metadata.save(self._metadata_file)
        return report

    def _repair_chunk(self, chunk, locations, report):
        if chunk.codec != Raptor10DecodingStrategy.codec:
            raise ValueError(f"unsupported codec {chunk.codec}")

        lost_indices = {location.packet_index for location in locations}
        lost = [p for p in chunk.packets if p.packet_index in lost_indices]
        healthy = [p for p in chunk.packets if p.packet_index not in lost_indices]
        sealer = self._metadata.sealing_keys
        data = Raptor10DecodingStrategy(
            replace(chunk, packets=healthy),
            self._servers,
            DisabledRetrievabilityProof(),
            sealer,
        ).decode()

        new_indices = list(
            range(
                chunk.next_packet_index,
                chunk.next_packet_index + len(lost) + self._extra_repair,
            )
        )
        generated = self._generate(
            chunk, data, max(new_indices + [healthy[0].packet_index])
        )
        reference = healthy[0]
        rebuilt = self._seal(
            chunk, reference.packet_index, generated[reference.packet_index]
        )
        if hashlib.sha256(rebuilt).hexdigest() != reference.packet_sha256:
            raise ValueError("re-encoding does not reproduce the stored packets")

        excluded = {packet.server for packet in lost}
        for packet in lost:
            chunk.packets.remove(packet)
            source = self._servers.get(packet.server)
            if source is not None:
                source.remove_packet(packet.packet_file)

        for position, packet_index in enumerate(new_indices):
            target = self._pick_target(chunk, excluded)
            self._store(chunk, packet_index, generated[packet_index], target)
            if position < len(lost):
                report.replaced.append(
                    ReplacedPacket(
                        chunk_index=chunk.chunk_index,
                        old_packet_index=lost[position].packet_index,
                        new_packet_index=packet_index,
                        from_server=lost[position].server,
                        to_server=target._storage_location,
                    )
                )
            else:
                report.added.append(
                    AddedPacket(
                        chunk.chunk_index, packet_index, target._storage_location
                    )
                )

        chunk.next_packet_index += len(new_indices)
        chunk.repair_packets = len(chunk.packets) - chunk.source_packets

    def _generate(self, chunk, data, highest_index):
        """Emit the packets of every ESI up to `highest_index`."""
        repair = max(0, highest_index + 1 - chunk.source_packets)
        return dict(raptor.Encoder(data, chunk.symbol_size).symbols(repair))

    def _seal(self, chunk, packet_index, packet_data):
        sealer = self._metadata.sealing_keys
        if sealer is None:
            return packet_data
        return sealer.seal(chunk.chunk_index, packet_index, packet_data)

    def _store(self, chunk, packet_index, packet_data, target):
        sealed = self._seal(chunk, packet_index, packet_data)
        block = Block(packet_index, 0, [], sealed)
        macs = []
        if self._metadata.proof_scheme == COMPACT_SCHEME:
            block.tag = self._metadata.compact_keys.tag(
                chunk.chunk_index, packet_index, sealed
            )
        elif self._metadata.proof_scheme == BOUNDED_SCHEME:
            proof = PolynomialRetrievabilityProof(chunk.polynomials)
            macs = proof.tag_packets([block])[packet_index]

        packet_file = self._packet_file(chunk, packet_index)
        target.store_packet(block, packet_file)
        chunk.packets.append(
            PacketMetadata(
                server=target._storage_location,
                packet_index=packet_index,
                degree=0,
                indices=[],
                packet_file=packet_file,
                packet_sha256=hashlib.sha256(sealed).hexdigest(),
                macs=macs,
            )
        )
        execution_logger.debug(
            f"Stored new packet {packet_index} of chunk {chunk.chunk_index} "
            f"on {target._storage_location}"
        )

    def _packet_file(self, chunk, packet_index):
        sealer = self._metadata.sealing_keys
        if sealer is not None:
            return sealer.packet_file(chunk.chunk_index, packet_index)
        stem = Path(self._metadata.original_filename).stem
        return f"{stem}_chunk_{chunk.chunk_index}_packet_{packet_index}.pkl"

    def _pick_target(self, chunk, excluded):
        """Prefer servers holding the fewest packets of this chunk."""
        candidates = [
            server
            for location, server in self._servers.items()
            if location not in excluded
        ] or list(self._servers.values())
        if not candidates:
            raise ValueError("no server available to store repaired packets")

        load = {}
        for packet in chunk.packets:
            load[packet.server] = load.get(packet.server, 0) + 1
        fewest = min(load.get(server._storage_location, 0) for server in candidates)
        return self._random.choice(
            [
                server
                for server in candidates
                if load.get(server._storage_location, 0) == fewest
            ]
        )

    def _load_servers(self, server_file):
        with open(server_file, "r") as file:
            data = json.load(file)
        servers = [
            Server(server_dict["storage_location"])
            for server_dict in data.get("servers", [])
        ]
        return {server._storage_location: server for server in servers}
