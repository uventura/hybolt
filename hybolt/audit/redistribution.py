import hashlib
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from hybolt.audit.audit import PacketLocation
from hybolt.encryption import raptor
from hybolt.encryption.block import Block
from hybolt.encryption.codecs import CODECS, CODEC_NAMES, codec_module
from hybolt.encryption.encoding_metadata import EncodingMetadata, PacketMetadata
from hybolt.encryption.retrievability import COMPACT_SCHEME
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

    As in Hy-SAIL's Figure 3, a new packet is the XOR of packets other servers
    still hold: every R10 or Online Codes packet is the XOR of the source
    blocks in its support, so a fresh ESI's support is solved over GF(2) as a
    combination of the healthy packets' supports, preferring low-degree
    packets. Online Codes decode by peeling, which a set of supports spanning
    GF(2)^K does not guarantee, so their chunks get fresh check blocks until
    they peel again.
    Only the packets of that combination are downloaded, checked against their
    SHA-256 and XORed; the chunk is never decoded. Each lost packet is replaced
    by a packet with a fresh, never used ESI, stored on another server, and
    `extra_repair` further packets can be added to widen the chunk's margin.
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
            raise ValueError("Redistribution requires chunked metadata")

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
        if chunk.codec not in CODECS:
            raise ValueError(f"unsupported codec {chunk.codec}")

        lost_indices = {location.packet_index for location in locations}
        lost = [p for p in chunk.packets if p.packet_index in lost_indices]
        healthy = [p for p in chunk.packets if p.packet_index not in lost_indices]
        new_indices = self._new_indices(chunk, healthy, len(lost))
        generated = self._combine(chunk, healthy, new_indices)

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

    def _new_indices(self, chunk, healthy, lost_count):
        """Fresh ESIs replacing the lost packets, plus the requested extra ones."""
        k = chunk.source_packets
        codec = codec_module(chunk.codec)
        new_indices = list(
            range(
                chunk.next_packet_index,
                chunk.next_packet_index + lost_count + self._extra_repair,
            )
        )
        healthy_indices = [packet.packet_index for packet in healthy]
        # Without a spanning set no fresh packet can be built; _plan reports it.
        if not self._spans(chunk, healthy):
            return new_indices
        while not codec.recoverable(k, healthy_indices + new_indices):
            new_indices.append(new_indices[-1] + 1)
        return new_indices

    def _spans(self, chunk, packets):
        k = chunk.source_packets
        system = raptor.Gf2System(k)
        codec = codec_module(chunk.codec)
        for packet in packets:
            system.add(codec.symbol_support(k, packet.packet_index))
        return system.rank == k

    def _combine(self, chunk, healthy, new_indices):
        """Plain symbols of `new_indices`, each the XOR of verified healthy packets."""
        k = chunk.source_packets
        codec = codec_module(chunk.codec)
        candidates = sorted(
            healthy,
            key=lambda p: codec.symbol_support(k, p.packet_index).bit_count(),
        )
        while True:
            plans = self._plan(chunk, candidates, new_indices)
            needed = {index for plan in plans.values() for index in plan}
            symbols = {
                index: self._download(chunk, candidates[index]) for index in needed
            }
            rejected = {index for index, symbol in symbols.items() if symbol is None}
            if not rejected:
                break
            candidates = [
                packet
                for index, packet in enumerate(candidates)
                if index not in rejected
            ]

        execution_logger.debug(
            f"Chunk {chunk.chunk_index}: rebuilding {len(new_indices)} packets "
            f"from {len(needed)} of {len(healthy)} healthy packets"
        )
        generated = {}
        for esi, plan in plans.items():
            value = 0
            for index in plan:
                value ^= int.from_bytes(symbols[index], "big")
            generated[esi] = value.to_bytes(chunk.symbol_size, "big")
        return generated

    def _plan(self, chunk, candidates, new_indices):
        """For each new ESI, the candidate positions whose packets XOR to it."""
        k = chunk.source_packets
        codec = codec_module(chunk.codec)
        system = raptor.Gf2System(k)
        for position, packet in enumerate(candidates):
            system.add(codec.symbol_support(k, packet.packet_index), 1 << position)

        plans = {}
        for esi in new_indices:
            remainder, combination = system.reduce(codec.symbol_support(k, esi))
            if remainder:
                raise ValueError(
                    f"Insufficient valid {CODEC_NAMES[chunk.codec]} packets to "
                    f"rebuild packet {esi}"
                )
            plans[esi] = raptor.support_indices(combination)
        return plans

    def _download(self, chunk, packet):
        """The opened symbol of a stored packet, or None when it cannot be trusted."""
        server = self._servers.get(packet.server)
        if server is None:
            return None
        try:
            data = server.download_block(packet.packet_index, packet.packet_file)
        except ValueError:
            return None
        if hashlib.sha256(data).hexdigest() != packet.packet_sha256:
            execution_logger.error(
                f"Packet {packet.packet_index} of chunk {chunk.chunk_index} "
                "does not match its SHA-256; leaving it out of the repair"
            )
            return None
        sealer = self._metadata.sealing_keys
        if sealer is None:
            return data
        return sealer.open(chunk.chunk_index, packet.packet_index, data)

    def _seal(self, chunk, packet_index, packet_data):
        sealer = self._metadata.sealing_keys
        if sealer is None:
            return packet_data
        return sealer.seal(chunk.chunk_index, packet_index, packet_data)

    def _store(self, chunk, packet_index, packet_data, target):
        sealed = self._seal(chunk, packet_index, packet_data)
        block = Block(packet_index, 0, [], sealed)
        # The bounded scheme needs nothing new: the client derives the MAC of a
        # fresh ESI from its source block MACs.
        if self._metadata.proof_scheme == COMPACT_SCHEME:
            block.tag = self._metadata.compact_keys.tag(
                chunk.chunk_index, packet_index, sealed
            )

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
