import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import hybolt.utils.galois as ga
from hybolt.encryption.codecs import DEFAULT_CODEC, codec_module
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import (
    BOUNDED_SCHEME,
    COMPACT_SCHEME,
    ChallengeLedger,
    CompactRetrievabilityProof,
    SourceMacs,
)
from hybolt.logger.logger import execution_logger
from hybolt.server.server import Server

# Exponents stay far below 2^lambda - 1, the order of x modulo a primitive P_j,
# so distinct exponents give distinct weights.
_MAX_SHIFT = 1 << 32


@dataclass(frozen=True)
class PacketLocation:
    chunk_index: int
    packet_index: int
    server: str
    packet_file: str


@dataclass
class ServerAudit:
    server: str
    stored_packets: int
    checked_packets: int
    corrupted: list[PacketLocation] = field(default_factory=list)
    tau_maximum: int = 0

    @property
    def tau_provider(self) -> int:
        return len(self.corrupted)

    @property
    def passed(self) -> bool:
        return self.tau_provider <= self.tau_maximum


@dataclass
class ChunkAudit:
    chunk_index: int
    packets: int
    # Repair packets r; neither code is MDS, so some sets of r losses already hurt.
    tolerated_losses: int
    corrupted: int = 0
    # Whether the packets not found corrupted still span the K source blocks.
    retrievable: bool = True


@dataclass
class AuditReport:
    scheme: str
    servers: list[ServerAudit]
    chunks: list[ChunkAudit]
    # Bounded scheme only: the polynomial revealed in this round and those left.
    polynomial_index: int | None = None
    remaining_challenges: int | None = None

    @property
    def corrupted_packets(self) -> list[PacketLocation]:
        return [packet for server in self.servers for packet in server.corrupted]

    @property
    def passed(self) -> bool:
        return all(server.passed for server in self.servers) and all(
            chunk.retrievable for chunk in self.chunks
        )


class AuditChallenge(ABC):
    """Strategy for one round's challenge over a sample of (chunk, packet) pairs."""

    polynomial_index = None
    remaining_challenges = None

    @abstractmethod
    def check(self, server, sample) -> bool:
        pass


class BoundedAuditChallenge(AuditChallenge):
    """Hy-SAIL Algorithm 2 with a single-use public polynomial P_j.

    The server answers (sum of x^k_eta * c_eta) mod P_j and the client compares it
    with the same combination of the packet MACs, which it derives from its
    source block MACs. The secret x^k_eta weights stop equal corruptions from
    cancelling in the XOR (see galois.aggregate_remainders).
    """

    def __init__(self, metadata, metadata_file, random):
        ledger = ChallengeLedger(metadata, metadata_file, len(metadata.polynomials))
        self.polynomial_index = ledger.draw()
        self.remaining_challenges = len(ledger.remaining)
        self._polynomial = metadata.polynomials[self.polynomial_index]
        self._random = random
        self._source_macs = {
            chunk.chunk_index: SourceMacs(chunk, metadata.sealing_keys)
            for chunk in metadata.chunks
        }

    def check(self, server, sample):
        shifts = (
            self._random.sample(range(1, _MAX_SHIFT), len(sample))
            if len(sample) > 1
            else None
        )
        expected = ga.aggregate_remainders(
            [
                self._source_macs[chunk_index].packet_mac(
                    packet.packet_index, self.polynomial_index
                )
                for chunk_index, packet in sample
            ],
            self._polynomial,
            shifts,
        )
        answer = server.receive_aggregate_challenge(
            self._polynomial, [packet.packet_file for _, packet in sample], shifts
        )
        return np.array_equal(expected, answer)


class CompactAuditChallenge(AuditChallenge):
    """Unbounded challenge: the secret polynomial never leaves the client."""

    def __init__(self, keys):
        self._proof = CompactRetrievabilityProof(keys)

    def check(self, server, sample):
        return self._proof.challenge(
            server,
            [
                (chunk_index, packet.packet_index, packet.packet_file)
                for chunk_index, packet in sample
            ],
        )


class Audit:
    """Hy-SAIL Auditing phase over a random sample of each server's packets.

    The challenge itself is an AuditChallenge chosen by the metadata's proof
    scheme. When a server's aggregate answer fails, the sampled packets are
    challenged one by one, in the same round, to locate the corrupted ones.
    """

    def __init__(self, metadata_file, server_file, sample_size=None, tau_maximum=0):
        if sample_size is not None and sample_size < 1:
            raise ValueError("sample_size must be positive")
        if tau_maximum < 0:
            raise ValueError("tau_maximum must not be negative")

        self._metadata_file = Path(metadata_file)
        self._metadata = EncodingMetadata.load(self._metadata_file)
        self._servers = self._load_servers(server_file)
        self._sample_size = sample_size
        self._tau_maximum = tau_maximum
        self._random = secrets.SystemRandom()
        self._validate_metadata()

    def run(self) -> AuditReport:
        challenge = self._create_challenge()
        execution_logger.debug(
            f"Audit round: scheme={self._metadata.proof_scheme}, "
            f"polynomial={challenge.polynomial_index}"
        )

        chunks = {
            unit.chunk_index: ChunkAudit(
                chunk_index=unit.chunk_index,
                packets=len(unit.packets),
                tolerated_losses=unit.repair_packets,
            )
            for unit in self._units()
        }
        server_audits = []
        corrupted = set()
        for storage_location, packets in self._packets_by_server().items():
            audit = self._audit_server(storage_location, packets, challenge)
            for location in audit.corrupted:
                chunks[location.chunk_index].corrupted += 1
                corrupted.add((location.chunk_index, location.packet_index))
            server_audits.append(audit)
        for unit in self._units():
            chunks[unit.chunk_index].retrievable = self._recoverable(unit, corrupted)

        return AuditReport(
            scheme=self._metadata.proof_scheme,
            servers=server_audits,
            chunks=sorted(chunks.values(), key=lambda chunk: chunk.chunk_index),
            polynomial_index=challenge.polynomial_index,
            remaining_challenges=challenge.remaining_challenges,
        )

    def _create_challenge(self) -> AuditChallenge:
        if self._metadata.proof_scheme == COMPACT_SCHEME:
            return CompactAuditChallenge(self._metadata.compact_keys)
        return BoundedAuditChallenge(self._metadata, self._metadata_file, self._random)

    def _audit_server(self, storage_location, packets, challenge):
        sample_size = min(self._sample_size or len(packets), len(packets))
        sample = self._random.sample(packets, sample_size)
        audit = ServerAudit(
            server=storage_location,
            stored_packets=len(packets),
            checked_packets=len(sample),
            tau_maximum=self._tau_maximum,
        )

        server = self._servers.get(storage_location)
        if server is None:
            # A server that left the deployment holds nothing retrievable.
            execution_logger.error(f"Server {storage_location} is unavailable")
            audit.checked_packets = len(packets)
            audit.corrupted = [
                self._location(chunk_index, packet) for chunk_index, packet in packets
            ]
            return audit

        if self._answers(server, sample, challenge):
            return audit

        audit.corrupted = [
            self._location(chunk_index, packet)
            for chunk_index, packet in sample
            if not self._answers(server, [(chunk_index, packet)], challenge)
        ]
        execution_logger.error(
            f"Server {storage_location}: {audit.tau_provider} corrupted packets "
            f"out of {audit.checked_packets} checked"
        )
        return audit

    def _answers(self, server, sample, challenge):
        try:
            return challenge.check(server, sample)
        except ValueError as error:
            # A missing packet or tag is an erasure: the server cannot answer.
            execution_logger.error(
                f"Challenge failed on {server._storage_location}: {error}"
            )
            return False

    def _recoverable(self, unit, corrupted):
        """Exact check with the chunk's own decoder criterion (rank or peeling)."""
        codec = codec_module(getattr(unit, "codec", DEFAULT_CODEC))
        return codec.recoverable(
            unit.source_packets,
            [
                packet.packet_index
                for packet in unit.packets
                if (unit.chunk_index, packet.packet_index) not in corrupted
            ],
        )

    def _location(self, chunk_index, packet):
        return PacketLocation(
            chunk_index=chunk_index,
            packet_index=packet.packet_index,
            server=packet.server,
            packet_file=packet.packet_file,
        )

    def _units(self):
        return self._metadata.chunks if self._metadata.chunks is not None else []

    def _packets_by_server(self):
        packets = {}
        for unit in self._units():
            for packet in unit.packets:
                packets.setdefault(packet.server, []).append((unit.chunk_index, packet))
        return packets

    def _validate_metadata(self):
        scheme = self._metadata.proof_scheme
        if self._metadata.chunks is None or scheme not in (
            BOUNDED_SCHEME,
            COMPACT_SCHEME,
        ):
            raise ValueError(
                "Audit requires metadata encoded with the retrievability proof; "
                "re-encode the file with --retrievability-proof"
            )
        if scheme == COMPACT_SCHEME:
            if self._metadata.compact_keys is None:
                raise ValueError("Compact metadata is missing the client keys")
            return

        for unit in self._units():
            missing = SourceMacs(unit).missing()
            if missing is not None:
                raise ValueError(f"Chunk {unit.chunk_index} has {missing}")

    def _load_servers(self, server_file):
        with open(server_file, "r") as file:
            data = json.load(file)
        servers = [
            Server(server_dict["storage_location"])
            for server_dict in data.get("servers", [])
        ]
        return {server._storage_location: server for server in servers}
