import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import hybolt.utils.galois as ga
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import ChallengeLedger
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
    tolerated_losses: int
    corrupted: int = 0

    @property
    def retrievable(self) -> bool:
        return self.corrupted <= self.tolerated_losses


@dataclass
class AuditReport:
    polynomial_index: int
    remaining_challenges: int
    servers: list[ServerAudit]
    chunks: list[ChunkAudit]

    @property
    def corrupted_packets(self) -> list[PacketLocation]:
        return [packet for server in self.servers for packet in server.corrupted]

    @property
    def passed(self) -> bool:
        return all(server.passed for server in self.servers) and all(
            chunk.retrievable for chunk in self.chunks
        )


class Audit:
    """Hy-SAIL Auditing phase (Algorithm 2) in the bounded model.

    Each round reveals one unused challenge polynomial P_j. Every server is asked
    for (sum of x^k_eta * c_eta) mod P_j over a random sample of its packets; the answer
    is compared with the XOR of the stored MACs. Each packet is weighted by a
    secret x^k_eta so that equal corruptions cannot cancel in the XOR (see
    galois.aggregate_remainders). When the aggregate fails, the
    sampled packets are checked one by one with the same, already revealed, P_j
    to locate the corrupted ones.
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
        polynomials = self._metadata.polynomials
        ledger = ChallengeLedger(self._metadata, self._metadata_file, len(polynomials))
        polynomial_index = ledger.draw()
        polynomial = polynomials[polynomial_index]
        execution_logger.debug(
            f"Audit round with challenge polynomial {polynomial_index}"
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
        for storage_location, packets in self._packets_by_server().items():
            audit = self._audit_server(
                storage_location, packets, polynomial, polynomial_index
            )
            for location in audit.corrupted:
                chunks[location.chunk_index].corrupted += 1
            server_audits.append(audit)

        return AuditReport(
            polynomial_index=polynomial_index,
            remaining_challenges=len(ledger.remaining),
            servers=server_audits,
            chunks=sorted(chunks.values(), key=lambda chunk: chunk.chunk_index),
        )

    def _audit_server(self, storage_location, packets, polynomial, polynomial_index):
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
            raise ValueError(
                f"Server not found for storage location: {storage_location}"
            )

        shifts = self._random_shifts(len(sample))
        expected = ga.aggregate_remainders(
            [packet.macs[polynomial_index] for _, packet in sample], polynomial, shifts
        )
        try:
            answer = server.receive_aggregate_challenge(
                polynomial, [packet.packet_file for _, packet in sample], shifts
            )
            if np.array_equal(expected, answer):
                return audit
        except ValueError as error:
            execution_logger.error(
                f"Aggregate challenge failed on {storage_location}: {error}"
            )

        audit.corrupted = [
            self._location(chunk_index, packet)
            for chunk_index, packet in sample
            if not self._packet_answers(server, packet, polynomial, polynomial_index)
        ]
        execution_logger.error(
            f"Server {storage_location}: {audit.tau_provider} corrupted packets "
            f"out of {audit.checked_packets} checked"
        )
        return audit

    def _random_shifts(self, count):
        """Distinct secret exponents k_eta for the x^k_eta weights of a challenge."""
        return self._random.sample(range(1, _MAX_SHIFT), count)

    def _packet_answers(self, server, packet, polynomial, polynomial_index):
        try:
            answer = server.receive_aggregate_challenge(
                polynomial, [packet.packet_file]
            )
        except ValueError:
            return False
        expected = ga.aggregate_remainders([packet.macs[polynomial_index]], polynomial)
        return np.array_equal(expected, answer)

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
        polynomial_count = len(self._metadata.polynomials)
        if self._metadata.chunks is None or polynomial_count == 0:
            raise ValueError(
                "Audit requires metadata encoded with the retrievability proof; "
                "re-encode the file with --retrievability-proof"
            )
        for unit in self._units():
            for packet in unit.packets:
                if len(packet.macs) != polynomial_count:
                    raise ValueError(
                        f"Packet {packet.packet_index} of chunk {unit.chunk_index} "
                        "has no MAC for every challenge polynomial"
                    )

    def _load_servers(self, server_file):
        with open(server_file, "r") as file:
            data = json.load(file)
        servers = [
            Server(server_dict["storage_location"])
            for server_dict in data.get("servers", [])
        ]
        return {server._storage_location: server for server in servers}
