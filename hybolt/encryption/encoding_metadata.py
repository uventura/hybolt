import hashlib
import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import numpy as np


@dataclass
class BlockMetadata:
    mac_value: np.ndarray
    block_index: int
    polynomial_index: int


@dataclass
class PacketMetadata:
    server: str  # storage_location
    packet_index: int
    degree: int
    indices: List[int]
    packet_file: str = ""
    packet_sha256: str = ""
    # One retrievability MAC per challenge polynomial; empty when the proof is off.
    macs: List[np.ndarray] = field(default_factory=list)


@dataclass
class ChunkMetadata:
    chunk_index: int
    byte_size: int
    polynomials: List[np.ndarray]
    blocks: List[BlockMetadata]
    packets: List[PacketMetadata]
    codec: str = "raptorq"
    transfer_length: int = 0
    symbol_size: int = 0
    repair_packets: int = 0


@dataclass
class EncodingMetadata:
    polynomials: List[np.ndarray]
    blocks: List[BlockMetadata]
    packets: List[PacketMetadata]
    original_filename: str = ""
    original_file_hash: str = ""
    packet_root_hash: str = ""
    chunks: List[ChunkMetadata] | None = None
    # Challenge polynomials already revealed to a server (bounded model).
    used_polynomial_indices: List[int] = field(default_factory=list)
    # "bounded", "compact" or "" when encoded without a retrievability proof.
    proof_scheme: str = ""
    # CompactKeys of the compact scheme; the client must keep them secret.
    compact_keys: object | None = None

    def add_packet(
        self, server: str, packet_index: int, degree: int, indices: List[int]
    ):
        self.packets.append(PacketMetadata(server, packet_index, degree, indices))

    def all_packets(self) -> List[PacketMetadata]:
        if self.chunks is None:
            return list(self.packets)
        return [packet for chunk in self.chunks for packet in chunk.packets]

    def compute_packet_root(self) -> str:
        serialized_packets = [
            {
                "server": packet.server,
                "packet_index": packet.packet_index,
                "degree": packet.degree,
                "indices": packet.indices,
                "packet_file": packet.packet_file,
                "packet_sha256": packet.packet_sha256,
            }
            for packet in sorted(
                self.all_packets(), key=lambda item: (item.server, item.packet_file)
            )
        ]
        payload = json.dumps(serialized_packets, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def save(self, file_path: Path):
        with open(file_path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, file_path: Path) -> "EncodingMetadata":
        with open(file_path, "rb") as f:
            metadata = pickle.load(f)

        if not hasattr(metadata, "original_filename"):
            metadata.original_filename = ""
        if not hasattr(metadata, "original_file_hash"):
            metadata.original_file_hash = ""
        if not hasattr(metadata, "packet_root_hash"):
            metadata.packet_root_hash = ""
        if not hasattr(metadata, "chunks"):
            metadata.chunks = None
        if not hasattr(metadata, "used_polynomial_indices"):
            metadata.used_polynomial_indices = []
        # Plain dataclass defaults are class attributes, so hasattr() cannot tell
        # whether an older pickle stored these fields.
        if "compact_keys" not in vars(metadata):
            metadata.compact_keys = None
        if "proof_scheme" not in vars(metadata):
            has_polynomials = bool(metadata.polynomials) or any(
                chunk.polynomials for chunk in metadata.chunks or []
            )
            metadata.proof_scheme = "bounded" if has_polynomials else ""
        for packet in metadata.packets:
            if not hasattr(packet, "macs"):
                packet.macs = []
        if metadata.chunks is not None:
            for chunk in metadata.chunks:
                if not hasattr(chunk, "codec"):
                    chunk.codec = "lt"
                if not hasattr(chunk, "transfer_length"):
                    chunk.transfer_length = 0
                if not hasattr(chunk, "symbol_size"):
                    chunk.symbol_size = 0
                if not hasattr(chunk, "repair_packets"):
                    chunk.repair_packets = 0
                for packet in chunk.packets:
                    if not hasattr(packet, "packet_sha256"):
                        packet.packet_sha256 = ""
                    if not hasattr(packet, "macs"):
                        packet.macs = []

        return metadata
