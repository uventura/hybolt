import hashlib
import json
import math
import time
from pathlib import Path

from hybolt.constant import DEFAULT_BLOCK_SIZE_PERCENTAGE, MAX_MAC_THREADS
from hybolt.encryption.encode import Encode
from hybolt.encryption.encoding_metadata import (
    BlockMetadata,
    ChunkMetadata,
    EncodingMetadata,
    PacketMetadata,
)
from hybolt.encryption.digest import Digest
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import (
    advance_progress,
    create_progress_task,
    get_progress,
)
from hybolt.server.packet_saver import PacketSaver
from hybolt.utils.decorators import stop_record_timeit


class HyboltEncode:
    def __init__(
        self,
        input_file: str,
        block_size: int | None = None,
        server_list: list = None,
        metadata_output: str = "./",
        max_threads: int = MAX_MAC_THREADS,
        chunk_count: int | None = None,
    ):
        self.input_file = input_file
        self.block_size = block_size
        self.server_list = server_list
        self.metadata_output = metadata_output
        self.max_threads = max_threads
        self.chunk_count = chunk_count
        self.average_chunk_encode_seconds = 0.0
        self.average_block_size = 0.0
        self.average_polynomial_division_seconds = 0.0

    @stop_record_timeit
    def encode(self) -> int:
        input_path = Path(self.input_file)
        execution_logger.debug(
            "Encoding input: "
            f"path={input_path}, bytes={input_path.stat().st_size}, "
            f"chunk_size={Digest(input_path, chunk_count=self.chunk_count).chunk_size}, "
            f"chunks={Digest(input_path, chunk_count=self.chunk_count).chunk_count}, "
            f"servers={len(self.server_list or [])}, max_threads={self.max_threads}"
        )
        digest = Digest(input_path, chunk_count=self.chunk_count)
        chunks = []
        packet_count = 0
        chunk_encode_durations = []
        total_block_bytes = 0
        block_count = 0
        polynomial_division_total_seconds = 0.0
        polynomial_division_count = 0
        progress = get_progress()
        chunk_task_id = create_progress_task(
            progress,
            "Encoding chunks",
            total=digest.chunk_count,
        )

        for chunk_index, chunk_data in digest.chunks():
            block_size = self._determine_block_size(len(chunk_data))
            execution_logger.debug(
                f"Encoding chunk {chunk_index + 1}/{digest.chunk_count}: "
                f"bytes={len(chunk_data)}, block_size={block_size}"
            )
            encode_started_at = time.perf_counter()
            encoded = Encode(chunk_data, block_size, self.max_threads)
            chunk_encode_durations.append(time.perf_counter() - encode_started_at)
            total_block_bytes += encoded.total_block_bytes
            block_count += encoded.num_blocks
            polynomial_division_total_seconds += (
                encoded.polynomial_division_total_seconds
            )
            polynomial_division_count += encoded.polynomial_division_count
            saver = PacketSaver(
                encoded.packets, input_path, self.server_list, chunk_index
            )
            saver.save()
            chunks.append(
                self._collect_chunk_metadata(
                    encoded, saver, chunk_index, len(chunk_data)
                )
            )
            packet_count += len(encoded.packets)
            advance_progress(progress, chunk_task_id)

        if chunk_encode_durations:
            self.average_chunk_encode_seconds = sum(chunk_encode_durations) / len(
                chunk_encode_durations
            )
        if block_count:
            self.average_block_size = total_block_bytes / block_count
        if polynomial_division_count:
            self.average_polynomial_division_seconds = (
                polynomial_division_total_seconds / polynomial_division_count
            )
        execution_logger.debug("Starting metadata write")
        self._save_packet_metadata(input_path, chunks)
        execution_logger.debug("Encoding completed successfully")
        return packet_count

    def _collect_chunk_metadata(self, encoded, saver, chunk_index, byte_size):
        blocks = []
        for block_index, mac_list in encoded.mac_blocks.items():
            for local_mac in mac_list:
                blocks.append(
                    BlockMetadata(
                        mac_value=local_mac.mac,
                        block_index=block_index,
                        polynomial_index=local_mac.polynomial_index,
                    )
                )

        packets = []
        for packet in saver.packet_metadata:
            packets.append(packet)

        return ChunkMetadata(
            chunk_index=chunk_index,
            byte_size=byte_size,
            polynomials=encoded.polynomials,
            blocks=blocks,
            packets=packets,
        )

    def _determine_block_size(self, file_size: int) -> int:
        if self.block_size is None:
            return max(1, math.ceil(file_size * DEFAULT_BLOCK_SIZE_PERCENTAGE))

        if self.block_size <= 0:
            raise ValueError("Block size must be a positive integer")

        return self.block_size

    def _save_packet_metadata(self, input_path: Path, chunks: list[ChunkMetadata]):
        metadata = EncodingMetadata(
            polynomials=[],
            blocks=[],
            packets=[],
            original_filename=input_path.name,
            original_file_hash=self._sha256_file(input_path),
            chunks=chunks,
        )
        metadata.packet_root_hash = self._compute_packet_root(
            [packet for chunk in chunks for packet in chunk.packets]
        )
        metadata_file = (
            Path(self.metadata_output) / f"{Path(self.input_file).stem}_metadata.pkl"
        )
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        metadata.save(metadata_file)
        execution_logger.debug(
            f"Metadata written: path={metadata_file}, "
            f"blocks={len(metadata.blocks)}, packets={len(metadata.packets)}"
        )

    def _compute_packet_root(self, packets: list[PacketMetadata]) -> str:
        serialized_packets = [
            {
                "server": packet.server,
                "packet_index": packet.packet_index,
                "degree": packet.degree,
                "indices": packet.indices,
                "packet_file": packet.packet_file,
            }
            for packet in sorted(
                packets, key=lambda item: (item.server, item.packet_file)
            )
        ]
        payload = json.dumps(serialized_packets, sort_keys=True).encode("utf-8")
        return self._sha256_hex(payload)

    def _sha256_hex(self, payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def _sha256_file(self, input_path: Path) -> str:
        digest = hashlib.sha256()
        with input_path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
