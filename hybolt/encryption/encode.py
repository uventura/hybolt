import math

from raptorq import Encoder

from hybolt.encryption.block import Block
from hybolt.encryption.retrievability import (
    DisabledRetrievabilityProof,
    RetrievabilityProof,
)
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import advance_progress, create_progress_task, get_progress
from hybolt.constant import DEFAULT_REDUNDANCY, MAX_MAC_THREADS


class Encode:
    def __init__(
        self,
        data,
        block_size,
        max_threads=MAX_MAC_THREADS,
        proof: RetrievabilityProof | None = None,
        redundancy: float = DEFAULT_REDUNDANCY,
        chunk_index: int = 0,
        sealer=None,
    ):
        if not data:
            raise ValueError("Data cannot be empty")
        if not 1 <= max_threads <= MAX_MAC_THREADS:
            raise ValueError(f"max_threads must be between 1 and {MAX_MAC_THREADS}")
        if redundancy <= 0:
            raise ValueError("redundancy must be positive")

        self._progress = get_progress()
        self._block_size = block_size
        self._max_threads = max_threads
        execution_logger.debug(
            f"Preparing encoding data: input_bytes={len(data)}, "
            f"block_size={block_size}, max_threads={max_threads}"
        )

        prepare_task_id = create_progress_task(
            self._progress,
            "Preparing data for encoding",
            total=2,
        )

        self._data = data
        advance_progress(self._progress, prepare_task_id)

        self._blocks = self._split_blocks(self._data, block_size)
        advance_progress(self._progress, prepare_task_id)
        execution_logger.debug(
            f"Prepared {len(self._blocks)} blocks after padding "
            f"({len(self._data)} bytes)"
        )

        self._num_blocks = len(self._blocks)
        self._repair_packets = max(1, math.ceil(redundancy * self._num_blocks))
        # RaptorQ packets are not XORs of source blocks, so MACs are kept per packet.
        self._mac_blocks = {}
        self._proof = proof or DisabledRetrievabilityProof()

        self._packets = self._encode()
        if sealer is not None:
            # MACs, tags and hashes cover the sealed bytes the servers store.
            for packet in self._packets:
                packet.data = sealer.seal(chunk_index, packet.index, packet.data)
        self._packet_macs = self._proof.tag_packets(self._packets)
        self._proof.attach_server_tags(self._packets, chunk_index)

    @property
    def packets(self):
        return list(self._packets)

    @property
    def symbol_size(self):
        return self._block_size

    @property
    def repair_packets(self):
        return self._repair_packets

    @property
    def num_blocks(self):
        return self._num_blocks

    @property
    def mac_blocks(self):
        return self._mac_blocks

    @property
    def packet_macs(self):
        return self._packet_macs

    @property
    def polynomials(self):
        return self._proof.polynomials

    @property
    def average_block_size(self):
        return sum(len(block) for block in self._blocks) / len(self._blocks)

    @property
    def total_block_bytes(self):
        return sum(len(block) for block in self._blocks)

    @property
    def polynomial_division_total_seconds(self):
        return self._proof.polynomial_division_total_seconds

    @property
    def polynomial_division_count(self):
        return self._proof.polynomial_division_count

    def _encode(self):
        # Chunks fit in a single RaptorQ source block, so this is the chunk's total.
        repair_packets_per_block = self._repair_packets
        encoder = Encoder.with_defaults(self._data, self._block_size)
        encoded_packets = encoder.get_encoded_packets(repair_packets_per_block)
        execution_logger.debug(
            f"Generating {len(encoded_packets)} RaptorQ packets from "
            f"{self._num_blocks} source symbols with "
            f"{repair_packets_per_block} repair packets per source block"
        )

        task_id = create_progress_task(
            self._progress,
            "Encoding packets",
            total=len(encoded_packets),
        )

        packets = []
        for index, packet_data in enumerate(encoded_packets):
            packets.append(Block(index, 0, [], packet_data))
            advance_progress(self._progress, task_id)

        return packets

    def _split_blocks(self, data, block_size):
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]
