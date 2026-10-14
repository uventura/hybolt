from raptorq import Encoder

from hybolt.encryption.block import Block
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import advance_progress, create_progress_task, get_progress
from hybolt.constant import MAX_MAC_THREADS


class Encode:
    def __init__(self, data, block_size, max_threads=MAX_MAC_THREADS):
        if not data:
            raise ValueError("Data cannot be empty")
        if not 1 <= max_threads <= MAX_MAC_THREADS:
            raise ValueError(f"max_threads must be between 1 and {MAX_MAC_THREADS}")

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
        self._polynomials = []
        self._mac_blocks = {}
        self._polynomial_division_total_seconds = 0.0
        self._polynomial_division_count = 0

        self._packets = self._encode()

    @property
    def packets(self):
        return list(self._packets)

    @property
    def symbol_size(self):
        return self._block_size

    @property
    def num_blocks(self):
        return self._num_blocks

    @property
    def mac_blocks(self):
        return self._mac_blocks

    @property
    def polynomials(self):
        return self._polynomials

    @property
    def average_block_size(self):
        return sum(len(block) for block in self._blocks) / len(self._blocks)

    @property
    def total_block_bytes(self):
        return sum(len(block) for block in self._blocks)

    @property
    def polynomial_division_total_seconds(self):
        return self._polynomial_division_total_seconds

    @property
    def polynomial_division_count(self):
        return self._polynomial_division_count

    def _encode(self):
        repair_packets_per_block = 2
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
