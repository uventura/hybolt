import random
from concurrent.futures import ThreadPoolExecutor
from functools import reduce
import numpy as np

from hybolt.encryption.block import Block
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import advance_progress, create_progress_task, get_progress
import hybolt.utils.galois as ga
import hybolt.utils.operators as op
from hybolt.utils.padding import add_padding
from hybolt.constant import MAX_MAC_THREADS, POLYNOMIAL_SET_SIZE


# It uses LtCode
class Encode:
    def __init__(self, data, block_size, max_threads=MAX_MAC_THREADS):
        if not data:
            raise ValueError("Data cannot be empty")
        if not 1 <= max_threads <= MAX_MAC_THREADS:
            raise ValueError(
                f"max_threads must be between 1 and {MAX_MAC_THREADS}"
            )

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

        self._data = add_padding(data, self._block_size)
        advance_progress(self._progress, prepare_task_id)

        self._blocks = self._split_blocks(self._data, block_size)
        advance_progress(self._progress, prepare_task_id)
        execution_logger.debug(
            f"Prepared {len(self._blocks)} blocks after padding "
            f"({len(self._data)} bytes)"
        )

        execution_logger.debug(
            f"Generating {POLYNOMIAL_SET_SIZE} challenge polynomials"
        )
        self._polynomials = self._polynomial_set_generation()
        execution_logger.debug("Challenge polynomial generation completed")
        self._mac_blocks = self._calculate_mac_for_each_block()
        execution_logger.debug("MAC calculation completed")

        self._num_blocks = len(self._blocks)

        self._packets = self._encode()

    @property
    def packets(self):
        values = self._packets.values()
        return [pkt for sublist in values for pkt in sublist]

    @property
    def num_blocks(self):
        return self._num_blocks

    @property
    def mac_blocks(self):
        return self._mac_blocks

    @property
    def polynomials(self):
        return self._polynomials

    def _encode(self):
        packets = {}
        K = self._num_blocks
        overhead = 6
        num_to_send = int(K * overhead)
        probabilities = op.robust_soliton_distribution(K)
        execution_logger.debug(
            f"Generating {num_to_send} packets from {K} blocks with "
            f"{overhead}x redundancy"
        )

        task_id = create_progress_task(
            self._progress,
            "Encoding packets",
            total=num_to_send,
        )

        for index in range(num_to_send):
            packet = self._generate_packet(index, K, probabilities)
            degree = packet.degree
            if degree not in packets:
                packets[degree] = []
            packets[degree].append(packet)

            advance_progress(self._progress, task_id)

        return packets

    def _generate_packet(self, index, K, probabilities):
        degree = np.random.choice(range(len(probabilities)), p=probabilities)
        # Ensure degree is at least 1 (the RSD can sometimes have a tiny p(0))
        degree = max(1, degree)
        indices = random.sample(range(K), degree)

        data = reduce(op.xor_bytes, (self._blocks[i] for i in indices))
        return Block(index, int(degree), indices, data)

    def _split_blocks(self, data, block_size):
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]

    def _calculate_mac_for_each_block(self):
        mac_blocks = {}
        execution_logger.debug(
            f"Calculating {len(self._blocks) * len(self._polynomials)} MACs "
            f"for {len(self._blocks)} blocks"
        )
        task_id = create_progress_task(
            self._progress,
            "Calculating MAC blocks",
            total=len(self._blocks) * len(self._polynomials),
        )

        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            for block_index, block_macs in executor.map(
                self._calculate_mac_for_block,
                enumerate(self._blocks),
            ):
                mac_blocks[block_index] = block_macs
                execution_logger.debug(
                    f"Completed MACs for block {block_index + 1}/"
                    f"{len(self._blocks)}"
                )
                for _ in block_macs:
                    advance_progress(self._progress, task_id)

        return mac_blocks

    def _calculate_mac_for_block(self, block_data):
        block_index, block = block_data
        execution_logger.debug(
            f"Starting MACs for block {block_index + 1}/{len(self._blocks)} "
            f"({len(block)} bytes)"
        )
        representation = ga.bytes_to_poly_coeffs(block)
        macs = [
            op.calculate_mac_for_block(
                representation=representation,
                polynomial=polynomial,
                polynomial_index=polynomial_index,
                block_index=block_index,
            )
            for polynomial_index, polynomial in enumerate(self._polynomials)
        ]
        return block_index, macs

    def _polynomial_set_generation(self):
        polynomials = []
        task_id = create_progress_task(
            self._progress,
            "Generating challenge polynomials",
            total=POLYNOMIAL_SET_SIZE,
        )

        while len(polynomials) < POLYNOMIAL_SET_SIZE:
            polynomial = ga.generate_challenge_polynomial()
            if polynomial.tolist() not in [p.tolist() for p in polynomials]:
                polynomials.append(polynomial)
                advance_progress(self._progress, task_id)

        return polynomials
