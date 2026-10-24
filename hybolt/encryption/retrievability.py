import random
import secrets
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor

import numpy as np

import hybolt.utils.galois as ga
from hybolt.constant import MAX_MAC_THREADS, POLYNOMIAL_SET_SIZE
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import advance_progress, create_progress_task, get_progress


class RetrievabilityProof(ABC):
    """Strategy for proving that a server still holds a packet before downloading it."""

    def __init__(self):
        self.polynomial_division_total_seconds = 0.0
        self.polynomial_division_count = 0

    @property
    @abstractmethod
    def enabled(self) -> bool:
        pass

    @property
    @abstractmethod
    def polynomials(self) -> list[np.ndarray]:
        pass

    @abstractmethod
    def tag_packets(self, packets) -> dict[int, list[np.ndarray]]:
        """Return the MACs of each packet, keyed by packet index, one per polynomial."""

    @abstractmethod
    def verify(self, server, block, expected_mac) -> bool:
        """Challenge `server` for `block`; `expected_mac(j)` gives the MAC for polynomial j."""


class PolynomialRetrievabilityProof(RetrievabilityProof):
    def __init__(
        self, polynomials=None, max_threads=MAX_MAC_THREADS, challenge_index=None
    ):
        super().__init__()
        self._max_threads = max_threads
        # The polynomial revealed in this session; random only when none was drawn.
        self.challenge_index = challenge_index
        self._polynomials = (
            list(polynomials)
            if polynomials is not None
            else self._polynomial_set_generation()
        )

    @property
    def enabled(self):
        return True

    @property
    def polynomials(self):
        return self._polynomials

    def tag_packets(self, packets):
        progress = get_progress()
        execution_logger.debug(
            f"Calculating {len(packets) * len(self._polynomials)} MACs "
            f"for {len(packets)} packets"
        )
        task_id = create_progress_task(
            progress,
            "Calculating packet MACs",
            total=len(packets),
        )

        packet_macs = {}
        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            for packet_index, macs, division_seconds in executor.map(
                self._calculate_packet_macs, packets
            ):
                packet_macs[packet_index] = macs
                self.polynomial_division_total_seconds += division_seconds
                self.polynomial_division_count += len(macs)
                advance_progress(progress, task_id)

        return packet_macs

    def verify(self, server, block, expected_mac):
        polynomial_index = self.challenge_index
        if polynomial_index is None:
            polynomial_index = random.randint(0, len(self._polynomials) - 1)
        polynomial = self._polynomials[polynomial_index]

        if block.packet_file:
            answer = server.receive_challenge(
                polynomial, block.index, block.packet_file
            )
        else:
            answer = server.receive_challenge(polynomial, block.index)

        verified = np.array_equal(
            _as_coefficients(expected_mac(polynomial_index)),
            _as_coefficients(answer),
        )
        if not verified:
            execution_logger.error(f"Validation failed for block index: {block.index}")

        return verified

    def _calculate_packet_macs(self, packet):
        representation = ga.bytes_to_poly_coeffs(packet.data)
        started_at = time.perf_counter()
        macs = [
            ga.gf2_poly_mod(representation, polynomial)
            for polynomial in self._polynomials
        ]
        return packet.index, macs, time.perf_counter() - started_at

    def _polynomial_set_generation(self):
        execution_logger.debug(
            f"Generating {POLYNOMIAL_SET_SIZE} challenge polynomials"
        )
        polynomials = []
        progress = get_progress()
        task_id = create_progress_task(
            progress,
            "Generating challenge polynomials",
            total=POLYNOMIAL_SET_SIZE,
        )

        while len(polynomials) < POLYNOMIAL_SET_SIZE:
            polynomial = ga.generate_challenge_polynomial()
            if polynomial.tolist() not in [p.tolist() for p in polynomials]:
                polynomials.append(polynomial)
                advance_progress(progress, task_id)

        return polynomials


class DisabledRetrievabilityProof(RetrievabilityProof):
    @property
    def enabled(self):
        return False

    @property
    def polynomials(self):
        return []

    def tag_packets(self, packets):
        return {}

    def verify(self, server, block, expected_mac):
        return True


def create_retrievability_proof(
    enabled: bool, polynomials=None, max_threads=MAX_MAC_THREADS
) -> RetrievabilityProof:
    if not enabled:
        return DisabledRetrievabilityProof()

    return PolynomialRetrievabilityProof(polynomials, max_threads)


class ChallengeSetExhaustedError(ValueError):
    pass


class ChallengeLedger:
    """Hands out each challenge polynomial once, as Hy-SAIL's bounded model requires.

    A server that learns P_j can keep c mod P_j and discard c, so a revealed
    polynomial must never be reused. The draw is persisted before the
    polynomial leaves the client, so a crash cannot cause a reuse either.
    """

    def __init__(self, metadata, metadata_file, polynomial_count):
        self._metadata = metadata
        self._metadata_file = metadata_file
        self._polynomial_count = polynomial_count

    @property
    def remaining(self) -> list[int]:
        used = set(self._metadata.used_polynomial_indices)
        return [index for index in range(self._polynomial_count) if index not in used]

    def draw(self) -> int:
        remaining = self.remaining
        if not remaining:
            raise ChallengeSetExhaustedError(
                f"All {self._polynomial_count} challenge polynomials were already "
                "revealed; re-encode the file to obtain a new challenge set"
            )

        index = secrets.choice(remaining)
        self._metadata.used_polynomial_indices.append(index)
        self._metadata.save(self._metadata_file)
        execution_logger.debug(
            f"Drew challenge polynomial {index}; {len(remaining) - 1} remaining"
        )
        return index


def xor_macs(macs):
    result = _as_coefficients(macs[0])
    for mac in macs[1:]:
        result = np.bitwise_xor(result, _as_coefficients(mac))
    return result


def _as_coefficients(value):
    if isinstance(value, bytes):
        return np.frombuffer(value, dtype=np.uint8)
    return np.asarray(value, dtype=np.uint8)
