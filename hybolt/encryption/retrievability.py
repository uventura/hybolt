import hashlib
import hmac
import random
import secrets
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import numpy as np

import hybolt.utils.galois as ga
from hybolt.constant import MAX_MAC_THREADS, POLYNOMIAL_SET_SIZE
from hybolt.encryption import raptor
from hybolt.encryption.codecs import DEFAULT_CODEC, codec_module
from hybolt.encryption.local_mac import LocalMac
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import advance_progress, create_progress_task, get_progress


BOUNDED_SCHEME = "bounded"
UNBOUNDED_SCHEME = "unbounded"
COMPACT_SCHEME = "compact"
# Schemes whose client keeps h_ij = m_i mod P_j for every source block.
POLYNOMIAL_SCHEMES = (BOUNDED_SCHEME, UNBOUNDED_SCHEME)


class RetrievabilityProof(ABC):
    """Strategy for proving that a server still holds a packet before downloading it."""

    scheme = ""
    # The client keeps one MAC per source block and polynomial (Hy-SAIL's
    # bounded model) and derives the MAC of any packet from them.
    requires_client_macs = False
    # Revealing a challenge lets the server forge future answers to it.
    single_use_challenges = False

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

    def tag_source_blocks(self, blocks) -> dict[int, list[LocalMac]]:
        """MACs the client keeps for each source block, one per polynomial."""
        return {}

    @abstractmethod
    def verify(self, server, block, expected_mac) -> bool:
        """Challenge `server` for `block`; `expected_mac(j)` gives the MAC for polynomial j."""

    def attach_server_tags(self, packets, chunk_index):
        """Set the tag each server stores next to a packet; none by default."""

    def verify_download(self, server, block, data, expected_mac=None) -> bool:
        """Check downloaded bytes after the transfer; nothing by default."""
        return True


class PolynomialRetrievabilityProof(RetrievabilityProof):
    """Hy-SAIL's bounded scheme: client-side MACs and single-use public challenges."""

    scheme = BOUNDED_SCHEME
    requires_client_macs = True
    single_use_challenges = True

    # None: the bounded set size, read when the set is generated.
    polynomial_count = None

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

    def tag_source_blocks(self, blocks):
        progress = get_progress()
        execution_logger.debug(
            f"Calculating {len(blocks) * len(self._polynomials)} MACs "
            f"for {len(blocks)} source blocks"
        )
        task_id = create_progress_task(
            progress,
            "Calculating source block MACs",
            total=len(blocks),
        )

        source_macs = {}
        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            for block_index, macs, division_seconds in executor.map(
                self._calculate_block_macs, range(len(blocks)), blocks
            ):
                source_macs[block_index] = [
                    LocalMac(mac, polynomial_index, block_index)
                    for polynomial_index, mac in enumerate(macs)
                ]
                self.polynomial_division_total_seconds += division_seconds
                self.polynomial_division_count += len(macs)
                advance_progress(progress, task_id)

        return source_macs

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

    def _calculate_block_macs(self, block_index, block):
        representation = ga.bytes_to_poly_coeffs(block)
        started_at = time.perf_counter()
        macs = [
            ga.gf2_poly_mod(representation, polynomial)
            for polynomial in self._polynomials
        ]
        return block_index, macs, time.perf_counter() - started_at

    def _polynomial_set_generation(self):
        count = self.polynomial_count or POLYNOMIAL_SET_SIZE
        execution_logger.debug(f"Generating {count} challenge polynomials")
        polynomials = []
        progress = get_progress()
        task_id = create_progress_task(
            progress,
            "Generating challenge polynomials",
            total=count,
        )

        while len(polynomials) < count:
            polynomial = ga.generate_challenge_polynomial()
            if polynomial.tolist() not in [p.tolist() for p in polynomials]:
                polynomials.append(polynomial)
                advance_progress(progress, task_id)

        return polynomials


class UnboundedRetrievabilityProof(PolynomialRetrievabilityProof):
    """Hy-SAIL's unbounded model: one secret polynomial P that never leaves the client.

    The client keeps h_i = m_i mod P for every source block. Servers are never
    sent P: before a download nothing is revealed, and the downloaded packet is
    reduced modulo P by the client and compared with the MAC derived from its
    support. Since a server cannot keep c mod P in place of c without knowing
    P, the same polynomial serves any number of audits.
    """

    scheme = UNBOUNDED_SCHEME
    single_use_challenges = False
    polynomial_count = 1

    def __init__(self, polynomials=None, max_threads=MAX_MAC_THREADS):
        super().__init__(polynomials, max_threads, challenge_index=0)
        if len(self._polynomials) != 1:
            raise ValueError("The unbounded scheme uses exactly one polynomial")

    @property
    def modulus(self) -> int:
        return ga._poly_coeffs_to_int(self._polynomials[0])

    def verify(self, server, block, expected_mac):
        # Revealing P would let the server answer from c mod P; check after download.
        return True

    def verify_download(self, server, block, data, expected_mac=None):
        if expected_mac is None:
            return True
        started_at = time.perf_counter()
        verified = self.matches(ga.bytes_to_poly_int(data), expected_mac(0))
        self.polynomial_division_total_seconds += time.perf_counter() - started_at
        self.polynomial_division_count += 1
        if not verified:
            execution_logger.error(f"Validation failed for block index: {block.index}")
        return verified

    def matches(self, value: int, expected_mac) -> bool:
        """Whether value(x) mod P equals the MAC derived by the client."""
        return ga.gf2_mod(value, self.modulus) == ga._poly_coeffs_to_int(
            _as_coefficients(expected_mac)
        )


class DisabledRetrievabilityProof(RetrievabilityProof):
    @property
    def enabled(self):
        return False

    @property
    def polynomials(self):
        return []

    def verify(self, server, block, expected_mac):
        return True


@dataclass
class CompactKeys:
    """Client secrets of the compact scheme: O(1) state, whatever the file size."""

    polynomial: np.ndarray
    prf_key: bytes
    file_id: bytes
    # Secret multiplier; without it a server can move c's low lambda bits into the tag.
    # Keys saved before it existed load as 1 and keep that weaker behaviour.
    alpha: int = 1

    @classmethod
    def generate(cls):
        polynomial = ga.generate_challenge_polynomial()
        degree = ga.polynomial_degree(polynomial)
        return cls(
            polynomial=polynomial,
            prf_key=secrets.token_bytes(32),
            file_id=secrets.token_bytes(16),
            alpha=secrets.randbelow((1 << degree) - 2) + 2,
        )

    @property
    def modulus(self) -> int:
        return ga._poly_coeffs_to_int(self.polynomial)

    @property
    def degree(self) -> int:
        return self.modulus.bit_length() - 1

    def mask(self, chunk_index, packet_index) -> int:
        """f_K(file, chunk, ESI): binds a tag to one position of one file."""
        message = (
            self.file_id
            + chunk_index.to_bytes(8, "big")
            + packet_index.to_bytes(8, "big")
        )
        digest = hmac.new(self.prf_key, message, hashlib.sha256).digest()
        return int.from_bytes(digest, "big") & ((1 << self.degree) - 1)

    def tag(self, chunk_index, packet_index, data) -> int:
        remainder = ga.gf2_mod(ga.bytes_to_poly_int(data), self.modulus)
        return self.scale(remainder) ^ self.mask(chunk_index, packet_index)

    def scale(self, value) -> int:
        """alpha * value mod P."""
        return ga.gf2_mod(ga.gf2_clmul(self.alpha, value), self.modulus)


class CompactRetrievabilityProof(RetrievabilityProof):
    """Unbounded scheme in the style of Shacham and Waters' private-key PoR.

    Servers store sigma = alpha * (c mod P) xor f_K(file, chunk, ESI) next to each
    packet. A challenge sends random coefficients nu; the server answers
    mu = sum(nu * c) and tau = sum(nu * sigma) without knowing P or alpha, and the
    client accepts when (tau xor alpha * mu xor sum(nu * f_K)) mod P = 0. P is never
    revealed, so challenges can be repeated indefinitely, and the client keeps only
    P, alpha, the PRF key and the file id.
    """

    scheme = COMPACT_SCHEME

    def __init__(self, keys: CompactKeys | None = None, chunk_index=None):
        super().__init__()
        self.keys = keys or CompactKeys.generate()
        self._chunk_index = chunk_index

    @property
    def enabled(self):
        return True

    @property
    def polynomials(self):
        return []

    def attach_server_tags(self, packets, chunk_index):
        for packet in packets:
            started_at = time.perf_counter()
            packet.tag = self.keys.tag(chunk_index, packet.index, packet.data)
            self.polynomial_division_total_seconds += time.perf_counter() - started_at
            self.polynomial_division_count += 1

    def verify(self, server, block, expected_mac):
        # Nothing is revealed before a download; the tag is checked afterwards.
        return True

    def verify_download(self, server, block, data, expected_mac=None):
        tag = server.download_tag(block.packet_file)
        verified = tag is not None and tag == self.keys.tag(
            self._chunk_index, block.index, data
        )
        if not verified:
            execution_logger.error(f"Tag verification failed for block {block.index}")
        return verified

    def challenge(self, server, packets) -> bool:
        """Audit `packets`, a list of (chunk_index, packet_index, packet_file)."""
        coefficients = [
            secrets.randbits(self.keys.degree) | 1 for _ in range(len(packets))
        ]
        mu, tau = server.receive_compact_challenge(
            [packet_file for _, _, packet_file in packets], coefficients
        )
        masks = 0
        for coefficient, (chunk_index, packet_index, _) in zip(coefficients, packets):
            masks ^= ga.gf2_clmul(
                coefficient, self.keys.mask(chunk_index, packet_index)
            )
        return (
            ga.gf2_mod(
                tau ^ self.keys.scale(ga.gf2_mod(mu, self.keys.modulus)) ^ masks,
                self.keys.modulus,
            )
            == 0
        )


def create_retrievability_proof(
    enabled: bool,
    polynomials=None,
    max_threads=MAX_MAC_THREADS,
    scheme=BOUNDED_SCHEME,
    keys=None,
    chunk_index=None,
) -> RetrievabilityProof:
    if not enabled:
        return DisabledRetrievabilityProof()
    if scheme == COMPACT_SCHEME:
        return CompactRetrievabilityProof(keys, chunk_index)
    if scheme == UNBOUNDED_SCHEME:
        return UnboundedRetrievabilityProof(polynomials, max_threads)
    if scheme != BOUNDED_SCHEME:
        raise ValueError(f"Unknown retrievability proof scheme: {scheme}")

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


class SourceMacs:
    """Hy-SAIL's client state for one chunk: h_ij = m_i mod P_j per source block.

    Every R10 or Online Codes packet is the XOR of the source blocks in its
    support, so by linearity its MAC is the XOR of their MACs (Hy-SAIL's
    Equation 4). A sealed packet adds its keystream, whose MAC the client
    recomputes from its key.
    """

    def __init__(self, chunk, sealer=None):
        self._polynomials = chunk.polynomials
        self._chunk_index = getattr(chunk, "chunk_index", 0)
        self._source_blocks = getattr(chunk, "source_packets", 0)
        self._symbol_size = getattr(chunk, "symbol_size", 0)
        self._codec = codec_module(getattr(chunk, "codec", DEFAULT_CODEC))
        self._sealer = sealer
        self._macs = {
            (block.block_index, block.polynomial_index): block.mac_value
            for block in chunk.blocks
        }

    def missing(self) -> str | None:
        """What keeps these MACs from backing a proof, or None when complete."""
        if not self._polynomials:
            return "no challenge polynomials"
        expected = self._source_blocks * len(self._polynomials)
        if self._source_blocks == 0 or len(self._macs) != expected:
            return "no MAC for every source block and polynomial"
        return None

    def packet_mac(self, packet_index, polynomial_index):
        support = self._codec.symbol_support(self._source_blocks, packet_index)
        mac = xor_macs(
            [
                self._macs[(block_index, polynomial_index)]
                for block_index in raptor.support_indices(support)
            ]
        )
        if self._sealer is None:
            return mac
        keystream = self._sealer.keystream(
            self._chunk_index, packet_index, self._symbol_size
        )
        return np.bitwise_xor(
            mac,
            ga.gf2_poly_mod(
                ga.bytes_to_poly_coeffs(keystream),
                self._polynomials[polynomial_index],
            ),
        )


def xor_macs(macs):
    result = _as_coefficients(macs[0])
    for mac in macs[1:]:
        result = np.bitwise_xor(result, _as_coefficients(mac))
    return result


def _as_coefficients(value):
    if isinstance(value, bytes):
        return np.frombuffer(value, dtype=np.uint8)
    return np.asarray(value, dtype=np.uint8)
