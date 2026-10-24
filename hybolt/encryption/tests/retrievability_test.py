import numpy as np
import pytest

import hybolt.utils.galois as ga
from hybolt.constant import POLYNOMIAL_LAMBDA, POLYNOMIAL_SET_SIZE
from hybolt.encryption.block import Block, LocalBlock
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import (
    ChallengeLedger,
    ChallengeSetExhaustedError,
    CompactKeys,
    CompactRetrievabilityProof,
    DisabledRetrievabilityProof,
    PolynomialRetrievabilityProof,
    create_retrievability_proof,
    xor_macs,
)

POLYNOMIAL = np.array([1, 0, 1, 1] + [0] * 12 + [1], dtype=np.uint8)


def _mac(data, polynomial=POLYNOMIAL):
    return ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(data), polynomial)


class ChallengeServer:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def receive_challenge(self, polynomial, check_block_index, packet_file=""):
        self.calls.append((polynomial, check_block_index, packet_file))
        return self.answer


def _block(packet_file=""):
    return LocalBlock(
        index=3, degree=1, indices=[0], server=None, packet_file=packet_file
    )


def test_given_enabled_flag_when_creating_proof_then_returns_polynomial_proof():
    proof = create_retrievability_proof(True, [POLYNOMIAL])

    assert isinstance(proof, PolynomialRetrievabilityProof)
    assert proof.enabled is True
    assert len(proof.polynomials) == 1


def test_given_disabled_flag_when_creating_proof_then_returns_disabled_proof():
    proof = create_retrievability_proof(False, [POLYNOMIAL])

    assert isinstance(proof, DisabledRetrievabilityProof)
    assert proof.enabled is False
    assert proof.polynomials == []


def test_given_no_polynomials_when_creating_enabled_proof_then_generates_challenge_set():
    proof = PolynomialRetrievabilityProof()

    assert len(proof.polynomials) == POLYNOMIAL_SET_SIZE
    assert all(len(p) == POLYNOMIAL_LAMBDA + 1 for p in proof.polynomials)
    assert len({tuple(p.tolist()) for p in proof.polynomials}) == POLYNOMIAL_SET_SIZE


def test_given_packets_when_tagging_then_computes_one_mac_per_polynomial():
    second_polynomial = np.array([1, 1] + [0] * 14 + [1], dtype=np.uint8)
    proof = PolynomialRetrievabilityProof([POLYNOMIAL, second_polynomial])
    packets = [Block(0, 0, [], b"ABCD"), Block(1, 0, [], b"WXYZ")]

    macs = proof.tag_packets(packets)

    assert set(macs) == {0, 1}
    assert np.array_equal(macs[1][0], _mac(b"WXYZ"))
    assert np.array_equal(macs[1][1], _mac(b"WXYZ", second_polynomial))
    assert proof.polynomial_division_count == 4
    assert proof.polynomial_division_total_seconds > 0


def test_given_disabled_proof_when_tagging_then_returns_no_macs():
    assert DisabledRetrievabilityProof().tag_packets([Block(0, 0, [], b"AB")]) == {}


def test_given_correct_answer_when_verifying_then_returns_true_and_forwards_packet_file():
    server = ChallengeServer(_mac(b"ABCD"))
    proof = PolynomialRetrievabilityProof([POLYNOMIAL])

    verified = proof.verify(server, _block("p.pkl"), lambda j: _mac(b"ABCD"))

    assert verified is True
    polynomial, index, packet_file = server.calls[0]
    assert np.array_equal(polynomial, POLYNOMIAL)
    assert (index, packet_file) == (3, "p.pkl")


def test_given_answer_differing_after_first_byte_when_verifying_then_returns_false():
    tampered = _mac(b"ABCD").copy()
    tampered[10] ^= 1
    server = ChallengeServer(tampered)
    proof = PolynomialRetrievabilityProof([POLYNOMIAL])

    assert np.packbits(tampered)[0] == np.packbits(_mac(b"ABCD"))[0]
    assert proof.verify(server, _block(), lambda j: _mac(b"ABCD")) is False


def test_given_many_polynomials_when_verifying_then_expects_mac_of_chosen_polynomial(
    monkeypatch,
):
    second_polynomial = np.array([1, 1] + [0] * 14 + [1], dtype=np.uint8)
    proof = PolynomialRetrievabilityProof([POLYNOMIAL, second_polynomial])
    macs = [_mac(b"ABCD"), _mac(b"ABCD", second_polynomial)]
    monkeypatch.setattr(
        "hybolt.encryption.retrievability.random.randint", lambda a, b: 1
    )
    server = ChallengeServer(macs[1])

    assert proof.verify(server, _block(), lambda j: macs[j]) is True
    assert np.array_equal(server.calls[0][0], second_polynomial)


def test_given_disabled_proof_when_verifying_then_accepts_without_challenge():
    server = ChallengeServer(b"")

    assert DisabledRetrievabilityProof().verify(server, _block(), None) is True
    assert server.calls == []


@pytest.mark.parametrize("as_bytes", [False, True])
def test_given_source_macs_when_xoring_then_matches_mac_of_xored_data(as_bytes):
    mac_a, mac_b = _mac(b"ABCD"), _mac(b"WXYZ")
    if as_bytes:
        mac_a, mac_b = mac_a.tobytes(), mac_b.tobytes()
    combined = bytes(a ^ b for a, b in zip(b"ABCD", b"WXYZ"))

    assert np.array_equal(xor_macs([mac_a, mac_b]), _mac(combined))


def _ledger(tmp_path, polynomial_count=3, used=None):
    metadata = EncodingMetadata(polynomials=[], blocks=[], packets=[])
    metadata.used_polynomial_indices = list(used or [])
    metadata_file = tmp_path / "metadata.pkl"
    metadata.save(metadata_file)
    return ChallengeLedger(metadata, metadata_file, polynomial_count), metadata_file


def test_given_ledger_when_drawing_every_challenge_then_returns_each_index_once(
    tmp_path,
):
    ledger, _ = _ledger(tmp_path)

    drawn = [ledger.draw() for _ in range(3)]

    assert sorted(drawn) == [0, 1, 2]
    assert ledger.remaining == []


def test_given_draw_when_drawing_then_persists_revealed_index_before_returning(
    tmp_path,
):
    ledger, metadata_file = _ledger(tmp_path)

    index = ledger.draw()

    assert EncodingMetadata.load(metadata_file).used_polynomial_indices == [index]


def test_given_used_indices_when_drawing_then_only_returns_unused_index(tmp_path):
    ledger, _ = _ledger(tmp_path, used=[0, 2])

    assert ledger.remaining == [1]
    assert ledger.draw() == 1


def test_given_exhausted_ledger_when_drawing_then_raises(tmp_path):
    ledger, _ = _ledger(tmp_path, used=[0, 1, 2])

    with pytest.raises(ChallengeSetExhaustedError, match="re-encode"):
        ledger.draw()


def test_given_fixed_challenge_index_when_verifying_then_always_uses_it():
    second_polynomial = np.array([1, 1] + [0] * 14 + [1], dtype=np.uint8)
    proof = PolynomialRetrievabilityProof(
        [POLYNOMIAL, second_polynomial], challenge_index=1
    )
    server = ChallengeServer(_mac(b"ABCD", second_polynomial))

    for _ in range(5):
        assert proof.verify(
            server,
            _block(),
            lambda j: _mac(b"ABCD", [POLYNOMIAL, second_polynomial][j]),
        )

    assert all(np.array_equal(call[0], second_polynomial) for call in server.calls)


# --- Compact (unbounded) scheme ---------------------------------------------


class CompactServer:
    """Stores packets with their tags and answers compact challenges honestly."""

    def __init__(self, packets):
        self.packets = {f"p{packet.index}": packet for packet in packets}
        self.challenges = []

    def receive_compact_challenge(self, packet_files, coefficients):
        self.challenges.append((list(packet_files), list(coefficients)))
        mu = tau = 0
        for packet_file, coefficient in zip(packet_files, coefficients):
            packet = self.packets[packet_file]
            mu ^= ga.gf2_clmul(ga.bytes_to_poly_int(packet.data), coefficient)
            tau ^= ga.gf2_clmul(packet.tag, coefficient)
        return mu, tau

    def download_tag(self, packet_file):
        return self.packets[packet_file].tag


def _compact_packets(chunk_index=0, count=4):
    proof = CompactRetrievabilityProof(chunk_index=chunk_index)
    packets = [Block(index, 0, [], bytes([index + 1]) * 32) for index in range(count)]
    proof.attach_server_tags(packets, chunk_index)
    return proof, packets


def _refs(packets, chunk_index=0):
    return [(chunk_index, packet.index, f"p{packet.index}") for packet in packets]


def test_given_compact_keys_when_tagging_then_tag_is_remainder_masked_by_position():
    keys = CompactKeys.generate()
    data = b"Hy-SAIL compact tag"

    tag = keys.tag(2, 5, data)

    remainder = ga.gf2_mod(ga.bytes_to_poly_int(data), keys.modulus)
    assert tag == remainder ^ keys.mask(2, 5)
    assert tag.bit_length() <= keys.degree
    assert keys.mask(2, 5) != keys.mask(2, 6)
    assert keys.mask(2, 5) != keys.mask(3, 5)
    assert keys.mask(2, 5) != CompactKeys.generate().mask(2, 5)


def test_given_generated_compact_keys_when_inspecting_then_polynomial_is_primitive():
    keys = CompactKeys.generate()

    assert keys.degree == POLYNOMIAL_LAMBDA
    assert ga.is_primitive(keys.polynomial)
    assert len(keys.prf_key) == 32
    assert len(keys.file_id) == 16


def test_given_packets_when_attaching_server_tags_then_tags_every_packet():
    proof, packets = _compact_packets()

    assert all(
        packet.tag == proof.keys.tag(0, packet.index, packet.data) for packet in packets
    )
    assert proof.polynomial_division_count == len(packets)
    assert proof.tag_packets(packets) == {}
    assert proof.polynomials == []


def test_given_honest_server_when_challenging_repeatedly_then_always_accepts():
    proof, packets = _compact_packets()
    server = CompactServer(packets)

    assert all(proof.challenge(server, _refs(packets)) for _ in range(50))
    assert len({tuple(coefficients) for _, coefficients in server.challenges}) == 50


def test_given_corrupted_packet_when_challenging_then_rejects():
    proof, packets = _compact_packets()
    packets[2].data = bytes(len(packets[2].data))

    assert proof.challenge(CompactServer(packets), _refs(packets)) is False


def test_given_two_packets_with_identical_errors_when_challenging_then_rejects():
    proof, packets = _compact_packets()
    for packet in packets[:2]:
        packet.data = bytes(byte ^ 0xFF for byte in packet.data)

    assert proof.challenge(CompactServer(packets), _refs(packets)) is False


def test_given_tags_swapped_between_positions_when_challenging_then_rejects():
    proof, packets = _compact_packets()
    packets[0].data, packets[1].data = packets[1].data, packets[0].data
    packets[0].tag, packets[1].tag = packets[1].tag, packets[0].tag

    assert proof.challenge(CompactServer(packets), _refs(packets)) is False


def test_given_packets_of_another_chunk_when_challenging_then_rejects():
    proof, packets = _compact_packets(chunk_index=0)

    assert proof.challenge(CompactServer(packets), _refs(packets, 1)) is False


def test_given_downloaded_data_when_verifying_then_checks_server_tag():
    proof, packets = _compact_packets()
    proof._chunk_index = 0
    server = CompactServer(packets)
    block = LocalBlock(index=1, degree=0, indices=[], server=server, packet_file="p1")

    assert proof.verify_download(server, block, packets[1].data) is True
    assert proof.verify_download(server, block, packets[2].data) is False
    packets[1].tag = None
    assert proof.verify_download(server, block, packets[1].data) is False


def test_given_compact_scheme_when_creating_proof_then_returns_compact_proof():
    keys = CompactKeys.generate()

    proof = create_retrievability_proof(
        True, scheme="compact", keys=keys, chunk_index=3
    )

    assert isinstance(proof, CompactRetrievabilityProof)
    assert proof.keys is keys
    assert not proof.requires_client_macs
    assert not proof.single_use_challenges


def test_given_unknown_scheme_when_creating_proof_then_raises():
    with pytest.raises(ValueError, match="Unknown"):
        create_retrievability_proof(True, scheme="sentinels")
