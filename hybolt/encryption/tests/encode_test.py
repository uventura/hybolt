import numpy as np
import pytest
from raptorq import Decoder

import hybolt.utils.galois as ga
from hybolt.constant import MAX_MAC_THREADS
from hybolt.encryption.encode import Encode
from hybolt.encryption.retrievability import PolynomialRetrievabilityProof


def test_given_input_data_when_encoding_then_generates_source_and_repair_packets():
    encoded = Encode(b"HelloWorld", block_size=2)

    assert len(encoded.packets) > encoded.num_blocks
    assert [packet.index for packet in encoded.packets] == list(
        range(len(encoded.packets))
    )


def test_given_input_data_when_encoding_then_generates_raptorq_packets():
    block_size = 2
    encoded = Encode(b"HelloWorld", block_size)

    for packet in encoded.packets:
        assert packet.degree == 0
        assert packet.indices == []
        assert len(packet.data) == block_size + 4


def test_given_missing_source_packets_when_decoding_then_recovers_with_repair_packets():
    original = b"RaptorQ recovers data after packet loss."
    encoded = Encode(original, block_size=8)
    decoder = Decoder.with_defaults(encoded.total_block_bytes, encoded.symbol_size)

    decoded = None
    for packet in encoded.packets[2:]:
        decoded = decoder.decode(packet.data)
        if decoded is not None:
            break

    assert decoded is not None
    assert decoded == original


def test_given_input_data_when_encoding_then_generates_packet_data_as_bytes():
    encoded = Encode(b"HelloWorld", 2)

    assert all(isinstance(packet.data, bytes) for packet in encoded.packets)


def test_given_single_small_block_when_encoding_then_preserves_transfer_length():
    encoded = Encode(b"A", block_size=10)

    assert encoded.total_block_bytes == 1
    assert all(len(packet.data) == 14 for packet in encoded.packets)


def test_given_input_data_when_encoding_then_blocks_preserve_source_bytes():
    encoded = Encode(b"ABCDEFGH", block_size=2)

    assert encoded._blocks == [b"AB", b"CD", b"EF", b"GH"]


def test_given_empty_data_when_encoding_then_raises_value_error():
    with pytest.raises(ValueError):
        Encode(b"", block_size=2)


@pytest.mark.parametrize("max_threads", [0, MAX_MAC_THREADS + 1])
def test_given_out_of_range_max_threads_when_encoding_then_raises_value_error(
    max_threads,
):
    with pytest.raises(ValueError, match="max_threads"):
        Encode(b"HelloWorld", block_size=2, max_threads=max_threads)


def test_given_raptorq_encoding_then_omits_incompatible_source_mac_metadata():
    encoded = Encode(b"HelloWorld", block_size=2)

    assert encoded.polynomials == []
    assert encoded.mac_blocks == {}
    assert encoded.packet_macs == {}


def test_given_retrievability_proof_when_encoding_then_tags_every_packet():
    polynomial = np.array([1, 0, 1, 1] + [0] * 12 + [1], dtype=np.uint8)
    proof = PolynomialRetrievabilityProof([polynomial])

    encoded = Encode(b"HelloWorld", block_size=2, proof=proof)

    assert len(encoded.polynomials) == 1
    assert np.array_equal(encoded.polynomials[0], polynomial)
    assert encoded.mac_blocks == {}
    assert set(encoded.packet_macs) == {packet.index for packet in encoded.packets}
    for packet in encoded.packets:
        expected = ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(packet.data), polynomial)
        assert np.array_equal(encoded.packet_macs[packet.index][0], expected)
    assert encoded.polynomial_division_count == len(encoded.packets)
