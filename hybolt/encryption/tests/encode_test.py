import pytest
from raptorq import Decoder

from hybolt.constant import MAX_MAC_THREADS
from hybolt.encryption.encode import Encode


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
