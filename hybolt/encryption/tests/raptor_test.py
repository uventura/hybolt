import random

import pytest

from hybolt.encryption import raptor


def _reference_block(k, symbol_size=8):
    """The block used to produce the reference vectors below."""
    return b"".join(
        bytes((i * 31 + j * 7 + k) % 256 for j in range(symbol_size)) for i in range(k)
    )


# Repair symbols produced by github.com/google/gofountain, an independent RFC
# 5053 implementation, for _reference_block(K).
REFERENCE_SYMBOLS = [
    (11, 11, "494c4752e5e8f3fe"),
    (11, 12, "213f212ba1e7e1eb"),
    (11, 13, "41504f661d6c6b72"),
    (11, 20, "c6dac2c67e4a424e"),
    (100, 100, "d1af5163d197a153"),
    (100, 139, "d3bd2f45d3a5571d"),
    (1000, 1039, "f7267d6c63324928"),
]


@pytest.mark.parametrize(("k", "esi", "expected"), REFERENCE_SYMBOLS)
def test_given_reference_block_when_encoding_then_matches_independent_implementation(
    k, esi, expected
):
    encoder = raptor.Encoder(_reference_block(k), 8)

    assert encoder.symbol(esi).hex() == expected


def test_given_k_when_deriving_parameters_then_follows_rfc_5053():
    params = raptor.parameters(1000)

    assert params.ldpc_symbols == 59
    assert params.half_symbols == 13
    assert params.half_weight == 7
    assert params.intermediate_symbols == 1072
    assert params.intermediate_prime == 1087
    assert params.systematic_index == 128


@pytest.mark.parametrize("k", [3, 8193])
def test_given_k_out_of_range_when_deriving_parameters_then_raises(k):
    with pytest.raises(ValueError, match="source symbols"):
        raptor.parameters(k)


def test_given_every_small_k_when_building_matrix_a_then_it_is_invertible():
    for k in range(4, 200):
        assert (
            len(raptor.intermediate_supports(k))
            == raptor.parameters(k).intermediate_symbols
        )


def test_given_data_when_encoding_then_source_symbols_come_first():
    data = bytes(range(40))
    encoder = raptor.Encoder(data, 8)

    symbols = encoder.symbols(3)

    assert [esi for esi, _ in symbols] == list(range(8))
    assert b"".join(symbol for _, symbol in symbols[:5]) == data


def test_given_any_esi_when_encoding_then_symbol_is_xor_of_its_source_support():
    data = random.Random(3).randbytes(11 * 16)
    encoder = raptor.Encoder(data, 16)
    sources = [data[i * 16 : (i + 1) * 16] for i in range(11)]

    for esi in range(11, 40):
        expected = bytes(16)
        for index in raptor.support_indices(encoder.support(esi)):
            expected = bytes(a ^ b for a, b in zip(expected, sources[index]))
        assert encoder.symbol(esi) == expected


def test_given_short_block_when_encoding_then_pads_to_minimum_source_symbols():
    encoder = raptor.Encoder(b"A", 10)

    assert encoder.source_symbols == 4
    assert encoder.symbol(0) == b"A" + bytes(9)
    assert encoder.symbol(1) == bytes(10)


def test_given_too_many_symbols_when_encoding_then_asks_for_larger_block_size():
    with pytest.raises(ValueError, match="larger block size"):
        raptor.Encoder(bytes(8193), 1)


@pytest.mark.parametrize("k", [4, 11, 64, 300])
def test_given_random_subset_of_symbols_when_decoding_then_recovers_block(k):
    rng = random.Random(k)
    data = rng.randbytes(k * 12 - 5)
    symbols = raptor.Encoder(data, 12).symbols(k)
    rng.shuffle(symbols)
    decoder = raptor.Decoder(len(data), 12)

    decoded = None
    for received, (esi, symbol) in enumerate(symbols, start=1):
        decoded = decoder.add(esi, symbol)
        if decoded is not None:
            break

    assert decoded == data
    assert received <= k + 8


def test_given_only_repair_symbols_when_decoding_then_recovers_block():
    data = bytes(range(256)) * 2
    symbols = raptor.Encoder(data, 32).symbols(40)
    decoder = raptor.Decoder(len(data), 32)

    decoded = None
    for esi, symbol in symbols[16:]:
        decoded = decoder.add(esi, symbol)
        if decoded is not None:
            break

    assert decoded == data


def test_given_symbol_of_wrong_size_when_decoding_then_raises():
    decoder = raptor.Decoder(32, 8)

    with pytest.raises(ValueError, match="expected 8"):
        decoder.add(0, bytes(7))


def test_given_dependent_rows_when_adding_to_system_then_reports_no_new_rank():
    system = raptor.Gf2System(3)

    assert system.add(0b011, 1)
    assert system.add(0b110, 2)
    assert not system.add(0b101, 3)
    assert system.rank == 2
    assert system.solve() is None
