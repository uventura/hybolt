import random

import pytest
from raptorq import Encoder

from hybolt.encryption.linear_mac import (
    LinearMacKey,
    derive_packet_macs,
    gf128_mul,
    gf256_mul,
    mac_to_symbol,
    subfield_embedding,
    symbol_to_mac,
)
from hybolt.encryption.sealing import SealingKeys


def _random_bytes(rng, size):
    return bytes(rng.getrandbits(8) for _ in range(size))


def _esi(packet):
    return int.from_bytes(packet[1:4], "big")


def _source_macs(key, packets, repair_packets):
    # RaptorQ aligns the symbol size down to 8 bytes, so K comes from the packets.
    source_count = len(packets) - repair_packets
    return [key.packet_mac(packet) for packet in packets[:source_count]]


def test_given_bytes_when_embedding_then_preserves_gf256_sum_and_product():
    embedding = subfield_embedding()
    rng = random.Random(1)

    for _ in range(500):
        left, right = rng.randrange(256), rng.randrange(256)
        assert embedding[left ^ right] == embedding[left] ^ embedding[right]
        assert embedding[gf256_mul(left, right)] == gf128_mul(
            embedding[left], embedding[right]
        )
    assert embedding[0] == 0
    assert embedding[1] == 1
    assert len(set(embedding)) == 256


def test_given_mac_when_converting_to_symbol_and_back_then_restores_mac():
    rng = random.Random(2)

    for _ in range(200):
        mac = rng.getrandbits(128)
        symbol = mac_to_symbol(mac)
        assert len(symbol) == 16
        assert symbol_to_mac(symbol) == mac


def test_given_symbol_scaled_by_byte_when_converting_then_scales_its_mac():
    embedding = subfield_embedding()
    rng = random.Random(3)
    mac = rng.getrandbits(128)

    for scalar in (2, 3, 0x8E, 0xFF):
        scaled = bytes(gf256_mul(scalar, byte) for byte in mac_to_symbol(mac))
        assert symbol_to_mac(scaled) == gf128_mul(embedding[scalar], mac)


def test_given_symbols_when_combining_over_gf256_then_mac_is_linear():
    key = LinearMacKey.generate()
    embedding = subfield_embedding()
    rng = random.Random(4)
    left, right = _random_bytes(rng, 300), _random_bytes(rng, 300)
    scalar = 0x53

    combined = bytes(gf256_mul(scalar, a) ^ b for a, b in zip(left, right))

    assert key.mac(combined) == gf128_mul(embedding[scalar], key.mac(left)) ^ (
        key.mac(right)
    )


def test_given_trailing_zero_padding_when_computing_mac_then_mac_is_unchanged():
    key = LinearMacKey.generate()
    data = b"hybolt" * 10

    assert key.mac(data) == key.mac(data + bytes(32))


@pytest.mark.parametrize(
    ("data_size", "symbol_size", "repair_packets"),
    [(1000, 100, 3), (6_000, 600, 10), (65_024, 6_503, 3), (40_000, 64, 50)],
)
def test_given_raptorq_packets_when_deriving_macs_then_match_macs_of_every_packet(
    data_size, symbol_size, repair_packets
):
    rng = random.Random(data_size)
    data = _random_bytes(rng, data_size)
    packets = Encoder.with_defaults(data, symbol_size).get_encoded_packets(
        repair_packets
    )
    key = LinearMacKey.generate()
    derived = derive_packet_macs(
        _source_macs(key, packets, repair_packets), repair_packets
    )

    assert derived == {_esi(packet): key.packet_mac(packet) for packet in packets}


def test_given_source_macs_when_deriving_fresh_esis_then_match_later_repair_packets():
    rng = random.Random(5)
    data = _random_bytes(rng, 5_000)
    key = LinearMacKey.generate()
    first = Encoder.with_defaults(data, 500).get_encoded_packets(2)
    source_macs = _source_macs(key, first, 2)

    # Redistribution later asks the encoder for ESIs that were never stored.
    later = Encoder.with_defaults(data, 500).get_encoded_packets(40)
    derived = derive_packet_macs(source_macs, 40)

    for packet in later[-5:]:
        assert derived[_esi(packet)] == key.packet_mac(packet)


def test_given_corrupted_packet_when_checking_derived_mac_then_mismatches():
    rng = random.Random(6)
    data = _random_bytes(rng, 5_000)
    key = LinearMacKey.generate()
    packets = Encoder.with_defaults(data, 500).get_encoded_packets(4)
    derived = derive_packet_macs(_source_macs(key, packets, 4), 4)
    repair = bytearray(packets[-1])
    repair[100] ^= 0x01

    assert derived[_esi(packets[-1])] != key.packet_mac(bytes(repair))


def test_given_sealed_packet_when_checking_mac_then_keystream_mac_is_additive():
    rng = random.Random(7)
    data = _random_bytes(rng, 5_000)
    key = LinearMacKey.generate()
    sealer = SealingKeys.generate()
    packets = Encoder.with_defaults(data, 500).get_encoded_packets(4)
    derived = derive_packet_macs(_source_macs(key, packets, 4), 4)
    packet = packets[-1]
    sealed = sealer.seal(0, _esi(packet), packet)
    keystream = sealer.seal(0, _esi(packet), bytes(len(packet)))

    # Sealing XORs a keystream, so the MAC of the sealed bytes is affine in it.
    assert key.packet_mac(sealed) == derived[_esi(packet)] ^ key.packet_mac(keystream)


def test_given_different_keys_when_computing_mac_then_values_differ():
    data = bytes(range(256)) * 4

    assert LinearMacKey.generate().mac(data) != LinearMacKey.generate().mac(data)


def test_given_zero_point_when_creating_key_then_raises():
    with pytest.raises(ValueError):
        LinearMacKey(0)
