from hybolt.encryption.sealing import SealingKeys


def test_given_packet_when_sealing_and_opening_then_restores_bytes():
    keys = SealingKeys.generate()
    data = bytes(range(256)) * 3

    sealed = keys.seal(1, 7, data)

    assert sealed != data
    assert len(sealed) == len(data)
    assert keys.open(1, 7, sealed) == data


def test_given_same_bytes_at_different_positions_when_sealing_then_ciphertexts_differ():
    keys = SealingKeys.generate()
    data = b"\x00" * 64

    assert keys.seal(0, 1, data) != keys.seal(0, 2, data)
    assert keys.seal(0, 1, data) != keys.seal(1, 1, data)
    assert keys.seal(0, 1, data) != SealingKeys.generate().seal(0, 1, data)


def test_given_position_when_naming_packet_then_name_is_opaque_and_deterministic():
    keys = SealingKeys.generate()

    name = keys.packet_file(3, 9)

    assert name == keys.packet_file(3, 9)
    assert name != keys.packet_file(3, 10)
    assert name != keys.packet_file(4, 9)
    assert name.endswith(".pkl")
    assert len(name) == len("0" * 32 + ".pkl")
    assert "chunk" not in name
