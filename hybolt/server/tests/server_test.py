import pickle

import numpy as np
import pytest

import hybolt.utils.galois as ga
from hybolt.encryption.block import Block
from hybolt.server.server import Server, StoredPacket


def test_given_storage_location_when_initializing_server_then_creates_location(
    tmp_path,
):
    storage_location = tmp_path / "storage"

    Server(str(storage_location))

    assert storage_location.exists()
    assert storage_location.is_dir()


def test_given_block_file_when_storing_then_copies_file(tmp_path):
    storage_location = tmp_path / "storage"
    server = Server(str(storage_location))

    block_file = tmp_path / "input_packet_0.pkl"
    block_data = b"test-data"
    block_file.write_bytes(block_data)

    server.storage_check_block(block_file)

    saved_file = storage_location / block_file.name
    assert saved_file.exists()
    assert saved_file.read_bytes() == block_data


def test_given_stored_block_when_downloading_then_returns_block_bytes(tmp_path):
    server = Server(str(tmp_path / "storage"))
    block_file = tmp_path / "input_packet_1.pkl"
    block_data = b"\x01\x02"
    block_file.write_bytes(block_data)

    server.storage_check_block(block_file)

    result = server.download_block(1)

    assert result == block_data


def test_given_pickled_packet_when_downloading_then_returns_packet_data(tmp_path):
    server = Server(str(tmp_path / "storage"))
    block_file = tmp_path / "input_packet_7.pkl"

    with open(block_file, "wb") as file:
        pickle.dump(Block(7, 1, [0], b"\x03\x04"), file)

    server.storage_check_block(block_file)

    result = server.download_block(7)

    assert result == b"\x03\x04"


def test_given_missing_block_when_downloading_then_raises(tmp_path):
    server = Server(str(tmp_path / "storage"))

    with pytest.raises(ValueError, match="Check block not found"):
        server.download_block(5)


def test_given_stored_block_when_receiving_challenge_then_returns_expected_response(
    tmp_path,
):
    server = Server(str(tmp_path / "storage"))
    block_file = tmp_path / "input_packet_2.pkl"
    block_data = b"\x01"
    block_file.write_bytes(block_data)

    server.storage_check_block(block_file)

    polynomial = np.array([1, 1])
    expected = ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(block_data), polynomial)

    result = server.receive_challenge(polynomial, 2)

    assert np.array_equal(result, expected)


def test_given_missing_block_when_receiving_challenge_then_raises(tmp_path):
    server = Server(str(tmp_path / "storage"))

    with pytest.raises(ValueError, match="Check block not found"):
        server.receive_challenge(np.array([1, 1]), 3)


def test_given_packet_when_storing_then_writes_pickle_readable_by_download(tmp_path):
    server = Server(str(tmp_path / "storage"))
    packet = Block(4, 1, [0], b"\x05\x06")

    packet_path = server.store_packet(packet, "input_packet_4.pkl")

    assert packet_path == tmp_path / "storage" / "input_packet_4.pkl"
    assert server.download_block(4, "input_packet_4.pkl") == b"\x05\x06"


def test_given_packets_when_answering_aggregate_challenge_then_xors_remainders(
    tmp_path,
):
    server = Server(str(tmp_path / "storage"))
    polynomial = ga.generate_challenge_polynomial(16)
    server.store_packet(Block(0, 0, [], b"\x01\x02\x03\x04"), "a.pkl")
    server.store_packet(Block(1, 0, [], b"\xff\x00\xaa\x55"), "b.pkl")

    answer = server.receive_aggregate_challenge(polynomial, ["a.pkl", "b.pkl"])

    expected = np.bitwise_xor(
        ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(b"\x01\x02\x03\x04"), polynomial),
        ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(b"\xff\x00\xaa\x55"), polynomial),
    )
    np.testing.assert_array_equal(answer, expected)


def test_given_shifts_when_answering_aggregate_challenge_then_weights_each_packet(
    tmp_path,
):
    server = Server(str(tmp_path / "storage"))
    polynomial = ga.generate_challenge_polynomial(16)
    server.store_packet(Block(0, 0, [], b"\x01\x02\x03\x04"), "a.pkl")
    server.store_packet(Block(1, 0, [], b"\x01\x02\x03\x04"), "b.pkl")

    plain = server.receive_aggregate_challenge(polynomial, ["a.pkl", "b.pkl"])
    weighted = server.receive_aggregate_challenge(
        polynomial, ["a.pkl", "b.pkl"], shifts=[1, 2]
    )

    remainder = ga.gf2_poly_mod(
        ga.bytes_to_poly_coeffs(b"\x01\x02\x03\x04"), polynomial
    )
    np.testing.assert_array_equal(
        weighted, ga.aggregate_remainders([remainder, remainder], polynomial, [1, 2])
    )
    assert not plain.any()
    assert weighted.any()


def test_given_missing_packet_when_answering_aggregate_challenge_then_raises(
    tmp_path,
):
    server = Server(str(tmp_path / "storage"))

    with pytest.raises(ValueError, match="missing.pkl"):
        server.receive_aggregate_challenge(np.array([1, 1, 1]), ["missing.pkl"])


def test_given_stored_packet_when_removing_then_deletes_file(tmp_path):
    server = Server(str(tmp_path / "storage"))
    path = server.store_packet(Block(0, 0, [], b"\x01"), "a.pkl")

    server.remove_packet("a.pkl")
    server.remove_packet("a.pkl")

    assert not path.exists()


def test_given_packet_when_storing_then_keeps_only_data_and_tag(tmp_path):
    server = Server(str(tmp_path / "storage"))
    packet = Block(9, 3, [1, 4, 7], b"\x07\x08")
    packet.tag = 0b1011
    packet.set_server(server)

    path = server.store_packet(packet, "opaque.pkl")

    with open(path, "rb") as file:
        stored = pickle.load(file)
    assert stored == StoredPacket(b"\x07\x08", 0b1011)


def test_given_tagged_packets_when_answering_compact_challenge_then_combines_data_and_tags(
    tmp_path,
):
    server = Server(str(tmp_path / "storage"))
    first, second = Block(0, 0, [], b"\x01\x02"), Block(1, 0, [], b"\xf0\x0f")
    first.tag, second.tag = 0b101, 0b011
    server.store_packet(first, "a.pkl")
    server.store_packet(second, "b.pkl")

    mu, tau = server.receive_compact_challenge(["a.pkl", "b.pkl"], [0b11, 0b10])

    assert mu == ga.gf2_clmul(0x0102, 0b11) ^ ga.gf2_clmul(0xF00F, 0b10)
    assert tau == ga.gf2_clmul(0b101, 0b11) ^ ga.gf2_clmul(0b011, 0b10)
    assert server.download_tag("a.pkl") == 0b101


def test_given_untagged_packet_when_answering_compact_challenge_then_raises(tmp_path):
    server = Server(str(tmp_path / "storage"))
    server.store_packet(Block(0, 0, [], b"\x01"), "a.pkl")

    with pytest.raises(ValueError, match="no tag"):
        server.receive_compact_challenge(["a.pkl"], [1])
    assert server.download_tag("missing.pkl") is None
