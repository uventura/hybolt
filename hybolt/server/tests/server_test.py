import pickle

import numpy as np
import pytest

import hybolt.utils.galois as ga
from hybolt.encryption.block import Block
from hybolt.server.server import Server


def test_given_storage_location_when_initializing_server_then_creates_location(tmp_path):
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
