import pytest

from hybolt.encryption.digest import Digest


def test_given_requested_chunk_count_when_splitting_then_creates_balanced_chunks(
    tmp_path,
):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"0123456789")

    chunks = list(Digest(input_file, chunk_count=4).chunks())

    assert [index for index, _ in chunks] == [0, 1, 2, 3]
    assert [len(chunk) for _, chunk in chunks] == [3, 3, 2, 2]
    assert b"".join(chunk for _, chunk in chunks) == b"0123456789"


def test_given_chunk_count_exceeding_input_bytes_when_splitting_then_raises(
    tmp_path,
):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"abc")

    with pytest.raises(ValueError, match="cannot exceed"):
        Digest(input_file, chunk_count=4)


def test_given_file_larger_than_a_chunk_when_splitting_then_uses_chunk_size(
    tmp_path,
):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(bytes(25))

    chunks = list(Digest(input_file, chunk_size=10).chunks())

    assert [len(chunk) for _, chunk in chunks] == [10, 10, 5]


def test_given_non_positive_chunk_size_when_creating_digest_then_raises(tmp_path):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"abc")

    with pytest.raises(ValueError, match="chunk_size"):
        Digest(input_file, chunk_size=0)
