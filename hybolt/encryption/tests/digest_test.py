import pytest

from hybolt.encryption.digest import Digest


def test_digest_splits_input_into_requested_number_of_balanced_chunks(tmp_path):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"0123456789")

    chunks = list(Digest(input_file, chunk_count=4).chunks())

    assert [index for index, _ in chunks] == [0, 1, 2, 3]
    assert [len(chunk) for _, chunk in chunks] == [3, 3, 2, 2]
    assert b"".join(chunk for _, chunk in chunks) == b"0123456789"


def test_digest_rejects_more_chunks_than_input_bytes(tmp_path):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"abc")

    with pytest.raises(ValueError, match="cannot exceed"):
        Digest(input_file, chunk_count=4)
