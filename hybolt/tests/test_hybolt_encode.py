import math

import numpy as np

from hybolt.constant import POLYNOMIAL_SET_SIZE
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode


def _encode(tmp_path, retrievability_proof=True, chunk_count=3, redundancy=0.25):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"Hy-SAIL keeps one challenge set per file. " * 8)
    HyboltEncode(
        str(input_file),
        block_size=16,
        server_list=[{"id": 1, "storage_location": str(tmp_path / "server")}],
        metadata_output=str(tmp_path),
        chunk_count=chunk_count,
        retrievability_proof=retrievability_proof,
        redundancy=redundancy,
    ).encode()
    return EncodingMetadata.load(tmp_path / "input_metadata.pkl")


def test_given_chunked_file_when_encoding_with_proof_then_chunks_share_one_polynomial_set(
    tmp_path,
):
    metadata = _encode(tmp_path)

    assert len(metadata.polynomials) == POLYNOMIAL_SET_SIZE
    assert len(metadata.chunks) == 3
    for chunk in metadata.chunks:
        assert len(chunk.polynomials) == POLYNOMIAL_SET_SIZE
        for shared, own in zip(metadata.polynomials, chunk.polynomials):
            assert np.array_equal(shared, own)
        assert all(len(packet.macs) == POLYNOMIAL_SET_SIZE for packet in chunk.packets)


def test_given_chunked_file_when_encoding_without_proof_then_stores_no_polynomials(
    tmp_path,
):
    metadata = _encode(tmp_path, retrievability_proof=False)

    assert metadata.polynomials == []
    assert all(chunk.polynomials == [] for chunk in metadata.chunks)
    assert all(
        packet.macs == [] for chunk in metadata.chunks for packet in chunk.packets
    )


def test_given_redundancy_when_encoding_then_records_repair_packets_per_chunk(tmp_path):
    metadata = _encode(tmp_path, retrievability_proof=False, redundancy=0.5)

    for chunk in metadata.chunks:
        assert chunk.repair_packets >= 1
        source_packets = len(chunk.packets) - chunk.repair_packets
        assert chunk.repair_packets == math.ceil(0.5 * source_packets)
