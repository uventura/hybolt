import math

import numpy as np

from hybolt.constant import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_SOURCE_SYMBOLS,
    POLYNOMIAL_SET_SIZE,
)
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode
from hybolt.server.server import Server


def _encode(
    tmp_path,
    retrievability_proof=True,
    chunk_count=3,
    redundancy=0.25,
    proof_scheme="bounded",
):
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
        proof_scheme=proof_scheme,
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
        # Hy-SAIL's n * l MACs: one per source block and polynomial.
        assert len(chunk.blocks) == chunk.source_packets * POLYNOMIAL_SET_SIZE


def test_given_chunked_file_when_encoding_without_proof_then_stores_no_polynomials(
    tmp_path,
):
    metadata = _encode(tmp_path, retrievability_proof=False)

    assert metadata.polynomials == []
    assert all(chunk.polynomials == [] for chunk in metadata.chunks)
    assert all(chunk.blocks == [] for chunk in metadata.chunks)


def test_given_redundancy_when_encoding_then_records_repair_packets_per_chunk(tmp_path):
    metadata = _encode(tmp_path, retrievability_proof=False, redundancy=0.5)

    for chunk in metadata.chunks:
        assert chunk.repair_packets >= 1
        source_packets = len(chunk.packets) - chunk.repair_packets
        assert chunk.repair_packets == math.ceil(0.5 * source_packets)


def test_given_compact_scheme_when_encoding_then_client_keeps_only_keys_and_servers_tags(
    tmp_path,
):
    metadata = _encode(tmp_path, proof_scheme="compact")

    assert metadata.proof_scheme == "compact"
    assert metadata.compact_keys is not None
    assert metadata.polynomials == []
    for chunk in metadata.chunks:
        for packet in chunk.packets:
            stored_tag = Server(packet.server).download_tag(packet.packet_file)
            data = Server(packet.server).download_block(0, packet.packet_file)
            assert stored_tag == metadata.compact_keys.tag(
                chunk.chunk_index, packet.packet_index, data
            )


def test_given_default_encoding_when_storing_then_hides_chunk_and_source_symbols(
    tmp_path,
):
    metadata = _encode(tmp_path, proof_scheme="compact")
    original = (tmp_path / "input.txt").read_bytes()

    assert metadata.sealing_keys is not None
    names = {
        packet.packet_file for chunk in metadata.chunks for packet in chunk.packets
    }
    assert not any("chunk" in name or "input" in name for name in names)
    for chunk in metadata.chunks:
        for packet in chunk.packets:
            if packet.packet_index >= chunk.source_packets:
                continue
            stored = Server(packet.server).download_block(0, packet.packet_file)
            assert stored not in original
            opened = metadata.sealing_keys.open(
                chunk.chunk_index, packet.packet_index, stored
            )
            assert opened.rstrip(b"\0") in original


def test_given_sealing_disabled_when_encoding_then_keeps_plain_packets(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"plain packets " * 8)
    HyboltEncode(
        str(input_file),
        block_size=16,
        server_list=[{"id": 1, "storage_location": str(tmp_path / "server")}],
        metadata_output=str(tmp_path),
        seal_packets=False,
    ).encode()
    metadata = EncodingMetadata.load(tmp_path / "input_metadata.pkl")

    assert metadata.sealing_keys is None
    packet = metadata.chunks[0].packets[0]
    assert packet.packet_file.startswith("input_chunk_0_packet_")
    stored = Server(packet.server).download_block(0, packet.packet_file)
    if packet.packet_index < metadata.chunks[0].source_packets:
        start = packet.packet_index * metadata.chunks[0].symbol_size
        assert stored == input_file.read_bytes()[start : start + len(stored)]


def test_given_full_chunk_when_encoding_by_default_then_uses_k_source_symbols(
    tmp_path,
):
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(bytes(range(256)) * (DEFAULT_CHUNK_SIZE // 256 + 1))
    HyboltEncode(
        str(input_file),
        server_list=[{"id": 1, "storage_location": str(tmp_path / "server")}],
        metadata_output=str(tmp_path),
        retrievability_proof=False,
    ).encode()
    chunk = EncodingMetadata.load(tmp_path / "input_metadata.pkl").chunks[0]

    assert chunk.byte_size == DEFAULT_CHUNK_SIZE
    assert chunk.source_packets == DEFAULT_SOURCE_SYMBOLS
    assert chunk.symbol_size == DEFAULT_CHUNK_SIZE // DEFAULT_SOURCE_SYMBOLS
