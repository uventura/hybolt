import math

import numpy as np

from hybolt.constant import POLYNOMIAL_SET_SIZE
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


def test_given_compact_scheme_when_encoding_then_client_keeps_only_keys_and_servers_tags(
    tmp_path,
):
    metadata = _encode(tmp_path, proof_scheme="compact")

    assert metadata.proof_scheme == "compact"
    assert metadata.compact_keys is not None
    assert metadata.polynomials == []
    for chunk in metadata.chunks:
        for packet in chunk.packets:
            assert packet.macs == []
            stored_tag = Server(packet.server).download_tag(packet.packet_file)
            data = Server(packet.server).download_block(0, packet.packet_file)
            assert stored_tag == metadata.compact_keys.tag(
                chunk.chunk_index, packet.packet_index, data
            )


def test_given_default_encoding_when_storing_then_hides_chunk_and_raptorq_header(
    tmp_path,
):
    metadata = _encode(tmp_path, proof_scheme="compact")

    assert metadata.sealing_keys is not None
    names = {
        packet.packet_file for chunk in metadata.chunks for packet in chunk.packets
    }
    assert not any("chunk" in name or "input" in name for name in names)
    for chunk in metadata.chunks:
        for packet in chunk.packets:
            stored = Server(packet.server).download_block(0, packet.packet_file)
            plain_header = bytes([0]) + packet.packet_index.to_bytes(3, "big")
            assert stored[:4] != plain_header
            opened = metadata.sealing_keys.open(
                chunk.chunk_index, packet.packet_index, stored
            )
            assert opened[:4] == plain_header


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
    assert stored[:4] == bytes([0]) + packet.packet_index.to_bytes(3, "big")
