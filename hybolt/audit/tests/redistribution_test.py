import json
import pickle
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.encryption.decode import Decode
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode


@pytest.fixture
def encoded(tmp_path, monkeypatch):
    monkeypatch.setattr("hybolt.encryption.retrievability.POLYNOMIAL_SET_SIZE", 6)
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"Redistribution rebuilds corrupted packets. " * 6)
    servers = [
        {"id": index, "storage_location": str(tmp_path / f"server_{index}")}
        for index in range(3)
    ]
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": servers}))
    HyboltEncode(
        str(input_file),
        block_size=24,
        server_list=servers,
        metadata_output=str(tmp_path),
        chunk_count=2,
        redundancy=0.5,
        proof_scheme="bounded",
    ).encode()
    return input_file, tmp_path / "input_metadata.pkl", server_file


def _corrupt(packet_metadata):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        packet = pickle.load(file)
    packet.data = bytes(len(packet.data))
    with open(path, "wb") as file:
        pickle.dump(packet, file)


def _packets(metadata_file, chunk_index=0):
    return EncodingMetadata.load(metadata_file).chunks[chunk_index].packets


def test_given_corrupted_packet_when_redistributing_then_moves_rebuilt_packet_to_other_server(
    encoded,
):
    _, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[0]
    _corrupt(victim)
    report = Audit(metadata_file, server_file).run()

    result = Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert result.succeeded
    [moved] = result.moved
    assert moved.from_server == victim.server
    assert moved.to_server != victim.server
    assert not (Path(victim.server) / victim.packet_file).exists()
    assert (Path(moved.to_server) / victim.packet_file).exists()
    relocated = {p.packet_index: p for p in _packets(metadata_file)}[
        victim.packet_index
    ]
    assert relocated.server == moved.to_server
    assert relocated.packet_sha256 == victim.packet_sha256


def test_given_redistributed_packet_when_auditing_again_then_audit_passes(encoded):
    _, metadata_file, server_file = encoded
    _corrupt(_packets(metadata_file)[1])
    report = Audit(metadata_file, server_file).run()
    Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    second = Audit(metadata_file, server_file).run()

    assert second.passed
    assert second.corrupted_packets == []


def test_given_redistribution_when_decoding_then_reconstructs_original_file(encoded):
    input_file, metadata_file, server_file = encoded
    for packet in _packets(metadata_file, 1)[:2]:
        _corrupt(packet)
    report = Audit(metadata_file, server_file).run()
    Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    decoded = Decode(metadata_file, server_file).decode()

    assert decoded == input_file.read_bytes()


def test_given_redistribution_when_saving_then_updates_packet_root_hash(encoded):
    _, metadata_file, server_file = encoded
    before = EncodingMetadata.load(metadata_file).packet_root_hash
    _corrupt(_packets(metadata_file)[0])
    report = Audit(metadata_file, server_file).run()

    Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    metadata = EncodingMetadata.load(metadata_file)
    assert metadata.packet_root_hash != before
    assert metadata.packet_root_hash == metadata.compute_packet_root()


def test_given_chunk_with_too_many_corruptions_when_redistributing_then_reports_failure(
    encoded,
):
    _, metadata_file, server_file = encoded
    chunk = EncodingMetadata.load(metadata_file).chunks[0]
    for packet in chunk.packets[: chunk.repair_packets + 1]:
        _corrupt(packet)
    report = Audit(metadata_file, server_file).run()

    result = Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert not result.succeeded
    assert 0 in result.failed_chunks
    assert "Insufficient" in result.failed_chunks[0]
