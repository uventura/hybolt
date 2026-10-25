import json
import pickle
import random
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.encryption.decode import Decode
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode


def _encode(tmp_path, redundancy, seed=0):
    # The seed fixes the packet layout; R10 is not MDS, so whether a given set
    # of lost packets is recoverable depends on which packets they are.
    random.seed(seed)
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
        redundancy=redundancy,
        proof_scheme="bounded",
    ).encode()
    return input_file, tmp_path / "input_metadata.pkl", server_file


@pytest.fixture
def encoded(tmp_path, monkeypatch):
    monkeypatch.setattr("hybolt.encryption.retrievability.POLYNOMIAL_SET_SIZE", 6)
    return _encode(tmp_path, redundancy=1.0)


def _corrupt(packet_metadata):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        packet = pickle.load(file)
    packet.data = bytes(len(packet.data))
    with open(path, "wb") as file:
        pickle.dump(packet, file)


def _packets(metadata_file, chunk_index=0):
    return EncodingMetadata.load(metadata_file).chunks[chunk_index].packets


def test_given_corrupted_packet_when_redistributing_then_replaces_it_with_fresh_esi(
    encoded,
):
    _, metadata_file, server_file = encoded
    chunk = EncodingMetadata.load(metadata_file).chunks[0]
    victim = chunk.packets[0]
    _corrupt(victim)
    report = Audit(metadata_file, server_file).run()

    result = Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert result.succeeded
    [replaced] = result.replaced
    assert replaced.old_packet_index == victim.packet_index
    assert replaced.new_packet_index == chunk.next_packet_index
    assert replaced.to_server != victim.server
    assert not (Path(victim.server) / victim.packet_file).exists()
    packets = {p.packet_index: p for p in _packets(metadata_file)}
    assert victim.packet_index not in packets
    fresh = packets[replaced.new_packet_index]
    assert fresh.server == replaced.to_server
    assert (Path(fresh.server) / fresh.packet_file).exists()
    assert fresh.packet_sha256 != victim.packet_sha256


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


def test_given_extra_repair_when_redistributing_then_widens_chunk_margin(encoded):
    _, metadata_file, server_file = encoded
    before = EncodingMetadata.load(metadata_file).chunks[0]
    _corrupt(before.packets[0])
    report = Audit(metadata_file, server_file).run()

    result = Redistribution(
        metadata_file, server_file, report.corrupted_packets, extra_repair=2
    ).run()

    after = EncodingMetadata.load(metadata_file).chunks[0]
    assert len(result.replaced) == 1
    assert len(result.added) == 2
    assert len(after.packets) == len(before.packets) + 2
    assert after.repair_packets == before.repair_packets + 2
    assert after.next_packet_index == before.next_packet_index + 3
    assert Audit(metadata_file, server_file).run().chunks[0].tolerated_losses == (
        before.repair_packets + 2
    )


def test_given_consecutive_repairs_when_redistributing_then_never_reuses_an_esi(
    encoded,
):
    _, metadata_file, server_file = encoded
    seen = {p.packet_index for p in _packets(metadata_file)}

    for _ in range(3):
        _corrupt(_packets(metadata_file)[0])
        report = Audit(metadata_file, server_file).run()
        result = Redistribution(
            metadata_file, server_file, report.corrupted_packets
        ).run()
        [replaced] = result.replaced
        assert replaced.new_packet_index not in seen
        seen.add(replaced.new_packet_index)

    assert Audit(metadata_file, server_file).run().passed


def test_given_server_that_left_when_auditing_and_redistributing_then_restores_chunks(
    tmp_path, monkeypatch
):
    # R10 needs a few packets beyond K, so losing a third of the packets takes
    # more redundancy than the other tests use.
    monkeypatch.setattr("hybolt.encryption.retrievability.POLYNOMIAL_SET_SIZE", 6)
    input_file, metadata_file, server_file = _encode(tmp_path, redundancy=2.0)
    servers = json.loads(server_file.read_text())["servers"]
    gone = servers.pop()
    remaining_file = tmp_path / "remaining_servers.json"
    remaining_file.write_text(json.dumps({"servers": servers}))
    lost = [
        p
        for chunk in EncodingMetadata.load(metadata_file).chunks
        for p in chunk.packets
        if p.server == gone["storage_location"]
    ]

    report = Audit(metadata_file, remaining_file).run()
    assert {p.packet_file for p in report.corrupted_packets} == {
        p.packet_file for p in lost
    }

    result = Redistribution(
        metadata_file, remaining_file, report.corrupted_packets
    ).run()

    assert result.succeeded
    assert len(result.replaced) == len(lost)
    assert all(
        p.server != gone["storage_location"]
        for chunk in EncodingMetadata.load(metadata_file).chunks
        for p in chunk.packets
    )
    assert Audit(metadata_file, remaining_file).run().passed
    decoded = Decode(metadata_file, remaining_file).decode()
    assert decoded == input_file.read_bytes()


def test_given_reencoding_mismatch_when_redistributing_then_refuses_chunk(encoded):
    _, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[-1]
    _corrupt(victim)
    report = Audit(metadata_file, server_file).run()
    metadata = EncodingMetadata.load(metadata_file)
    metadata.chunks[0].packets[0].packet_sha256 = "0" * 64
    metadata.save(metadata_file)

    result = Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert "does not reproduce" in result.failed_chunks[0]
    assert victim.packet_index in {p.packet_index for p in _packets(metadata_file)}


def test_given_negative_extra_repair_when_creating_redistribution_then_raises(
    encoded,
):
    _, metadata_file, server_file = encoded

    with pytest.raises(ValueError, match="extra_repair"):
        Redistribution(metadata_file, server_file, [], extra_repair=-1)


def test_given_metadata_saved_before_fresh_esis_when_loading_then_backfills_counters(
    encoded,
):
    _, metadata_file, _ = encoded
    metadata = EncodingMetadata.load(metadata_file)
    chunk = metadata.chunks[0]
    expected_source = chunk.source_packets
    expected_next = chunk.next_packet_index
    del chunk.source_packets
    del chunk.next_packet_index
    metadata.save(metadata_file)

    loaded = EncodingMetadata.load(metadata_file).chunks[0]

    assert loaded.source_packets == expected_source
    assert loaded.next_packet_index == expected_next
