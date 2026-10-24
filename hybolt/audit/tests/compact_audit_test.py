import json
import pickle
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.encryption.decode import Decode
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode
from hybolt.server.server import Server


@pytest.fixture
def encoded(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"Compact audits never reveal the polynomial. " * 6)
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
        proof_scheme="compact",
    ).encode()
    return input_file, tmp_path / "input_metadata.pkl", server_file


def _packets(metadata_file, chunk_index=0):
    return EncodingMetadata.load(metadata_file).chunks[chunk_index].packets


def _rewrite(packet_metadata, transform):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        stored = pickle.load(file)
    transform(stored)
    with open(path, "wb") as file:
        pickle.dump(stored, file)


def _flip(stored):
    stored.data = bytes(byte ^ 0xFF for byte in stored.data)


def test_given_honest_servers_when_auditing_more_rounds_than_bounded_set_then_always_passes(
    encoded,
):
    _, metadata_file, server_file = encoded

    reports = [Audit(metadata_file, server_file).run() for _ in range(45)]

    assert all(report.passed for report in reports)
    assert all(report.polynomial_index is None for report in reports)
    assert EncodingMetadata.load(metadata_file).used_polynomial_indices == []


def test_given_audit_when_challenging_then_never_sends_the_secret_polynomial(
    encoded, monkeypatch
):
    _, metadata_file, server_file = encoded

    def forbid(*args, **kwargs):
        raise AssertionError("compact audits must not send polynomials")

    monkeypatch.setattr(Server, "receive_aggregate_challenge", forbid)
    monkeypatch.setattr(Server, "receive_challenge", forbid)

    assert Audit(metadata_file, server_file).run().passed


def test_given_corrupted_packet_when_auditing_then_locates_it(encoded):
    _, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[0]
    _rewrite(victim, _flip)

    report = Audit(metadata_file, server_file).run()

    assert [p.packet_index for p in report.corrupted_packets] == [victim.packet_index]
    assert not report.passed


def test_given_pair_with_identical_corruption_when_auditing_then_detects_both(encoded):
    _, metadata_file, server_file = encoded
    by_server = {}
    for chunk in EncodingMetadata.load(metadata_file).chunks:
        for packet in chunk.packets:
            by_server.setdefault(packet.server, []).append(packet)
    pair = next(packets for packets in by_server.values() if len(packets) > 1)[:2]
    for packet in pair:
        _rewrite(packet, _flip)

    report = Audit(metadata_file, server_file).run()

    assert {p.packet_file for p in report.corrupted_packets} == {
        packet.packet_file for packet in pair
    }


def test_given_server_that_dropped_data_but_kept_tag_when_auditing_then_fails(
    encoded,
):
    _, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[1]

    def drop_data(stored):
        stored.data = b""

    _rewrite(victim, drop_data)

    report = Audit(metadata_file, server_file).run()

    assert [p.packet_index for p in report.corrupted_packets] == [victim.packet_index]


def test_given_missing_tag_when_auditing_then_reports_packet(encoded):
    _, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[2]

    def drop_tag(stored):
        stored.tag = None

    _rewrite(victim, drop_tag)

    report = Audit(metadata_file, server_file).run()

    assert [p.packet_index for p in report.corrupted_packets] == [victim.packet_index]


def test_given_corruption_when_redistributing_then_rebuilt_packet_is_tagged(encoded):
    input_file, metadata_file, server_file = encoded
    victim = _packets(metadata_file)[0]
    _rewrite(victim, _flip)
    report = Audit(metadata_file, server_file).run()

    result = Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert result.succeeded
    assert Audit(metadata_file, server_file).run().passed
    assert Decode(metadata_file, server_file).decode() == input_file.read_bytes()


def test_given_compact_metadata_without_keys_when_auditing_then_raises(encoded):
    _, metadata_file, server_file = encoded
    metadata = EncodingMetadata.load(metadata_file)
    metadata.compact_keys = None
    metadata.save(metadata_file)

    with pytest.raises(ValueError, match="client keys"):
        Audit(metadata_file, server_file)
