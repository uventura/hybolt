import json
import pickle
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import ChallengeSetExhaustedError
from hybolt.hybolt_encode import HyboltEncode

POLYNOMIAL_SET_SIZE = 4


@pytest.fixture
def encoded(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "hybolt.encryption.retrievability.POLYNOMIAL_SET_SIZE", POLYNOMIAL_SET_SIZE
    )
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"Hy-SAIL audits check blocks with polynomials. " * 6)
    servers = [
        {"id": index, "storage_location": str(tmp_path / f"server_{index}")}
        for index in range(2)
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
    return tmp_path / "input_metadata.pkl", server_file


def _metadata(metadata_file):
    return EncodingMetadata.load(metadata_file)


def _first_packet(metadata_file):
    return _metadata(metadata_file).chunks[0].packets[0]


def _rewrite(packet_metadata, change):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        packet = pickle.load(file)
    packet.data = change(packet.data)
    with open(path, "wb") as file:
        pickle.dump(packet, file)


def _corrupt(packet_metadata):
    """Flip one byte whose position depends on the packet, so errors never cancel."""

    def flip(data):
        data = bytearray(data)
        data[packet_metadata.packet_index % len(data)] ^= 0xFF
        return bytes(data)

    _rewrite(packet_metadata, flip)


def _corrupt_identically(packet_metadata):
    _rewrite(packet_metadata, lambda data: bytes(byte ^ 0xFF for byte in data))


def test_given_honest_servers_when_auditing_then_passes_and_checks_every_packet(
    encoded,
):
    metadata_file, server_file = encoded
    total_packets = sum(len(c.packets) for c in _metadata(metadata_file).chunks)

    report = Audit(metadata_file, server_file).run()

    assert report.passed
    assert report.corrupted_packets == []
    assert sum(server.checked_packets for server in report.servers) == total_packets
    assert report.remaining_challenges == POLYNOMIAL_SET_SIZE - 1


def test_given_audit_round_when_running_then_persists_revealed_polynomial(encoded):
    metadata_file, server_file = encoded

    report = Audit(metadata_file, server_file).run()

    assert _metadata(metadata_file).used_polynomial_indices == [report.polynomial_index]


def test_given_several_rounds_when_auditing_then_never_reuses_a_polynomial(encoded):
    metadata_file, server_file = encoded

    indices = [
        Audit(metadata_file, server_file).run().polynomial_index
        for _ in range(POLYNOMIAL_SET_SIZE)
    ]

    assert sorted(indices) == list(range(POLYNOMIAL_SET_SIZE))
    with pytest.raises(ChallengeSetExhaustedError):
        Audit(metadata_file, server_file).run()


def test_given_corrupted_packet_when_auditing_then_locates_it_and_fails_server(
    encoded,
):
    metadata_file, server_file = encoded
    corrupted = _first_packet(metadata_file)
    _corrupt(corrupted)

    report = Audit(metadata_file, server_file).run()

    assert not report.passed
    assert [(p.chunk_index, p.packet_index) for p in report.corrupted_packets] == [
        (0, corrupted.packet_index)
    ]
    failing = {server.server: server for server in report.servers}[corrupted.server]
    assert failing.tau_provider == 1
    assert not failing.passed
    assert report.chunks[0].corrupted == 1
    assert report.chunks[0].retrievable


def test_given_corruption_within_tau_maximum_when_auditing_then_server_passes(encoded):
    metadata_file, server_file = encoded
    _corrupt(_first_packet(metadata_file))

    report = Audit(metadata_file, server_file, tau_maximum=1).run()

    assert all(server.passed for server in report.servers)
    assert report.passed
    assert len(report.corrupted_packets) == 1


def test_given_deleted_packet_when_auditing_then_reports_it_as_corrupted(encoded):
    metadata_file, server_file = encoded
    deleted = _first_packet(metadata_file)
    (Path(deleted.server) / deleted.packet_file).unlink()

    report = Audit(metadata_file, server_file).run()

    assert [p.packet_file for p in report.corrupted_packets] == [deleted.packet_file]


def test_given_more_corruptions_than_repairs_when_auditing_then_chunk_is_at_risk(
    encoded,
):
    metadata_file, server_file = encoded
    chunk = _metadata(metadata_file).chunks[0]
    for packet in chunk.packets[: chunk.repair_packets + 1]:
        _corrupt(packet)

    report = Audit(metadata_file, server_file).run()

    assert report.chunks[0].corrupted == chunk.repair_packets + 1
    assert not report.chunks[0].retrievable
    assert not report.passed


def test_given_sample_size_when_auditing_then_limits_packets_checked_per_server(
    encoded,
):
    metadata_file, server_file = encoded

    report = Audit(metadata_file, server_file, sample_size=2).run()

    assert all(server.checked_packets == 2 for server in report.servers)


def test_given_metadata_without_proof_when_auditing_then_raises(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"no proof")
    servers = [{"id": 1, "storage_location": str(tmp_path / "server")}]
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": servers}))
    HyboltEncode(
        str(input_file),
        server_list=servers,
        metadata_output=str(tmp_path),
        retrievability_proof=False,
    ).encode()

    with pytest.raises(ValueError, match="retrievability proof"):
        Audit(tmp_path / "input_metadata.pkl", server_file)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [({"sample_size": 0}, "sample_size"), ({"tau_maximum": -1}, "tau_maximum")],
)
def test_given_invalid_parameters_when_creating_audit_then_raises(
    encoded, kwargs, message
):
    metadata_file, server_file = encoded

    with pytest.raises(ValueError, match=message):
        Audit(metadata_file, server_file, **kwargs)


def _two_packets_on_one_server(metadata_file):
    """Two (chunk index, packet) pairs stored on the same server."""
    by_server = {}
    for chunk in _metadata(metadata_file).chunks:
        for packet in chunk.packets:
            by_server.setdefault(packet.server, []).append((chunk.chunk_index, packet))
    return next(packets for packets in by_server.values() if len(packets) > 1)[:2]


def _audit_only(metadata_file, server_file, packets):
    audit = Audit(metadata_file, server_file)
    audit._packets_by_server = lambda: {packets[0][1].server: list(packets)}
    return audit.run()


def test_given_two_packets_with_identical_corruption_when_auditing_together_then_they_cancel(
    encoded,
):
    """Hy-SAIL's plain XOR answer: equal errors cancel, a limitation kept as future work."""
    metadata_file, server_file = encoded
    pair = _two_packets_on_one_server(metadata_file)
    for _, packet in pair:
        _corrupt_identically(packet)

    report = _audit_only(metadata_file, server_file, pair)

    assert report.corrupted_packets == []


def test_given_two_packets_with_identical_corruption_when_auditing_alone_then_detects_each(
    encoded,
):
    metadata_file, server_file = encoded
    pair = _two_packets_on_one_server(metadata_file)
    for _, packet in pair:
        _corrupt_identically(packet)

    found = [
        _audit_only(metadata_file, server_file, [item]).corrupted_packets
        for item in pair
    ]

    assert [[p.packet_file for p in report] for report in found] == [
        [packet.packet_file] for _, packet in pair
    ]
