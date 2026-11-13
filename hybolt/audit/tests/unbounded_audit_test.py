import json
import pickle
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.constant import POLYNOMIAL_SET_SIZE
from hybolt.encryption.decode import Decode
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode
from hybolt.server.server import Server

CONTENT = b"Hy-SAIL's unbounded model keeps a single secret polynomial. " * 8


@pytest.fixture(params=[False, True], ids=["plain", "sealed"])
def encoded(request, tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(CONTENT)
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
        proof_scheme="unbounded",
        seal_packets=request.param,
    ).encode()
    return tmp_path / "input_metadata.pkl", server_file


@pytest.fixture
def secret_polynomial(monkeypatch):
    """Fail the test if any polynomial is sent to a server."""

    def reveal(*args, **kwargs):
        raise AssertionError("the unbounded model must not reveal its polynomial")

    monkeypatch.setattr(Server, "receive_challenge", reveal)
    monkeypatch.setattr(Server, "receive_aggregate_challenge", reveal)


def _metadata(metadata_file):
    return EncodingMetadata.load(metadata_file)


def _packets(metadata_file, chunk_index=0):
    return _metadata(metadata_file).chunks[chunk_index].packets


def _corrupt(packet_metadata):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        packet = pickle.load(file)
    data = bytearray(packet.data)
    data[len(data) // 2] ^= 0x01
    packet.data = bytes(data)
    with open(path, "wb") as file:
        pickle.dump(packet, file)


def test_given_unbounded_encoding_when_saving_then_keeps_one_mac_per_source_block(
    encoded,
):
    metadata = _metadata(encoded[0])

    assert metadata.proof_scheme == "unbounded"
    assert len(metadata.polynomials) == 1
    for chunk in metadata.chunks:
        assert len(chunk.blocks) == chunk.source_packets


def test_given_honest_servers_when_auditing_then_passes_without_revealing_polynomial(
    encoded, secret_polynomial
):
    metadata_file, server_file = encoded

    report = Audit(metadata_file, server_file).run()

    assert report.passed
    assert report.corrupted_packets == []
    assert report.polynomial_index is None
    assert _metadata(metadata_file).used_polynomial_indices == []


def test_given_more_rounds_than_bounded_set_when_auditing_then_every_round_passes(
    encoded,
):
    metadata_file, server_file = encoded

    reports = [
        Audit(metadata_file, server_file, sample_size=2).run()
        for _ in range(POLYNOMIAL_SET_SIZE + 5)
    ]

    assert all(report.passed for report in reports)


def test_given_corrupted_packet_when_auditing_then_locates_it(
    encoded, secret_polynomial
):
    metadata_file, server_file = encoded
    corrupted = _packets(metadata_file)[0]
    _corrupt(corrupted)

    report = Audit(metadata_file, server_file).run()

    assert not report.passed
    assert [(p.chunk_index, p.packet_index) for p in report.corrupted_packets] == [
        (0, corrupted.packet_index)
    ]


def test_given_deleted_packet_when_auditing_then_reports_it_as_corrupted(encoded):
    metadata_file, server_file = encoded
    deleted = _packets(metadata_file)[0]
    (Path(deleted.server) / deleted.packet_file).unlink()

    report = Audit(metadata_file, server_file).run()

    assert [p.packet_file for p in report.corrupted_packets] == [deleted.packet_file]


def test_given_xor_challenge_when_answering_then_answer_has_packet_length(encoded):
    metadata_file, _ = encoded
    packet = _packets(metadata_file)[0]
    server = Server(packet.server)
    with open(Path(packet.server) / packet.packet_file, "rb") as file:
        data = pickle.load(file).data

    answer = server.receive_xor_challenge([packet.packet_file])

    assert answer.to_bytes(len(data), "big") == data


def test_given_corrupted_packet_when_decoding_then_skips_it_and_recovers_file(
    encoded, secret_polynomial
):
    metadata_file, server_file = encoded
    _corrupt(_packets(metadata_file)[0])

    decoded = Decode(metadata_file, server_file).decode()

    assert decoded == CONTENT
    assert _metadata(metadata_file).used_polynomial_indices == []


def test_given_redistribution_when_auditing_again_then_passes_and_decodes(encoded):
    metadata_file, server_file = encoded
    for packet in _packets(metadata_file, 1)[:2]:
        _corrupt(packet)
    report = Audit(metadata_file, server_file).run()

    Redistribution(metadata_file, server_file, report.corrupted_packets).run()

    assert Audit(metadata_file, server_file).run().passed
    assert Decode(metadata_file, server_file).decode() == CONTENT
