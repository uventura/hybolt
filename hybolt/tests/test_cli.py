import json

import pytest
from click.testing import CliRunner

from hybolt.hybolt import main


def test_given_max_threads_option_when_encoding_then_forwards_max_threads(
    tmp_path, monkeypatch
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["max_threads"] = args[4]
            captured["chunk_count"] = args[5]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory",
        lambda log_dir: captured.update(log_dir=log_dir),
    )
    monkeypatch.setattr("hybolt.hybolt.time.perf_counter", iter([1.0, 3.5]).__next__)

    result = CliRunner().invoke(
        main,
        [
            "encode",
            str(input_file),
            "--server-list",
            str(server_list),
            "--max-threads",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["max_threads"] == 2
    assert captured["chunk_count"] is None
    assert captured["log_dir"] == "logs"
    assert "Average chunk encoding time: 0.250s" in result.output
    assert "Total encoding runtime: 2.500s" in result.output


def test_given_chunk_count_option_when_encoding_then_forwards_chunk_count(
    tmp_path, monkeypatch
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["chunk_count"] = args[5]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)

    result = CliRunner().invoke(
        main,
        [
            "encode",
            str(input_file),
            "--server-list",
            str(server_list),
            "--chunk-count",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["chunk_count"] == 2


def test_given_log_directory_option_when_decoding_then_forwards_log_directory(
    tmp_path, monkeypatch
):
    metadata_file = tmp_path / "metadata.pkl"
    metadata_file.write_bytes(b"metadata")
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": []}), encoding="utf-8")
    log_dir = tmp_path / "custom-logs"
    captured = {}

    class StubHyboltDecode:
        def __init__(self, *args):
            pass

        def decode(self):
            return tmp_path / "decoded.txt"

    monkeypatch.setattr("hybolt.hybolt.HyboltDecode", StubHyboltDecode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory",
        lambda value: captured.update(log_dir=value),
    )

    result = CliRunner().invoke(
        main,
        [
            "decode",
            str(metadata_file),
            "--server-file",
            str(server_file),
            "--log-dir",
            str(log_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["log_dir"] == str(log_dir)


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ([], True),
        (["--retrievability-proof"], True),
        (["--no-retrievability-proof"], False),
    ],
)
def test_given_retrievability_proof_flag_when_encoding_then_forwards_flag(
    tmp_path, monkeypatch, flag, expected
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["retrievability_proof"] = args[6]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda log_dir: None
    )
    monkeypatch.setattr(
        "hybolt.hybolt.append_runtime_record", lambda *args, **kwargs: None
    )

    result = CliRunner().invoke(
        main, ["encode", str(input_file), "--server-list", str(server_list), *flag]
    )

    assert result.exit_code == 0, result.output
    assert captured["retrievability_proof"] is expected


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ([], True),
        (["--retrievability-proof"], True),
        (["--no-retrievability-proof"], False),
    ],
)
def test_given_retrievability_proof_flag_when_decoding_then_forwards_flag(
    tmp_path, monkeypatch, flag, expected
):
    metadata_file = tmp_path / "metadata.pkl"
    metadata_file.write_bytes(b"metadata")
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": []}), encoding="utf-8")
    captured = {}

    class StubHyboltDecode:
        def __init__(self, *args):
            captured["retrievability_proof"] = args[3]

        def decode(self):
            return tmp_path / "decoded.txt"

    monkeypatch.setattr("hybolt.hybolt.HyboltDecode", StubHyboltDecode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda value: None
    )

    result = CliRunner().invoke(
        main,
        ["decode", str(metadata_file), "--server-file", str(server_file), *flag],
    )

    assert result.exit_code == 0, result.output
    assert captured["retrievability_proof"] is expected


@pytest.mark.parametrize(
    ("flag", "expected"), [([], 0.25), (["--redundancy", "0.5"], 0.5)]
)
def test_given_redundancy_option_when_encoding_then_forwards_redundancy(
    tmp_path, monkeypatch, flag, expected
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["redundancy"] = args[7]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda log_dir: None
    )
    monkeypatch.setattr(
        "hybolt.hybolt.append_runtime_record", lambda *args, **kwargs: None
    )

    result = CliRunner().invoke(
        main, ["encode", str(input_file), "--server-list", str(server_list), *flag]
    )

    assert result.exit_code == 0, result.output
    assert captured["redundancy"] == expected


def test_given_non_positive_redundancy_when_encoding_then_rejects_option(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(json.dumps({"servers": []}), encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "encode",
            str(input_file),
            "--server-list",
            str(server_list),
            "--redundancy",
            "0",
        ],
    )

    assert result.exit_code != 0
    assert "--redundancy" in result.output


def _audit_report(passed, corrupted=()):
    from hybolt.audit.audit import AuditReport, ChunkAudit, ServerAudit

    server = ServerAudit(
        server="server_1",
        stored_packets=4,
        checked_packets=4,
        corrupted=list(corrupted),
    )
    chunk = ChunkAudit(
        chunk_index=0, packets=4, tolerated_losses=1, corrupted=len(corrupted)
    )
    report = AuditReport(
        scheme="bounded",
        servers=[server],
        chunks=[chunk],
        polynomial_index=3,
        remaining_challenges=39,
    )
    assert report.passed is passed
    return report


def _invoke_audit(tmp_path, monkeypatch, report, extra=()):
    metadata_file = tmp_path / "metadata.pkl"
    metadata_file.write_bytes(b"metadata")
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": []}), encoding="utf-8")
    captured = {}

    class StubAudit:
        def __init__(self, *args):
            captured["args"] = args

        def run(self):
            return report

    monkeypatch.setattr("hybolt.hybolt.Audit", StubAudit)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda value: None
    )
    result = CliRunner().invoke(
        main,
        ["audit", str(metadata_file), "--server-file", str(server_file), *extra],
    )
    return result, captured


def test_given_clean_audit_when_auditing_then_reports_success(tmp_path, monkeypatch):
    result, captured = _invoke_audit(
        tmp_path,
        monkeypatch,
        _audit_report(True),
        ["--sample-size", "2", "--tau-maximum", "1"],
    )

    assert result.exit_code == 0, result.output
    assert captured["args"][2:] == (2, 1)
    assert "Challenge polynomial 3 (39 challenges remaining)" in result.output
    assert "Audit passed" in result.output


def test_given_corruption_when_auditing_then_exits_with_failure(tmp_path, monkeypatch):
    from hybolt.audit.audit import PacketLocation

    corrupted = [PacketLocation(0, 2, "server_1", "input_chunk_0_packet_2.pkl")]

    result, _ = _invoke_audit(tmp_path, monkeypatch, _audit_report(False, corrupted))

    assert result.exit_code == 1
    assert "[FAILED]" in result.output
    assert "chunk 0: 1 corrupted, 1 tolerated [retrievable]" in result.output
    assert "Audit found 1 corrupted packets" in result.output


def test_given_audit_error_when_auditing_then_reports_click_error(
    tmp_path, monkeypatch
):
    metadata_file = tmp_path / "metadata.pkl"
    metadata_file.write_bytes(b"metadata")
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": []}), encoding="utf-8")

    class FailingAudit:
        def __init__(self, *args):
            raise ValueError("Audit requires metadata encoded with the proof")

    monkeypatch.setattr("hybolt.hybolt.Audit", FailingAudit)

    result = CliRunner().invoke(
        main, ["audit", str(metadata_file), "--server-file", str(server_file)]
    )

    assert result.exit_code == 1
    assert "Error: Audit requires metadata encoded with the proof" in result.output


@pytest.mark.parametrize("succeeded", [True, False])
def test_given_redistribute_flag_when_audit_finds_corruption_then_redistributes(
    tmp_path, monkeypatch, succeeded
):
    from hybolt.audit.audit import PacketLocation
    from hybolt.audit.redistribution import (
        AddedPacket,
        RedistributionReport,
        ReplacedPacket,
    )

    corrupted = [PacketLocation(0, 2, "server_1", "input_chunk_0_packet_2.pkl")]
    captured = {}

    class StubRedistribution:
        def __init__(self, *args):
            captured["args"] = args

        def run(self):
            return RedistributionReport(
                replaced=[ReplacedPacket(0, 2, 14, "server_1", "server_2")],
                added=[AddedPacket(0, 15, "server_3")],
                failed_chunks={} if succeeded else {1: "Insufficient packets"},
            )

    monkeypatch.setattr("hybolt.hybolt.Redistribution", StubRedistribution)

    result, _ = _invoke_audit(
        tmp_path,
        monkeypatch,
        _audit_report(False, corrupted),
        ["--redistribute", "--extra-repair", "1"],
    )

    assert captured["args"][2:] == (corrupted, 1)
    assert (
        "chunk 0: packet 2 (server_1) replaced by new packet 14 (server_2)"
        in result.output
    )
    assert "chunk 0: added packet 15 (server_3)" in result.output
    assert "Replaced 1 packets and added 1 repair packets" in result.output
    assert result.exit_code == (0 if succeeded else 1)


def test_given_compact_audit_when_auditing_then_reports_unbounded_challenges(
    tmp_path, monkeypatch
):
    from hybolt.audit.audit import AuditReport

    report = AuditReport(scheme="compact", servers=[], chunks=[])

    result, _ = _invoke_audit(tmp_path, monkeypatch, report)

    assert result.exit_code == 0, result.output
    assert "Compact audit (unbounded challenges)" in result.output


@pytest.mark.parametrize(
    ("flag", "expected"), [([], True), (["--no-seal-packets"], False)]
)
def test_given_seal_option_when_encoding_then_forwards_flag(
    tmp_path, monkeypatch, flag, expected
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["seal_packets"] = args[9]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda log_dir: None
    )
    monkeypatch.setattr(
        "hybolt.hybolt.append_runtime_record", lambda *args, **kwargs: None
    )

    result = CliRunner().invoke(
        main, ["encode", str(input_file), "--server-list", str(server_list), *flag]
    )

    assert result.exit_code == 0, result.output
    assert captured["seal_packets"] is expected


@pytest.mark.parametrize(
    ("flag", "expected"), [((), "r10"), (("--codec", "online"), "online")]
)
def test_given_codec_option_when_encoding_then_forwards_codec(
    tmp_path, monkeypatch, flag, expected
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    server_list = tmp_path / "servers.json"
    server_list.write_text(
        json.dumps({"servers": [{"id": 1, "storage_location": str(tmp_path)}]}),
        encoding="utf-8",
    )
    captured = {}

    class StubHyboltEncode:
        average_chunk_encode_seconds = 0.25
        average_block_size = 1.0
        average_polynomial_division_seconds = 0.01

        def __init__(self, *args):
            captured["codec"] = args[10]

        def encode(self):
            return 1

    monkeypatch.setattr("hybolt.hybolt.HyboltEncode", StubHyboltEncode)
    monkeypatch.setattr(
        "hybolt.hybolt.execution_logger.set_log_directory", lambda log_dir: None
    )
    monkeypatch.setattr(
        "hybolt.hybolt.append_runtime_record", lambda *args, **kwargs: None
    )

    result = CliRunner().invoke(
        main, ["encode", str(input_file), "--server-list", str(server_list), *flag]
    )

    assert result.exit_code == 0, result.output
    assert captured["codec"] == expected
