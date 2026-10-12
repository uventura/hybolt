import json

from click.testing import CliRunner

from hybolt.hybolt import main


def test_encode_command_forwards_max_threads(tmp_path, monkeypatch):
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


def test_encode_command_forwards_chunk_count(tmp_path, monkeypatch):
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


def test_decode_command_forwards_log_directory(tmp_path, monkeypatch):
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
