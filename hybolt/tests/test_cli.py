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
        def __init__(self, *args):
            captured["max_threads"] = args[4]

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
            "--max-threads",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["max_threads"] == 2
