import importlib.util
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

from hybolt.server.server import StoredPacket


CORRUPT_PACKETS_SCRIPT = Path(__file__).parents[2] / "scripts" / "corrupt_packets.py"


def _corrupt_packets(*arguments):
    spec = importlib.util.spec_from_file_location(
        "corrupt_packets", CORRUPT_PACKETS_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.corrupt_packets(*arguments)


def _store(path, data, tag):
    with path.open("wb") as file:
        pickle.dump(StoredPacket(data, tag), file)


def _load(path):
    with path.open("rb") as file:
        return pickle.load(file)


def _run(*arguments):
    return subprocess.run(
        [sys.executable, str(CORRUPT_PACKETS_SCRIPT), *map(str, arguments)],
        capture_output=True,
        check=False,
        text=True,
    )


def test_given_stored_packets_when_corrupting_then_flips_first_byte_and_keeps_tag(
    tmp_path,
):
    _store(tmp_path / "a.pkl", b"\x0fHyBolt", 7)
    _store(tmp_path / "b.pkl", b"\x0fHyBolt", 9)

    result = _run(tmp_path)

    assert result.returncode == 0, result.stdout
    assert result.stdout == f"Corrupted {tmp_path / 'a.pkl'}\n"
    assert _load(tmp_path / "a.pkl") == StoredPacket(b"\xf0HyBolt", 7)
    assert _load(tmp_path / "b.pkl") == StoredPacket(b"\x0fHyBolt", 9)


def test_given_count_when_corrupting_then_corrupts_that_many_in_name_order(tmp_path):
    for name in ("c.pkl", "a.pkl", "b.pkl"):
        _store(tmp_path / name, b"\x00", None)

    corrupted = _corrupt_packets(tmp_path, 2)

    assert corrupted == [tmp_path / "a.pkl", tmp_path / "b.pkl"]
    assert [_load(tmp_path / name).data for name in ("a.pkl", "b.pkl", "c.pkl")] == [
        b"\xff",
        b"\xff",
        b"\x00",
    ]


def test_given_too_few_packets_when_corrupting_then_fails_without_changes(tmp_path):
    _store(tmp_path / "a.pkl", b"\x00", None)

    with pytest.raises(ValueError, match="cannot corrupt 2"):
        _corrupt_packets(tmp_path, 2)

    assert _load(tmp_path / "a.pkl").data == b"\x00"
