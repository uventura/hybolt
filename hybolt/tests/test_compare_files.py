import subprocess
import sys
from pathlib import Path


COMPARE_FILES_SCRIPT = (
    Path(__file__).parents[2] / "scripts" / "compare_files.py"
)


def test_given_identical_files_when_comparing_then_reports_passed(tmp_path):
    first_file = tmp_path / "first.bin"
    second_file = tmp_path / "second.bin"
    first_file.write_bytes(b"\x00HyBolt\xff")
    second_file.write_bytes(b"\x00HyBolt\xff")

    result = subprocess.run(
        [sys.executable, str(COMPARE_FILES_SCRIPT), str(first_file), str(second_file)],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "Passed: files are identical\n"


def test_given_different_files_when_comparing_then_reports_failed(tmp_path):
    first_file = tmp_path / "first.bin"
    second_file = tmp_path / "second.bin"
    first_file.write_bytes(b"first")
    second_file.write_bytes(b"second")

    result = subprocess.run(
        [sys.executable, str(COMPARE_FILES_SCRIPT), str(first_file), str(second_file)],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == "Failed: files differ\n"
