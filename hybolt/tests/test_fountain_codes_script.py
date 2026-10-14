import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "fountain_codes_tests.py"


def test_given_small_sizes_when_benchmarking_then_writes_raptorq_plot(tmp_path):
    output = tmp_path / "fountain_codes_runtime.png"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--sizes",
            "64,128",
            "--samples",
            "1",
            "--loss-count",
            "1",
            "--output",
            str(output),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert output.is_file()
    assert output.stat().st_size > 0
    assert "RaptorQ runtime plot written to" in result.stdout
