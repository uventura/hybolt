import json

from click.testing import CliRunner

from hybolt.hybolt import main
from hybolt.utils.runtime_records import append_runtime_record


def test_given_existing_records_when_appending_then_keeps_previous_records(tmp_path):
    append_runtime_record(tmp_path, "a.txt", 10, 0.5, 1.0, 0.01)
    path = append_runtime_record(tmp_path, "b.txt", 20, 1.5, 2.0, 0.02)

    assert path.name == "encode_runtime.json"
    assert json.loads(path.read_text(encoding="utf-8")) == [
        {
            "file_path": "a.txt",
            "file_size": 10,
            "runtime": 0.5,
            "block_size": 1.0,
            "polynomial_division_runtime": 0.01,
        },
        {
            "file_path": "b.txt",
            "file_size": 20,
            "runtime": 1.5,
            "block_size": 2.0,
            "polynomial_division_runtime": 0.02,
        },
    ]


def test_given_runtime_file_when_plotting_then_writes_image(tmp_path):
    append_runtime_record(tmp_path, "a.txt", 10, 0.5, 1.0, 0.01)
    append_runtime_record(tmp_path, "b.txt", 20, 1.5, 2.0, 0.02)
    output = tmp_path / "plot.png"
    polynomial_output = tmp_path / "polynomial-plot.png"

    result = CliRunner().invoke(
        main,
        [
            "plot",
            str(tmp_path / "encode_runtime.json"),
            "--output",
            str(output),
            "--polynomial-division-output",
            str(polynomial_output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output.stat().st_size > 0
    assert polynomial_output.stat().st_size > 0
