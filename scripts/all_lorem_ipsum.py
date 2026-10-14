#!/usr/bin/env python3
import re
import subprocess
from glob import glob
from pathlib import Path

LIMIT = 1024
LOREM_IPSUM_DIRECTORY = Path("examples/lorem_ipsum")
SERVER_LIST = Path("examples/server_list_example.json")
METADATA_DIRECTORY = Path("output")
LOG_DIRECTORY = Path("logs")


def lorem_file_size_kib(file_path: Path) -> int:
    match = re.fullmatch(r"(\d+)kib\.txt", file_path.name)
    if match is None:
        raise ValueError(f"Unexpected lorem ipsum filename: {file_path}")
    return int(match.group(1))


def input_files() -> list[Path]:
    files = [Path(path) for path in glob(str(LOREM_IPSUM_DIRECTORY / "*"))]
    return sorted(
        (
            file_path
            for file_path in files
            if file_path.is_file() and lorem_file_size_kib(file_path) < LIMIT
        ),
        key=lorem_file_size_kib,
    )


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    METADATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)

    for input_file in input_files():
        run_command(
            [
                "hybolt",
                "encode",
                "--server-list",
                str(SERVER_LIST),
                "--metadata-output",
                str(METADATA_DIRECTORY),
                "--log-dir",
                str(LOG_DIRECTORY),
                "--chunk-count",
                "1",
                str(input_file),
            ]
        )

    run_command(
        [
            "hybolt",
            "plot",
            str(LOG_DIRECTORY / "encode_runtime.json"),
            "--output",
            str(LOG_DIRECTORY / "encode_runtime.png"),
            "--polynomial-division-output",
            str(LOG_DIRECTORY / "polynomial_division_runtime.png"),
        ]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
