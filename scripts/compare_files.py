#!/usr/bin/env python3
import argparse
from pathlib import Path


def files_are_equal(first_file: Path, second_file: Path) -> bool:
    if first_file.stat().st_size != second_file.stat().st_size:
        return False

    with first_file.open("rb") as first, second_file.open("rb") as second:
        while first_chunk := first.read(1024 * 1024):
            if first_chunk != second.read(1024 * 1024):
                return False
        return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two files by their binary contents."
    )
    parser.add_argument("first_file", type=Path)
    parser.add_argument("second_file", type=Path)
    arguments = parser.parse_args()

    if not arguments.first_file.is_file():
        print(f"Failed: file not found: {arguments.first_file}")
        return 1
    if not arguments.second_file.is_file():
        print(f"Failed: file not found: {arguments.second_file}")
        return 1

    if files_are_equal(arguments.first_file, arguments.second_file):
        print("Passed: files are identical")
        return 0

    print("Failed: files differ")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
