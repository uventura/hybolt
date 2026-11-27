#!/usr/bin/env python3
"""Corrupt stored packets of one server to simulate a faulty or dishonest provider.

The first byte of each packet's data is flipped and its tag is kept, so the
packet still loads but no longer matches the tag the client computed at encode
time. Packets are picked in name order, so runs are reproducible.
"""

import argparse
import pickle
from pathlib import Path

from hybolt.server.server import StoredPacket


def corrupt_packets(storage_location: Path, count: int = 1) -> list[Path]:
    if count < 1:
        raise ValueError("count must be positive")

    packet_files = sorted(Path(storage_location).glob("*.pkl"))
    if len(packet_files) < count:
        raise ValueError(
            f"{storage_location} holds {len(packet_files)} packets, "
            f"cannot corrupt {count}"
        )

    corrupted = []
    for packet_file in packet_files[:count]:
        with packet_file.open("rb") as file:
            stored = pickle.load(file)
        if not isinstance(stored, StoredPacket) or not stored.data:
            raise ValueError(f"{packet_file} is not a stored packet")

        data = bytes([stored.data[0] ^ 0xFF]) + stored.data[1:]
        with packet_file.open("wb") as file:
            pickle.dump(StoredPacket(data, stored.tag), file)
        corrupted.append(packet_file)
    return corrupted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Flip one byte of stored packets, keeping their tags."
    )
    parser.add_argument("storage_location", type=Path)
    parser.add_argument("--count", type=int, default=1)
    arguments = parser.parse_args()

    try:
        corrupted = corrupt_packets(arguments.storage_location, arguments.count)
    except ValueError as error:
        print(f"Failed: {error}")
        return 1

    for packet_file in corrupted:
        print(f"Corrupted {packet_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
