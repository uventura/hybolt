#!/usr/bin/env python3
import argparse
import statistics
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from hybolt.encryption.encode import Encode
from raptorq import Decoder


DEFAULT_SIZES = (1024, 4096, 16384, 65536, 262144, 1048576)


def parse_sizes(value: str) -> tuple[int, ...]:
    sizes = tuple(int(size) for size in value.split(","))
    if not sizes or any(size <= 0 for size in sizes):
        raise argparse.ArgumentTypeError("sizes must be positive integers")
    return sizes


def benchmark(size: int, samples: int, loss_count: int) -> tuple[float, float]:
    encode_durations = []
    decode_durations = []
    payload = bytes(index % 251 for index in range(size))
    symbol_size = max(1, size // 32)

    for _ in range(samples):
        encode_started_at = time.perf_counter()
        encoded = Encode(payload, symbol_size)
        encode_durations.append(time.perf_counter() - encode_started_at)

        decoder = Decoder.with_defaults(encoded.total_block_bytes, encoded.symbol_size)
        decoded = None
        decode_started_at = time.perf_counter()
        for packet in encoded.packets[loss_count:]:
            decoded = decoder.decode(packet.data)
            if decoded is not None:
                break
        decode_durations.append(time.perf_counter() - decode_started_at)

        if decoded is None or decoded != payload:
            raise RuntimeError(
                f"RaptorQ recovery failed for {size} bytes after dropping "
                f"{loss_count} packets"
            )

    return statistics.mean(encode_durations), statistics.mean(decode_durations)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark HyBolt's RaptorQ fountain-code implementation."
    )
    parser.add_argument(
        "--sizes",
        type=parse_sizes,
        default=DEFAULT_SIZES,
        help="Comma-separated payload sizes in bytes",
    )
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--loss-count", type=int, default=2)
    parser.add_argument(
        "--output", type=Path, default=Path("logs/fountain_codes_runtime.png")
    )
    args = parser.parse_args()
    if args.samples <= 0:
        parser.error("--samples must be positive")
    if args.loss_count < 0:
        parser.error("--loss-count cannot be negative")

    results = [benchmark(size, args.samples, args.loss_count) for size in args.sizes]
    encode_times, decode_times = zip(*results)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots()
    axis.plot(args.sizes, encode_times, marker="o", label="encode")
    axis.plot(args.sizes, decode_times, marker="o", label="decode after loss")
    axis.set_title("RaptorQ runtime by payload size")
    axis.set_xlabel("payload size (bytes)")
    axis.set_ylabel("average runtime (s)")
    axis.set_xscale("log", base=2)
    axis.grid(True, linestyle="--", alpha=0.4)
    axis.legend()
    figure.tight_layout()
    figure.savefig(args.output)
    plt.close(figure)
    print(f"RaptorQ runtime plot written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
