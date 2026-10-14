#!/usr/bin/env python3
import sys
import time
from pathlib import Path

import matplotlib
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from hybolt.utils.galois import gf2_poly_mod

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SAMPLE_SIZES_BYTES = (
    1,
    4,
    16,
    64,
    256,
    1024,
    4096,
    16384,
    65536,
    262144,
    1048576,
    10485760,
)
SAMPLES_PER_SIZE = 5
DIVISOR_DEGREE = 127
OUTPUT_PATH = Path("logs/gf2_poly_mod_runtime.png")


def polynomial_divisor() -> np.ndarray:
    divisor = np.zeros(DIVISOR_DEGREE + 1, dtype=np.uint8)
    divisor[0] = 1
    divisor[-1] = 1
    return divisor


def benchmark_division(message_size_bytes: int, divisor: np.ndarray) -> float:
    message = np.ones(message_size_bytes * 8, dtype=np.uint8)
    durations = []
    for _ in range(SAMPLES_PER_SIZE):
        started_at = time.perf_counter()
        gf2_poly_mod(message, divisor)
        durations.append(time.perf_counter() - started_at)
    return sum(durations) / len(durations)


def main() -> int:
    divisor = polynomial_divisor()
    runtimes = [
        benchmark_division(message_size_bytes, divisor)
        for message_size_bytes in SAMPLE_SIZES_BYTES
    ]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots()
    axis.plot(SAMPLE_SIZES_BYTES, runtimes, marker="o", linewidth=2)
    axis.set_title("GF(2) polynomial division runtime by message size")
    axis.set_xlabel("message size (bytes)")
    axis.set_ylabel("average division runtime (s)")
    axis.set_xscale("log", base=2)
    axis.grid(True, linestyle="--", alpha=0.4)
    figure.tight_layout()
    figure.savefig(OUTPUT_PATH)
    plt.close(figure)

    print(f"GF(2) polynomial division runtime plot written to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
