#!/usr/bin/env python3
"""Measurements and plots for the results chapter of the thesis.

Each experiment writes its raw numbers to ``<data-dir>/<name>.json`` and its
figure to ``<figure-dir>/<name>.pdf``. Run every experiment with

    python scripts/thesis_benchmarks.py all

or a subset, e.g. ``python scripts/thesis_benchmarks.py overhead loss``.
``--quick`` shrinks every workload to check the script end to end, and
``replot`` redraws the pipeline, detection, overhead and codec figures from the
saved data without measuring again.

The figures follow the architecture of the article: Hy-SAIL's polynomial MACs
of the source blocks and a SHA-256 hash per packet, without server tags or
packet encryption, in its bounded (l single-use polynomials) and unbounded
(one secret polynomial) models.
"""

import argparse
import functools
import json
import math
import pickle
import random
import shutil
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path

import matplotlib
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import hybolt.utils.galois as ga
from hybolt.audit.audit import Audit
from hybolt.constant import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_REDUNDANCY,
    DEFAULT_SOURCE_SYMBOLS,
    POLYNOMIAL_LAMBDA,
    POLYNOMIAL_SET_SIZE,
)
from hybolt.encryption import encode as encode_module
from hybolt.encryption import online_codes, raptor
from hybolt.encryption.retrievability import (
    BOUNDED_SCHEME,
    UNBOUNDED_SCHEME,
    PolynomialRetrievabilityProof,
)
from hybolt.hybolt_decode import HyboltDecode
from hybolt.hybolt_encode import HyboltEncode
from hybolt.logger.logger import execution_logger
from hybolt.server.packet_saver import PacketSaver

matplotlib.use("Agg")
import matplotlib.pyplot as plt

KIB = 1024
MIB = 1024 * KIB
MB = 1000 * 1000

# Categorical palette of the article figures (scripts/article_figures.py).
CATEGORICAL_COLORS = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#6250d6")
# Monochrome blue palette of the thesis figures. Series slots alternate dark and
# light tones so that neighbouring series stay apart; markers and line styles
# repeat the identity for grayscale print.
COLORS = ("#0b2d63", "#3f7fcb", "#8ab8e8", "#1f5aa8", "#6aa3e0", "#13417f")
# Sequential blues, dark to light, for stacked bars.
SEQUENTIAL_BLUES = ("#0b2d63", "#1f5aa8", "#3f7fcb", "#6aa3e0", "#9cc4ee", "#cfe2f7")
MARKERS = ("o", "s", "^", "D", "v", "P")
LINESTYLES = ("-", "--", "-.", ":", (0, (5, 1)), (0, (3, 1, 1, 1)))
TEXT_SECONDARY = "#52514e"
GRID = "#d9d8d4"
# Heading of this file's figures, also the legend label of HyBolt's own runs.
SCHEME_LABELS = {
    BOUNDED_SCHEME: "limitado",
    UNBOUNDED_SCHEME: "ilimitado",
    "none": "sem PoR",
}
PROOF_SCHEMES = (BOUNDED_SCHEME, UNBOUNDED_SCHEME)

# Hy-SAIL's thesis (2013), Figure 5.5: m(x) mod P(x) time by message block size.
# Word for a stored encoding symbol in figure labels: the thesis says "pacotes";
# scripts/presentation_plots.py switches it to "blocos" for the slides.
PACKETS_LABEL = "pacotes"

HYSAIL_MAC_SECONDS = {
    0.25: 0.0075,
    0.5: 0.02,
    1: 0.062,
    2: 0.16,
    4: 0.72,
    8: 2.5,
    16: 9.5,
    20: 14.5,
    24: 23.5,
    28: 31,
    32: 40,
    36: 52,
    40: 62,
}


def configure_style():
    plt.rcParams.update(
        {
            "figure.figsize": (6.0, 3.6),
            "figure.dpi": 150,
            "font.size": 9,
            "axes.titlesize": 9,
            "axes.labelsize": 9,
            "axes.edgecolor": TEXT_SECONDARY,
            "axes.labelcolor": "#0b0b0b",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.color": GRID,
            "grid.linestyle": "-",
            "grid.linewidth": 0.6,
            "xtick.color": TEXT_SECONDARY,
            "ytick.color": TEXT_SECONDARY,
            "legend.frameon": False,
            "legend.fontsize": 8,
            "lines.linewidth": 2,
            "lines.markersize": 5,
            "savefig.bbox": "tight",
        }
    )


def series_style(slot):
    return {
        "color": COLORS[slot],
        "marker": MARKERS[slot],
        "linestyle": LINESTYLES[slot],
    }


def format_mib_axis(axis, sizes):
    ticks = sorted({size / MIB for size in sizes})
    axis.set_xticks(
        ticks, [f"{tick:g}" if tick >= 1 else f"1/{1 / tick:g}" for tick in ticks]
    )
    axis.minorticks_off()


def size_label(size):
    if size >= MIB:
        return f"{size // MIB} MiB"
    return f"{size // KIB} KiB"


class StageTimer:
    """Accumulates the time spent in wrapped functions, grouped by stage."""

    def __init__(self):
        self.seconds = defaultdict(float)

    @contextmanager
    def instrument(self, stages):
        originals = []
        for owner, attribute, stage in stages:
            original = getattr(owner, attribute)
            originals.append((owner, attribute, original))
            setattr(owner, attribute, self._timed(original, stage))
        try:
            yield self
        finally:
            for owner, attribute, original in reversed(originals):
                setattr(owner, attribute, original)

    def _timed(self, func, stage):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            started_at = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                self.seconds[stage] += time.perf_counter() - started_at

        return wrapper


ENCODE_STAGES = (
    (encode_module.Encode, "_encode", "R10"),
    (PolynomialRetrievabilityProof, "tag_source_blocks", "MACs"),
    (PacketSaver, "save", "distribuição"),
    (HyboltEncode, "_save_packet_metadata", "metadados"),
)


class Deployment:
    """Three local storage directories, recreated for every encoded file."""

    def __init__(self, work_dir, server_count=3):
        self.root = Path(work_dir)
        self.servers = [
            {
                "id": index + 1,
                "storage_location": str(self.root / f"server_{index + 1}"),
            }
            for index in range(server_count)
        ]
        self.server_file = self.root / "servers.json"

    def reset(self):
        shutil.rmtree(self.root, ignore_errors=True)
        for server in self.servers:
            Path(server["storage_location"]).mkdir(parents=True)
        self.server_file.write_text(json.dumps({"servers": self.servers}))

    def stored_bytes(self):
        return sum(
            path.stat().st_size
            for server in self.servers
            for path in Path(server["storage_location"]).iterdir()
        )

    def packet_paths(self, server_index=0):
        return sorted(Path(self.servers[server_index]["storage_location"]).iterdir())


def default_chunk_code(redundancy=DEFAULT_REDUNDANCY):
    """K and r of a full chunk with HyBolt's default symbol size."""
    symbol_size = math.ceil(DEFAULT_CHUNK_SIZE / DEFAULT_SOURCE_SYMBOLS)
    k = raptor.source_symbol_count(DEFAULT_CHUNK_SIZE, symbol_size)
    return k, max(1, math.ceil(redundancy * k))


def write_input(path, size, seed=0):
    rng = np.random.default_rng(seed)
    with open(path, "wb") as target:
        remaining = size
        while remaining:
            block = min(remaining, 16 * MIB)
            target.write(rng.integers(0, 256, block, dtype=np.uint8).tobytes())
            remaining -= block


def encode_file(
    deployment,
    input_file,
    scheme,
    seal=False,
    redundancy=DEFAULT_REDUNDANCY,
    codec=raptor.CODEC,
    stages=ENCODE_STAGES,
):
    deployment.reset()
    metadata_dir = deployment.root / "metadata"
    timer = StageTimer()
    encoder = HyboltEncode(
        str(input_file),
        None,
        deployment.servers,
        str(metadata_dir),
        retrievability_proof=scheme != "none",
        redundancy=redundancy,
        proof_scheme=scheme if scheme in PROOF_SCHEMES else BOUNDED_SCHEME,
        seal_packets=seal,
        codec=codec,
    )
    with timer.instrument(stages):
        started_at = time.perf_counter()
        packet_count = encoder.encode()
        runtime = time.perf_counter() - started_at
    metadata_file = metadata_dir / f"{Path(input_file).stem}_metadata.pkl"
    return {
        "runtime": runtime,
        "packets": packet_count,
        "stages": dict(timer.seconds),
        "metadata_file": metadata_file,
        "metadata_bytes": metadata_file.stat().st_size,
        "stored_bytes": deployment.stored_bytes(),
    }


def decode_file(deployment, metadata_file, proof=True, timer=None, stages=()):
    output_file = deployment.root / "decoded.bin"
    decoder = HyboltDecode(
        str(metadata_file), str(deployment.server_file), str(output_file), proof
    )
    with (timer or StageTimer()).instrument(stages):
        started_at = time.perf_counter()
        decoder.decode()
        runtime = time.perf_counter() - started_at
    return runtime, output_file


def audit_file(deployment, metadata_file, sample_size=None):
    started_at = time.perf_counter()
    report = Audit(str(metadata_file), str(deployment.server_file), sample_size).run()
    return time.perf_counter() - started_at, report


def save_json(data_dir, name, data):
    path = Path(data_dir) / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def save_figure(figure, figure_dir, name):
    path = Path(figure_dir) / f"{name}.pdf"
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path)
    plt.close(figure)
    print(f"  figure written to {path}")
    return path


# ---------------------------------------------------------------------------
# Pipeline: encode, audit and decode by file size and proof scheme
# ---------------------------------------------------------------------------


def experiment_pipeline(args):
    sizes = {
        "none": [64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB, 64 * MIB],
        UNBOUNDED_SCHEME: [64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB, 64 * MIB],
        BOUNDED_SCHEME: [64 * KIB, 256 * KIB, MIB],
    }
    if args.quick:
        sizes = {scheme: [64 * KIB, 256 * KIB] for scheme in sizes}
    deployment = Deployment(Path(args.work_dir) / "pipeline")
    inputs_dir = Path(args.work_dir) / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for scheme, scheme_sizes in sizes.items():
        for size in scheme_sizes:
            input_file = inputs_dir / f"random_{size}.bin"
            if not input_file.exists():
                write_input(input_file, size)
            repeats = 1 if size >= 4 * MIB else args.repeats
            for repeat in range(repeats):
                print(f"  pipeline {scheme} {size_label(size)} run {repeat + 1}")
                encoded = encode_file(deployment, input_file, scheme)
                record = {
                    "scheme": scheme,
                    "file_size": size,
                    "repeat": repeat,
                    "encode_seconds": encoded["runtime"],
                    "packets": encoded["packets"],
                    "stages": encoded["stages"],
                    "metadata_bytes": encoded["metadata_bytes"],
                    "stored_bytes": encoded["stored_bytes"],
                }
                if scheme != "none":
                    audit_seconds, report = audit_file(
                        deployment, encoded["metadata_file"]
                    )
                    sampled_seconds, _ = audit_file(
                        deployment, encoded["metadata_file"], sample_size=50
                    )
                    record["audit_all_seconds"] = audit_seconds
                    record["audit_sample50_seconds"] = sampled_seconds
                    record["audit_passed"] = report.passed
                decode_seconds, output_file = decode_file(
                    deployment, encoded["metadata_file"], proof=scheme != "none"
                )
                record["decode_seconds"] = decode_seconds
                record["decoded_ok"] = (
                    output_file.read_bytes() == input_file.read_bytes()
                )
                results.append(record)
    save_json(args.data_dir, "pipeline", results)
    plot_pipeline(results, args.figure_dir)
    return results


def _aggregate(results, scheme, key):
    by_size = defaultdict(list)
    for record in results:
        if record["scheme"] == scheme and key in record:
            by_size[record["file_size"]].append(record[key])
    sizes = sorted(by_size)
    return sizes, [statistics.mean(by_size[size]) for size in sizes]


def plot_pipeline(results, figure_dir):
    schemes = [BOUNDED_SCHEME, UNBOUNDED_SCHEME, "none"]
    all_sizes = [record["file_size"] for record in results]
    for key, name, ylabel in (
        ("encode_seconds", "encode_runtime", "tempo de codificação (s)"),
        ("decode_seconds", "decode_runtime", "tempo de decodificação (s)"),
    ):
        figure, axis = plt.subplots()
        for slot, scheme in enumerate(schemes):
            sizes, values = _aggregate(results, scheme, key)
            if sizes:
                axis.plot(
                    [size / MIB for size in sizes],
                    values,
                    label=SCHEME_LABELS[scheme],
                    **series_style(slot),
                )
        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        format_mib_axis(axis, all_sizes)
        axis.set_xlabel("tamanho do arquivo (MiB)")
        axis.set_ylabel(ylabel)
        axis.legend()
        save_figure(figure, figure_dir, name)

    figure, axis = plt.subplots()
    for slot, scheme in enumerate(PROOF_SCHEMES):
        for style, (key, sample) in enumerate(
            (("audit_all_seconds", f"todos os {PACKETS_LABEL}"), ("audit_sample50_seconds", "s = 50"))
        ):
            sizes, values = _aggregate(results, scheme, key)
            if sizes:
                axis.plot(
                    [size / MIB for size in sizes],
                    values,
                    label=f"{SCHEME_LABELS[scheme]}, {sample}",
                    color=COLORS[slot],
                    marker=MARKERS[slot],
                    linestyle=LINESTYLES[style],
                )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    format_mib_axis(axis, all_sizes)
    axis.set_xlabel("tamanho do arquivo (MiB)")
    axis.set_ylabel("tempo da rodada de auditoria (s)")
    axis.legend()
    save_figure(figure, figure_dir, "audit_runtime")

    figure, axis = plt.subplots()
    for slot, scheme in enumerate(schemes):
        sizes, values = _aggregate(results, scheme, "metadata_bytes")
        if sizes:
            axis.plot(
                [size / MIB for size in sizes],
                [100 * value / size for value, size in zip(values, sizes)],
                label=f"{SCHEME_LABELS[scheme]} (medido)",
                **series_style(slot),
            )
    # K MACs of lambda bits per polynomial and full chunk.
    for slot, (polynomials, label) in enumerate(
        (
            (POLYNOMIAL_SET_SIZE, r"limitado, MACs em bits ($K l \lambda$ por chunk)"),
            (1, r"ilimitado, MACs em bits ($K \lambda$ por chunk)"),
        )
    ):
        axis.axhline(
            100
            * default_chunk_code()[0]
            * polynomials
            * POLYNOMIAL_LAMBDA
            / (8 * DEFAULT_CHUNK_SIZE),
            color=COLORS[slot],
            linestyle=":",
            linewidth=1.2,
            label=label,
        )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    format_mib_axis(axis, all_sizes)
    axis.set_xlabel("tamanho do arquivo (MiB)")
    axis.set_ylabel("metadados do usuário (% do arquivo)")
    axis.legend()
    save_figure(figure, figure_dir, "metadata_size")

    records = [
        record
        for record in results
        if record["file_size"] == MIB and record["repeat"] == 0
    ]
    if records:
        plot_stages(records, figure_dir)


def plot_stages(records, figure_dir):
    stages = ["R10", "MACs", "distribuição", "metadados", "outros"]
    figure, axis = plt.subplots(figsize=(6.0, 0.6 + 0.6 * len(records)))
    labels = [SCHEME_LABELS[record["scheme"]] for record in records]
    for row, record in enumerate(records):
        left = 0.0
        total = record["encode_seconds"]
        measured = sum(record["stages"].values())
        seconds = dict(record["stages"], outros=max(0.0, total - measured))
        for slot, stage in enumerate(stages):
            share = 100 * seconds.get(stage, 0.0) / total
            axis.barh(
                row,
                share,
                left=left,
                height=0.55,
                color=SEQUENTIAL_BLUES[slot],
                edgecolor="white",
                linewidth=2,
                label=stage if row == 0 else None,
            )
            if share >= 6:
                axis.text(
                    left + share / 2,
                    row,
                    f"{share:.0f}%",
                    ha="center",
                    va="center",
                    color="white" if slot < 3 else SEQUENTIAL_BLUES[0],
                    fontsize=8,
                )
            left += share
    axis.set_yticks(range(len(records)), labels)
    axis.set_xlim(0, 100)
    axis.set_xlabel("fração do tempo de codificação de 1 MiB (%)")
    axis.grid(axis="y", visible=False)
    axis.legend(ncol=5, loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=7)
    save_figure(figure, figure_dir, "encode_stages")


# ---------------------------------------------------------------------------
# MAC: polynomial division time against Hy-SAIL's measurements
# ---------------------------------------------------------------------------


def experiment_mac(args):
    sizes_kib = [0.25, 0.5, 1, 2, 4, 8, 16, 20, 24, 28, 32, 36, 40, 64]
    samples = 3 if args.quick else 20
    polynomial = ga.generate_challenge_polynomial()
    rng = np.random.default_rng(1)
    results = []
    for size_kib in sizes_kib:
        data = rng.integers(0, 256, int(size_kib * KIB), dtype=np.uint8).tobytes()
        coefficients = ga.bytes_to_poly_coeffs(data)
        durations = []
        for _ in range(samples):
            started_at = time.perf_counter()
            ga.gf2_poly_mod(coefficients, polynomial)
            durations.append(time.perf_counter() - started_at)
        integer = ga.bytes_to_poly_int(data)
        modulus = int("".join(str(bit) for bit in polynomial[::-1]), 2)
        int_durations = []
        for _ in range(samples):
            started_at = time.perf_counter()
            ga.gf2_mod(integer, modulus)
            int_durations.append(time.perf_counter() - started_at)
        results.append(
            {
                "block_kib": size_kib,
                "coefficient_seconds": statistics.median(durations),
                "integer_seconds": statistics.median(int_durations),
                "hysail_seconds": HYSAIL_MAC_SECONDS.get(size_kib),
            }
        )
    save_json(args.data_dir, "mac", results)

    figure, axis = plt.subplots()
    hysail = [record for record in results if record["hysail_seconds"]]
    axis.plot(
        [record["block_kib"] for record in hysail],
        [record["hysail_seconds"] for record in hysail],
        label="HySAIL (2013), Python 2.7",
        **series_style(1),
    )
    axis.plot(
        [record["block_kib"] for record in results],
        [record["coefficient_seconds"] for record in results],
        label="HyBolt (tabela de bytes, extensão em C)",
        **series_style(0),
    )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    axis.set_xlabel("tamanho do bloco (KiB)")
    axis.set_ylabel(r"tempo de $m(x)\ \mathrm{mod}\ P(x)$ (s)")
    axis.legend()
    save_figure(figure, args.figure_dir, "mac_runtime")
    return results


# ---------------------------------------------------------------------------
# Overhead: symbols needed for recovery, R10 against Online and LT codes
# ---------------------------------------------------------------------------


class PeelingDecoder:
    """Symbolic belief-propagation decoder: tracks which symbols are known."""

    def __init__(self, variable_count, target_count):
        self._known = bytearray(variable_count)
        self._target_count = target_count
        self._recovered_targets = 0
        self._checks = []
        self._checks_of = [[] for _ in range(variable_count)]

    @property
    def complete(self):
        return self._recovered_targets == self._target_count

    def add_check(self, variables):
        unknown = {variable for variable in variables if not self._known[variable]}
        check_index = len(self._checks)
        self._checks.append(unknown)
        for variable in unknown:
            self._checks_of[variable].append(check_index)
        if len(unknown) == 1:
            self._release([check_index])

    def _release(self, pending):
        while pending:
            check = self._checks[pending.pop()]
            if len(check) != 1:
                continue
            variable = check.pop()
            if self._known[variable]:
                continue
            self._known[variable] = 1
            if variable < self._target_count:
                self._recovered_targets += 1
            for other_index in self._checks_of[variable]:
                other = self._checks[other_index]
                other.discard(variable)
                if len(other) == 1:
                    pending.append(other_index)


def robust_soliton(k, c=0.1, delta=0.5):
    spike = c * math.log(k / delta) * math.sqrt(k)
    rho = [1 / k] + [1 / (d * (d - 1)) for d in range(2, k + 1)]
    pivot = max(1, min(k, int(round(k / spike))))
    tau = [0.0] * k
    for d in range(1, pivot):
        tau[d - 1] = spike / (d * k)
    tau[pivot - 1] = spike * math.log(spike / delta) / k
    weights = np.asarray(rho) + np.asarray(tau)
    return weights / weights.sum()


def received_until_decoded(codec, k, order):
    """Symbols of `order` received until the codec's own decoder finishes.

    Every packet of both codes is the XOR of the source symbols in its
    support, so the outcome is decided without the data: R10 decodes once the
    supports have rank K, Online Codes once peeling recovers every source.
    """
    if codec is online_codes:
        decoder = online_codes.PeelingDecoder(k)
        for received, esi in enumerate(order, start=1):
            if decoder.add(int(esi)):
                return received
        return None
    system = raptor.Gf2System(k)
    for received, esi in enumerate(order, start=1):
        system.add(raptor.symbol_support(k, int(esi)))
        if system.rank == k:
            return received
    return None


def symbols_needed_online(k, rng, pool_factor=4):
    """Check blocks of HyBolt's Online Codes received in random order until decoded."""
    return received_until_decoded(online_codes, k, rng.permutation(pool_factor * k))


def symbols_needed_lt(k, rng, limit_factor=4):
    decoder = PeelingDecoder(k, k)
    distribution = robust_soliton(k)
    degrees = rng.choice(k, size=limit_factor * k, p=distribution) + 1
    for received, degree in enumerate(degrees, start=1):
        decoder.add_check(rng.choice(k, size=degree, replace=False).tolist())
        if decoder.complete:
            return received
    return None


def symbols_needed_r10(k, rng, pool_factor=3):
    """Symbols received, in random order, until their R10 supports span GF(2)^K."""
    return received_until_decoded(raptor, k, rng.permutation(pool_factor * k))


def experiment_overhead(args):
    ks = [10, default_chunk_code()[0], 1000]
    trials = dict(zip(ks, (2000, 1000, 200)))
    if args.quick:
        trials = {k: 20 for k in ks}
    rng = np.random.default_rng(2)
    results = {}
    for k in ks:
        needed = {"r10": [], "online": [], "lt": []}
        started = time.perf_counter()
        for _ in range(trials[k]):
            needed["r10"].append(symbols_needed_r10(k, rng))
        r10_seconds = time.perf_counter() - started
        for _ in range(trials[k]):
            needed["online"].append(symbols_needed_online(k, rng))
            needed["lt"].append(symbols_needed_lt(k, rng))
        results[k] = {
            "needed": needed,
            "r10_rank_seconds": r10_seconds,
            "online_epsilon": online_codes.parameters(k).epsilon,
        }
        summary = {
            code: statistics.mean(value - k for value in values if value is not None)
            for code, values in needed.items()
        }
        print(f"  overhead K={k}: mean extra symbols {summary}")
    save_json(args.data_dir, "overhead", results)
    plot_overhead(results, args.figure_dir)
    return results


def plot_overhead(results, figure_dir):
    ks = [int(k) for k in results]
    figure, axes = plt.subplots(1, len(ks), figsize=(6.2, 2.8), sharey=True)
    codes = (
        ("r10", "Raptor R10"),
        ("online", "Online Codes"),
        ("lt", "LT (sóliton robusto)"),
    )
    for axis, k in zip(axes, ks):
        limit = 3.0 if k < 100 else 1.6
        ratios = np.linspace(0.9, limit, 400)
        needed = results[k] if k in results else results[str(k)]
        for slot, (code, label) in enumerate(codes):
            if code not in needed["needed"]:
                continue
            values = np.asarray(
                [
                    value if value is not None else np.inf
                    for value in needed["needed"][code]
                ]
            )
            success = [100 * np.mean(values <= ratio * k) for ratio in ratios]
            axis.step(
                ratios,
                success,
                where="post",
                label=label,
                color=COLORS[slot],
                linestyle=LINESTYLES[slot],
                linewidth=1.8,
            )
        axis.set_title(f"K = {k}")
        axis.set_xlabel("símbolos recebidos / K")
    axes[0].set_ylabel("decodificações bem-sucedidas (%)")
    axes[1].legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.25))
    save_figure(figure, figure_dir, "reception_overhead")


# ---------------------------------------------------------------------------
# Loss: decoding success after losing a fraction of each chunk's packets
# ---------------------------------------------------------------------------


def failure_by_losses(k, total, rng, trials, codec=raptor):
    """P(chunk lost | h random losses) for h = 0..total, over ESIs 0..total-1.

    A random order of the packets gives, at once, the outcome of losing its
    first h packets for every h: decodability only grows with the packets
    held, so the chunk survives while the packets left still include the
    prefix of the reversed order that decodes.
    """
    needed = []
    for _ in range(trials):
        received = received_until_decoded(codec, k, rng.permutation(total))
        needed.append(total + 1 if received is None else received)
    needed = np.asarray(needed)
    return [float(np.mean(needed > total - lost)) for lost in range(total + 1)]


def experiment_loss(args):
    redundancies = [0.1, 0.25, 0.5, 1.0]
    # HyBolt's default chunk: 100 source symbols of 6,500 bytes.
    k, _ = default_chunk_code()
    trials = 50 if args.quick else 4000
    rng = np.random.default_rng(3)
    results = []
    for redundancy in redundancies:
        repair = max(1, math.ceil(redundancy * k))
        total = k + repair
        failures = failure_by_losses(k, total, rng, trials)
        for lost in range(total + 1):
            rate = 1 - failures[lost]
            results.append(
                {
                    "redundancy": redundancy,
                    "repair": repair,
                    "total": total,
                    "lost": lost,
                    "success_rate": rate,
                }
            )
    save_json(args.data_dir, "loss", results)
    plot_loss(results, args.figure_dir)
    return results


def plot_loss(results, figure_dir):
    redundancies = sorted({row["redundancy"] for row in results})
    figure, axis = plt.subplots()
    for slot, redundancy in enumerate(redundancies):
        rows = [row for row in results if row["redundancy"] == redundancy]
        axis.plot(
            [100 * row["lost"] / row["total"] for row in rows],
            [100 * row["success_rate"] for row in rows],
            label=(
                rf"$\varepsilon$ = {redundancy:g} "
                rf"($K$ = {rows[0]['total'] - rows[0]['repair']}, "
                rf"$r$ = {rows[0]['repair']})"
            ),
            **series_style(slot),
        )
        alpha = rows[0]["repair"] / rows[0]["total"]
        axis.axvline(100 * alpha, color=COLORS[slot], linewidth=0.8, linestyle=":")
    axis.set_xlabel(f"{PACKETS_LABEL} perdidos no chunk (%)")
    axis.set_ylabel("chunks recuperados (%)")
    axis.set_xlim(0, 60)
    axis.legend(loc="lower left")
    save_figure(figure, figure_dir, "loss_tolerance")


# ---------------------------------------------------------------------------
# Detection: audits against random corruption
# ---------------------------------------------------------------------------


def corrupt_packets(paths, rng=None):
    """Flip one byte of each packet.

    With `rng`, each packet gets an independent error (random position and
    value); without it, every packet gets the same error, whose copies cancel
    in a plain XOR answer.
    """
    originals = {}
    for path in paths:
        originals[path] = path.read_bytes()
        stored = pickle.loads(originals[path])
        data = bytearray(stored.data)
        if rng is None:
            data[len(data) // 2] ^= 0xFF
        else:
            data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
        stored.data = bytes(data)
        path.write_bytes(pickle.dumps(stored))
    return originals


def restore_packets(originals):
    for path, content in originals.items():
        path.write_bytes(content)


def experiment_detection(args):
    """Audit rounds against random corruption, for each proof model.

    Measurements of models not run now are kept from the saved data, so one
    model can be measured again without repeating the others.
    """
    size = MIB if args.quick else 4 * MIB
    trials = 5 if args.quick else 100
    fractions = [0.01, 0.05]
    sample_sizes = [1, 2, 5, 10, 20, 50, 100, 200]
    input_file = Path(args.work_dir) / "inputs" / f"detection_{size}.bin"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    write_input(input_file, size, seed=4)
    rng = random.Random(5)

    saved = Path(args.data_dir) / "detection.json"
    empirical = [
        row
        for row in (
            json.loads(saved.read_text())["empirical"] if saved.exists() else []
        )
        if row.get("scheme", BOUNDED_SCHEME) not in args.detection_schemes
    ]
    for scheme in args.detection_schemes:
        deployment = Deployment(Path(args.work_dir) / f"detection_{scheme}")
        encoded = encode_file(deployment, input_file, scheme)
        # Each bounded round reveals one polynomial; restoring the metadata
        # before every round reuses the l polynomials across the measurements.
        metadata = encoded["metadata_file"].read_bytes()
        paths = deployment.packet_paths(0)
        server = deployment.servers[0]["storage_location"]
        for fraction in fractions:
            corrupted_count = max(1, round(fraction * len(paths)))
            for sample_size in sample_sizes:
                if sample_size > len(paths):
                    continue
                detected = 0
                for _ in range(trials):
                    originals = corrupt_packets(
                        rng.sample(paths, corrupted_count), rng
                    )
                    encoded["metadata_file"].write_bytes(metadata)
                    try:
                        _, report = audit_file(
                            deployment, encoded["metadata_file"], sample_size
                        )
                    finally:
                        restore_packets(originals)
                    audit = next(
                        item for item in report.servers if item.server == server
                    )
                    detected += audit.tau_provider > 0
                empirical.append(
                    {
                        "scheme": scheme,
                        "fraction": corrupted_count / len(paths),
                        "sample_size": sample_size,
                        "detection_rate": detected / trials,
                        "server_packets": len(paths),
                    }
                )
                print(
                    f"  detection {scheme} beta={fraction} s={sample_size}: "
                    f"{detected}/{trials}"
                )

    save_json(args.data_dir, "detection", {"empirical": empirical})
    plot_detection(empirical, fractions, sample_sizes, args.figure_dir)


def detection_probability(packets, corrupted, sample_size):
    """P(a sample without replacement hits a corrupted packet): 1 - C(N-c, s) / C(N, s)."""
    return 1 - math.comb(packets - corrupted, sample_size) / math.comb(
        packets, sample_size
    )


def plot_detection(empirical, fractions, sample_sizes, figure_dir):
    figure, axis = plt.subplots()
    markers = {BOUNDED_SCHEME: ("o", None), UNBOUNDED_SCHEME: ("s", "white")}
    for slot, fraction in enumerate(fractions):
        rows = [row for row in empirical if abs(row["fraction"] - fraction) < 0.01]
        beta = rows[0]["fraction"]
        packets = rows[0]["server_packets"]
        grid = np.arange(1, min(max(sample_sizes), packets) + 1)
        corrupted = round(beta * packets)
        axis.plot(
            grid,
            [100 * detection_probability(packets, corrupted, size) for size in grid],
            color=COLORS[slot],
            linestyle=LINESTYLES[slot],
            linewidth=1.5,
            label=rf"teórica, $\beta$ = {100 * beta:.1f}%",
        )
        for scheme, (marker, face) in markers.items():
            measured = [
                row for row in rows if row.get("scheme", BOUNDED_SCHEME) == scheme
            ]
            if not measured:
                continue
            axis.plot(
                [row["sample_size"] for row in measured],
                [100 * row["detection_rate"] for row in measured],
                linestyle="none",
                marker=marker,
                markersize=6,
                color=COLORS[slot],
                markerfacecolor=face or COLORS[slot],
                markeredgewidth=1.2,
                label=rf"{SCHEME_LABELS[scheme]}, $\beta$ = {100 * beta:.1f}%",
            )
    axis.set_xscale("log")
    axis.set_xlabel(f"{PACKETS_LABEL} amostrados por provedor ($s$)")
    axis.set_ylabel("rodadas que detectam corrupção (%)")
    axis.legend(loc="upper left")
    save_figure(figure, figure_dir, "audit_detection")


# ---------------------------------------------------------------------------
# Codecs: HyBolt with Online Codes, as in Hy-SAIL, against Raptor R10
# ---------------------------------------------------------------------------

CODECS = ((raptor.CODEC, "Raptor R10"), (online_codes.CODEC, "Online Codes"))
CODEC_CONFIGS = (
    ("codec", "codec"),
    ("none", "end-to-end"),
)
# The codec's own work, under one name for both codes.
CODEC_STAGES = (
    *(stage for stage in ENCODE_STAGES if stage[0] is not encode_module.Encode),
    (raptor.Encoder, "__init__", "código"),
    (raptor.Encoder, "symbols", "código"),
    (online_codes.Encoder, "__init__", "código"),
    (online_codes.Encoder, "symbols", "código"),
)
DECODER_STAGES = (
    (raptor.Decoder, "add", "código"),
    (online_codes.Decoder, "add", "código"),
)


def experiment_codecs(args):
    """Encode and decode the file sizes of Hy-SAIL's article with both codes.

    Both codes run inside the same HyBolt pipeline, on the same machine and
    with the same chunks, so the comparison isolates the fountain code.
    """
    sizes_mb = [1, 5] if args.quick else [50, 100, 500]
    deployment = Deployment(Path(args.work_dir) / "codecs")
    inputs_dir = Path(args.work_dir) / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    timings = []
    for size_mb in sizes_mb:
        input_file = inputs_dir / f"codecs_{size_mb}mb.bin"
        if not input_file.exists():
            write_input(input_file, size_mb * MB, seed=size_mb)
        for codec, _ in CODECS:
            for scheme, seal in (("none", False),):
                print(f"  codecs {size_mb} MB codec={codec} scheme={scheme}")
                encoded = encode_file(
                    deployment,
                    input_file,
                    scheme,
                    seal=seal,
                    codec=codec,
                    stages=CODEC_STAGES,
                )
                decode_timer = StageTimer()
                decode_seconds, output_file = decode_file(
                    deployment,
                    encoded["metadata_file"],
                    proof=scheme != "none",
                    timer=decode_timer,
                    stages=DECODER_STAGES,
                )
                timings.append(
                    {
                        "size_mb": size_mb,
                        "codec": codec,
                        "scheme": scheme,
                        "sealed": seal,
                        "encode_seconds": encoded["runtime"],
                        "encode_codec_seconds": encoded["stages"].get("código", 0.0),
                        "decode_seconds": decode_seconds,
                        "decode_codec_seconds": decode_timer.seconds["código"],
                        "stages": encoded["stages"],
                        "packets": encoded["packets"],
                        "stored_bytes": encoded["stored_bytes"],
                        "metadata_bytes": encoded["metadata_bytes"],
                        "decoded_ok": output_file.read_bytes()
                        == input_file.read_bytes(),
                    }
                )
        input_file.unlink()

    results = {
        "timings": timings,
        "chunk": chunk_codec_benchmark(args),
        "loss": codec_loss_model(args),
    }
    save_json(args.data_dir, "codecs", results)
    plot_codecs(results, args.figure_dir)
    return results


def chunk_codec_benchmark(args):
    """Encode and decode one default chunk in memory, without storage or proofs.

    The file runs above are dominated by writing and reading packets, whose
    time varies between runs; this isolates each code's own work. Decoding
    receives the stored packets in random order until the chunk is recovered.
    """
    k, repair = default_chunk_code()
    symbol_size = math.ceil(DEFAULT_CHUNK_SIZE / DEFAULT_SOURCE_SYMBOLS)
    trials = 5 if args.quick else 200
    rng = np.random.default_rng(9)
    results = {}
    for codec, _ in CODECS:
        module = raptor if codec == raptor.CODEC else online_codes
        encode_seconds, decode_seconds, received = [], [], []
        for _ in range(trials):
            data = rng.integers(0, 256, DEFAULT_CHUNK_SIZE, dtype=np.uint8).tobytes()
            started_at = time.perf_counter()
            symbols = module.Encoder(data, symbol_size).symbols(repair)
            encode_seconds.append(time.perf_counter() - started_at)
            decoder = module.Decoder(len(data), symbol_size)
            started_at = time.perf_counter()
            for count, index in enumerate(rng.permutation(len(symbols)), start=1):
                decoded = decoder.add(*symbols[index])
                if decoded is not None:
                    break
            decode_seconds.append(time.perf_counter() - started_at)
            if decoded != data:
                raise AssertionError(f"{codec} decoded a different chunk")
            received.append(count)
        results[codec] = {
            "k": k,
            "stored_packets": len(symbols),
            "encode_seconds": statistics.median(encode_seconds),
            "decode_seconds": statistics.median(decode_seconds),
            "received_mean": statistics.mean(received),
            "received_max": max(received),
        }
        print(f"  chunk {codec}: {results[codec]}")
    return results


def codec_loss_model(args):
    """Loss tolerance of a default chunk with each code and redundancy.

    Online Codes store as many check blocks as the chunk needs to decode, at
    least K + r, which is the set the encoder writes.
    """
    k, _ = default_chunk_code()
    trials = 50 if args.quick else 4000
    rng = np.random.default_rng(8)
    results = []
    for redundancy in (0.25, 0.5):
        repair = max(1, math.ceil(redundancy * k))
        for codec, _ in CODECS:
            module = raptor if codec == raptor.CODEC else online_codes
            total = k + repair
            if module is online_codes:
                total = online_codes.check_block_count(k, total)
            failures = failure_by_losses(k, total, rng, trials, codec=module)
            results.append(
                {
                    "codec": codec,
                    "redundancy": redundancy,
                    "k": k,
                    "total": total,
                    "success_rate": [1 - failure for failure in failures],
                }
            )
            tolerated = max(
                lost for lost, failure in enumerate(failures) if failure <= 0.01
            )
            print(
                f"  codec loss {codec} eps={redundancy}: {total} packets, "
                f"{tolerated} losses tolerated in 99% of chunks"
            )
    return results


def plot_codecs(results, figure_dir):
    timings = results["timings"]
    sizes_mb = sorted({record["size_mb"] for record in timings})
    figure, axes = plt.subplots(1, 2, figsize=(6.2, 3.0), sharey=True)
    for axis, key, title in (
        (axes[0], "encode", "codificação"),
        (axes[1], "decode", "decodificação"),
    ):
        for codec_slot, (codec, codec_label) in enumerate(CODECS):
            for config_slot, (config, config_label) in enumerate(CODEC_CONFIGS):
                values = [
                    _codec_value(timings, size, codec, config, key) for size in sizes_mb
                ]
                axis.plot(
                    sizes_mb,
                    values,
                    color=COLORS[codec_slot],
                    marker=MARKERS[config_slot],
                    linestyle=LINESTYLES[config_slot],
                    label=f"{codec_label}, {config_label}",
                )
        axis.set_xscale("log")
        axis.set_yscale("log")
        axis.set_xticks(sizes_mb, [f"{size}" for size in sizes_mb])
        axis.minorticks_off()
        axis.set_xlabel("tamanho do arquivo (MB)")
        axis.set_title(title)
    axes[0].set_ylabel("tempo (s)")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(
        handles, labels, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.02)
    )
    save_figure(figure, figure_dir, "codec_comparison")

    figure, axis = plt.subplots()
    for row in results["loss"]:
        codec_slot = [codec for codec, _ in CODECS].index(row["codec"])
        style_slot = 0 if row["redundancy"] == 0.25 else 1
        total = row["total"]
        axis.plot(
            [100 * lost / total for lost in range(total + 1)],
            [100 * rate for rate in row["success_rate"]],
            color=COLORS[codec_slot],
            linestyle=LINESTYLES[style_slot],
            linewidth=1.8,
            label=(
                f"{dict(CODECS)[row['codec']]}, "
                rf"$\varepsilon$ = {row['redundancy']:g} ({total} {PACKETS_LABEL})"
            ),
        )
    axis.set_xlabel(f"{PACKETS_LABEL} perdidos no chunk (%)")
    axis.set_ylabel("chunks recuperados (%)")
    axis.set_xlim(0, 40)
    axis.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    save_figure(figure, figure_dir, "codec_loss")


def _codec_value(timings, size_mb, codec, config, key):
    scheme = "none" if config == "codec" else config
    for record in timings:
        if (
            record["size_mb"] == size_mb
            and record["codec"] == codec
            and record["scheme"] == scheme
        ):
            if config == "codec":
                return record[f"{key}_codec_seconds"]
            return record[f"{key}_seconds"]
    return np.nan


# ---------------------------------------------------------------------------
# Degrees: degree distributions of the fountain codes
# ---------------------------------------------------------------------------


def r10_degree_distribution():
    """RFC 5053, Section 5.4.4.2, Table 1."""
    distribution = np.zeros(max(raptor.tables.DEGREES))
    previous = 0
    for threshold, degree in zip(
        raptor.tables.DEGREE_THRESHOLDS, raptor.tables.DEGREES
    ):
        distribution[degree - 1] = (threshold - previous) / (1 << 20)
        previous = threshold
    return distribution


def experiment_degrees(args):
    k = 1000
    distributions = {
        "LT, sóliton robusto (K = 1000)": robust_soliton(k),
        r"Online Codes ($\varepsilon$ = 0,01)": np.asarray(
            online_codes.degree_distribution(0.01)
        ),
        "Raptor R10 (RFC 5053)": r10_degree_distribution(),
    }
    summary = {}
    figure, axis = plt.subplots()
    for slot, (label, distribution) in enumerate(distributions.items()):
        degrees = np.arange(1, len(distribution) + 1)
        mask = distribution > 0
        axis.plot(
            degrees[mask],
            distribution[mask],
            color=COLORS[slot],
            linestyle=LINESTYLES[slot],
            linewidth=1.6,
            label=label,
        )
        summary[label] = {
            "max_degree": int(degrees[mask][-1]),
            "mean_degree": float((degrees * distribution).sum()),
            "degree_1": float(distribution[0]),
            "degree_2": float(distribution[1]),
        }
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("grau do símbolo codificado")
    axis.set_ylabel("probabilidade")
    axis.legend()
    save_json(args.data_dir, "degrees", summary)
    save_figure(figure, args.figure_dir, "degree_distributions")
    print(f"  {summary}")
    return summary


def replot_saved(args):
    """Redraw the figures of the slow experiments from their saved JSON."""
    data_dir = Path(args.data_dir)
    plot_pipeline(json.loads((data_dir / "pipeline.json").read_text()), args.figure_dir)
    detection = json.loads((data_dir / "detection.json").read_text())
    plot_detection(
        detection["empirical"],
        [0.01, 0.05],
        [1, 2, 5, 10, 20, 50, 100, 200],
        args.figure_dir,
    )
    plot_codecs(json.loads((data_dir / "codecs.json").read_text()), args.figure_dir)
    plot_overhead(json.loads((data_dir / "overhead.json").read_text()), args.figure_dir)


EXPERIMENTS = {
    "degrees": experiment_degrees,
    "mac": experiment_mac,
    "overhead": experiment_overhead,
    "loss": experiment_loss,
    "pipeline": experiment_pipeline,
    "detection": experiment_detection,
    "codecs": experiment_codecs,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "experiments",
        nargs="+",
        choices=[*EXPERIMENTS, "all", "replot"],
        help="Experiments to run; replot redraws the slow ones from saved data",
    )
    parser.add_argument("--quick", action="store_true", help="Run tiny workloads")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Scratch directory for inputs and storage (a temporary one by default)",
    )
    parser.add_argument(
        "--detection-schemes",
        type=lambda value: value.split(","),
        default=list(PROOF_SCHEMES),
        help="Proof models measured by the detection experiment, comma separated",
    )
    parser.add_argument("--data-dir", type=Path, default=Path("logs/thesis"))
    parser.add_argument(
        "--figure-dir", type=Path, default=Path("doc/thesis/img/resultados")
    )
    args = parser.parse_args()
    if args.work_dir is None:
        args.work_dir = Path(tempfile.mkdtemp(prefix="hybolt-thesis-"))
    args.work_dir.mkdir(parents=True, exist_ok=True)
    execution_logger.set_log_directory(str(args.work_dir / "logs"))
    configure_style()

    if "replot" in args.experiments:
        replot_saved(args)
        return 0

    names = list(EXPERIMENTS) if "all" in args.experiments else args.experiments
    for name in names:
        print(f"Running {name}")
        started_at = time.perf_counter()
        EXPERIMENTS[name](args)
        print(f"  {name} finished in {time.perf_counter() - started_at:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
