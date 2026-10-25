#!/usr/bin/env python3
"""Measurements and plots for the results chapter of the thesis.

Each experiment writes its raw numbers to ``<data-dir>/<name>.json`` and its
figure to ``<figure-dir>/<name>.pdf``. Run every experiment with

    python scripts/thesis_benchmarks.py all

or a subset, e.g. ``python scripts/thesis_benchmarks.py overhead loss``.
``--quick`` shrinks every workload to check the script end to end, and
``replot`` redraws the pipeline, detection and Hy-SAIL figures from the saved
data without measuring again.
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
from hybolt.constant import POLYNOMIAL_LAMBDA, POLYNOMIAL_SET_SIZE
from hybolt.encryption import encode as encode_module
from hybolt.encryption import raptor
from hybolt.encryption.retrievability import (
    BOUNDED_SCHEME,
    COMPACT_SCHEME,
    CompactRetrievabilityProof,
    PolynomialRetrievabilityProof,
)
from hybolt.encryption.sealing import SealingKeys
from hybolt.hybolt_decode import HyboltDecode
from hybolt.hybolt_encode import HyboltEncode
from hybolt.logger.logger import execution_logger
from hybolt.server.packet_saver import PacketSaver

matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    # RaptorQ is no longer a HyBolt dependency; when installed, it is measured
    # as the reference the R10 trade-off is compared with.
    import raptorq
except ImportError:
    raptorq = None

KIB = 1024
MIB = 1024 * KIB
MB = 1000 * 1000

# Categorical slots of the reference palette, in fixed order; markers and line
# styles repeat the identity for grayscale print.
COLORS = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#6250d6")
MARKERS = ("o", "s", "^", "D", "v", "P")
LINESTYLES = ("-", "--", "-.", ":", (0, (5, 1)), (0, (3, 1, 1, 1)))
TEXT_SECONDARY = "#52514e"
GRID = "#d9d8d4"
# Heading of this file's figures, also the legend label of HyBolt's own runs.
SCHEME_LABELS = {
    COMPACT_SCHEME: "compacto",
    BOUNDED_SCHEME: "limitado",
    "none": "sem prova",
}

# Hy-SAIL's measurements, read from the figures of its publications.
# Thesis (2013), Figure 5.5: m(x) mod P(x) time by message block size.
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
# IEEE Access (2019), Figures 5 and 6: fastest encode and decode over n.
HYSAIL_CODEC_SECONDS = {
    50: {"encode": 3.0, "decode": 2.0},
    100: {"encode": 5.0, "decode": 4.0},
    500: {"encode": 21.0, "decode": 27.0},
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
    (SealingKeys, "seal", "cifragem"),
    (PolynomialRetrievabilityProof, "tag_source_blocks", "MAC/etiqueta"),
    (CompactRetrievabilityProof, "attach_server_tags", "MAC/etiqueta"),
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


def default_chunk_code(redundancy=0.25):
    """K and r of a full chunk with HyBolt's default 10% symbol size."""
    chunk_size = POLYNOMIAL_LAMBDA * 512
    symbol_size = math.ceil(0.1 * chunk_size)
    k = raptor.source_symbol_count(chunk_size, symbol_size)
    return k, max(1, math.ceil(redundancy * k))


def write_input(path, size, seed=0):
    rng = np.random.default_rng(seed)
    with open(path, "wb") as target:
        remaining = size
        while remaining:
            block = min(remaining, 16 * MIB)
            target.write(rng.integers(0, 256, block, dtype=np.uint8).tobytes())
            remaining -= block


def encode_file(deployment, input_file, scheme, seal=True, redundancy=0.25):
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
        proof_scheme=scheme if scheme != "none" else COMPACT_SCHEME,
        seal_packets=seal,
    )
    with timer.instrument(ENCODE_STAGES):
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


def decode_file(deployment, metadata_file, proof=True):
    output_file = deployment.root / "decoded.bin"
    started_at = time.perf_counter()
    HyboltDecode(
        str(metadata_file), str(deployment.server_file), str(output_file), proof
    ).decode()
    return time.perf_counter() - started_at, output_file


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
        COMPACT_SCHEME: [64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB, 64 * MIB],
        "none": [64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB, 64 * MIB],
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
            repeats = 1 if size >= 4 * MIB or scheme == BOUNDED_SCHEME else args.repeats
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
    schemes = [COMPACT_SCHEME, BOUNDED_SCHEME, "none"]
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
    for slot, (scheme, key, label) in enumerate(
        (
            (COMPACT_SCHEME, "audit_all_seconds", "compacto, todos os pacotes"),
            (BOUNDED_SCHEME, "audit_all_seconds", "limitado, todos os pacotes"),
            (COMPACT_SCHEME, "audit_sample50_seconds", "compacto, s = 50"),
            (BOUNDED_SCHEME, "audit_sample50_seconds", "limitado, s = 50"),
        )
    ):
        sizes, values = _aggregate(results, scheme, key)
        if sizes:
            axis.plot(
                [size / MIB for size in sizes],
                values,
                label=label,
                **series_style(slot),
            )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    format_mib_axis(axis, all_sizes)
    axis.set_xlabel("tamanho do arquivo (MiB)")
    axis.set_ylabel("tempo da rodada de auditoria (s)")
    axis.legend()
    save_figure(figure, figure_dir, "audit_runtime")

    figure, axis = plt.subplots()
    for slot, scheme in enumerate(schemes[:2]):
        sizes, values = _aggregate(results, scheme, "metadata_bytes")
        if sizes:
            axis.plot(
                [size / MIB for size in sizes],
                [100 * value / size for value, size in zip(values, sizes)],
                label=f"{SCHEME_LABELS[scheme]} (medido)",
                **series_style(slot),
            )
    # n * l MACs: K source blocks per chunk of lambda * 512 bytes.
    axis.axhline(
        100
        * default_chunk_code()[0]
        * POLYNOMIAL_SET_SIZE
        * POLYNOMIAL_LAMBDA
        / (8 * POLYNOMIAL_LAMBDA * 512),
        color=COLORS[3],
        linestyle=":",
        linewidth=1.5,
        label=r"limitado, MACs em bits ($K l \lambda$ por chunk)",
    )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    format_mib_axis(axis, all_sizes)
    axis.set_xlabel("tamanho do arquivo (MiB)")
    axis.set_ylabel("metadados do usuário (% do arquivo)")
    axis.legend()
    save_figure(figure, figure_dir, "metadata_size")

    compact = [
        record
        for record in results
        if record["scheme"] in (COMPACT_SCHEME, BOUNDED_SCHEME)
        and record["file_size"] == MIB
        and record["repeat"] == 0
    ]
    if compact:
        plot_stages(compact, figure_dir)


def plot_stages(records, figure_dir):
    stages = [
        "R10",
        "cifragem",
        "MAC/etiqueta",
        "distribuição",
        "metadados",
        "outros",
    ]
    figure, axis = plt.subplots(figsize=(6.0, 2.2))
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
                color=COLORS[slot],
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
                    color="white",
                    fontsize=8,
                )
            left += share
    axis.set_yticks(range(len(records)), labels)
    axis.set_xlim(0, 100)
    axis.set_xlabel("fração do tempo de codificação de 1 MiB (%)")
    axis.grid(axis="y", visible=False)
    axis.legend(ncol=6, loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=7)
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
        label="HyBolt, esquema limitado (tabela de bytes)",
        **series_style(0),
    )
    axis.plot(
        [record["block_kib"] for record in results],
        [record["integer_seconds"] for record in results],
        label="HyBolt, esquema compacto (inteiros)",
        **series_style(2),
    )
    axis.set_xscale("log", base=2)
    axis.set_yscale("log")
    axis.set_xlabel("tamanho do bloco (KiB)")
    axis.set_ylabel(r"tempo de $m(x)\ \mathrm{mod}\ P(x)$ (s)")
    axis.legend()
    save_figure(figure, args.figure_dir, "mac_runtime")
    return results


# ---------------------------------------------------------------------------
# Overhead: symbols needed for recovery, R10 against RaptorQ, Online and LT codes
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


def online_max_degree(epsilon):
    return math.ceil(math.log(epsilon**2 / 4) / math.log(1 - epsilon / 2))


def online_auxiliary_count(k, epsilon, q):
    return max(1, math.ceil(0.55 * q * epsilon * k))


def online_epsilon(k, q=3, epsilon=0.01):
    """Smallest epsilon whose maximum degree fits in the composite message.

    Maymounkov's distribution assumes F < k; for small k the design epsilon
    has to grow until it does.
    """
    while online_max_degree(epsilon) > k + online_auxiliary_count(k, epsilon, q):
        epsilon *= 1.05
    return epsilon


def online_degree_distribution(epsilon):
    max_degree = online_max_degree(epsilon)
    rho_1 = 1 - (1 + 1 / max_degree) / (1 + epsilon)
    weights = [rho_1] + [
        (1 - rho_1) * max_degree / ((max_degree - 1) * degree * (degree - 1))
        for degree in range(2, max_degree + 1)
    ]
    weights = np.asarray(weights)
    return weights / weights.sum()


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


def symbols_needed_online(k, rng, q=3, limit_factor=4):
    epsilon = online_epsilon(k, q)
    auxiliary = online_auxiliary_count(k, epsilon, q)
    composite = k + auxiliary
    decoder = PeelingDecoder(composite, k)
    members = defaultdict(list)
    for source in range(k):
        for auxiliary_index in rng.choice(
            auxiliary, size=min(q, auxiliary), replace=False
        ):
            members[auxiliary_index].append(source)
    for auxiliary_index, sources in members.items():
        decoder.add_check(sources + [k + auxiliary_index])
    distribution = online_degree_distribution(epsilon)
    degrees = rng.choice(len(distribution), size=limit_factor * k, p=distribution) + 1
    for received, degree in enumerate(degrees, start=1):
        decoder.add_check(rng.choice(composite, size=degree, replace=False).tolist())
        if decoder.complete:
            return received
    return None


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
    """Symbols received, in random order, until their R10 supports span GF(2)^K.

    Every R10 symbol is the XOR of the source symbols in its support, so a set
    decodes exactly when the supports have rank K: this is the decoder's own
    criterion, computed without the data.
    """
    system = raptor.Gf2System(k)
    for received, esi in enumerate(rng.permutation(pool_factor * k), start=1):
        system.add(raptor.symbol_support(k, int(esi)))
        if system.rank == k:
            return received
    return None


def symbols_needed_raptorq(packets, transfer_length, symbol_size, rng):
    decoder = raptorq.Decoder.with_defaults(transfer_length, symbol_size)
    for received, index in enumerate(rng.permutation(len(packets)), start=1):
        if decoder.decode(packets[index]) is not None:
            return received
    return None


def experiment_overhead(args):
    ks = [default_chunk_code()[0], 100, 1000]
    trials = dict(zip(ks, (2000, 1000, 200)))
    if args.quick:
        trials = {k: 20 for k in ks}
    symbol_size = 16
    rng = np.random.default_rng(2)
    results = {}
    for k in ks:
        needed = {"r10": [], "online": [], "lt": []}
        started = time.perf_counter()
        for _ in range(trials[k]):
            needed["r10"].append(symbols_needed_r10(k, rng))
        r10_seconds = time.perf_counter() - started
        if raptorq is not None:
            data = rng.integers(0, 256, k * symbol_size, dtype=np.uint8).tobytes()
            packets = raptorq.Encoder.with_defaults(
                data, symbol_size
            ).get_encoded_packets(k)
            needed["raptorq"] = [
                symbols_needed_raptorq(packets, len(data), symbol_size, rng)
                for _ in range(trials[k])
            ]
        for _ in range(trials[k]):
            needed["online"].append(symbols_needed_online(k, rng))
            needed["lt"].append(symbols_needed_lt(k, rng))
        results[k] = {
            "needed": needed,
            "r10_rank_seconds": r10_seconds,
            "online_epsilon": online_epsilon(k),
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
        ("raptorq", "RaptorQ"),
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
    axes[1].legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.25))
    save_figure(figure, figure_dir, "reception_overhead")


# ---------------------------------------------------------------------------
# Loss: decoding success after losing a fraction of each chunk's packets
# ---------------------------------------------------------------------------


def recoverable_after_losses(k, total, rng, trials, lost):
    """Fraction of random `lost`-subsets of ESIs 0..total-1 that still decode."""
    supports = [raptor.symbol_support(k, esi) for esi in range(total)]
    successes = 0
    for _ in range(trials):
        system = raptor.Gf2System(k)
        for index in rng.permutation(total)[lost:]:
            system.add(supports[index])
        successes += system.rank == k
    return successes / trials


def experiment_loss(args):
    redundancies = [0.1, 0.25, 0.5, 1.0]
    # HyBolt's default chunk: 65,024 bytes in 6,503-byte symbols, so K = 10.
    k, _ = default_chunk_code()
    trials = 50 if args.quick else 2000
    rng = np.random.default_rng(3)
    results = []
    for redundancy in redundancies:
        repair = max(1, math.ceil(redundancy * k))
        total = k + repair
        for lost in range(total + 1):
            rate = recoverable_after_losses(k, total, rng, trials if lost else 1, lost)
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
    axis.set_xlabel("pacotes perdidos no chunk (%)")
    axis.set_ylabel("chunks recuperados (%)")
    axis.set_xlim(0, 60)
    axis.legend(loc="lower left")
    save_figure(figure, args.figure_dir, "loss_tolerance")
    return results


# ---------------------------------------------------------------------------
# Detection: audits against random corruption, and chunk-targeted attacks
# ---------------------------------------------------------------------------


def corrupt_packets(paths):
    originals = {}
    for path in paths:
        originals[path] = path.read_bytes()
        stored = pickle.loads(originals[path])
        data = bytearray(stored.data)
        data[len(data) // 2] ^= 0xFF
        stored.data = bytes(data)
        path.write_bytes(pickle.dumps(stored))
    return originals


def restore_packets(originals):
    for path, content in originals.items():
        path.write_bytes(content)


def experiment_detection(args):
    size = MIB if args.quick else 4 * MIB
    trials = 5 if args.quick else 100
    fractions = [0.01, 0.05]
    sample_sizes = [1, 2, 5, 10, 20, 50, 100, 200]
    deployment = Deployment(Path(args.work_dir) / "detection")
    input_file = Path(args.work_dir) / "inputs" / f"detection_{size}.bin"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    write_input(input_file, size, seed=4)
    encoded = encode_file(deployment, input_file, COMPACT_SCHEME)
    paths = deployment.packet_paths(0)
    server = deployment.servers[0]["storage_location"]
    rng = random.Random(5)

    empirical = []
    for fraction in fractions:
        corrupted_count = max(1, round(fraction * len(paths)))
        for sample_size in sample_sizes:
            if sample_size > len(paths):
                continue
            detected = 0
            for _ in range(trials):
                originals = corrupt_packets(rng.sample(paths, corrupted_count))
                try:
                    _, report = audit_file(
                        deployment, encoded["metadata_file"], sample_size
                    )
                finally:
                    restore_packets(originals)
                audit = next(item for item in report.servers if item.server == server)
                detected += audit.tau_provider > 0
            empirical.append(
                {
                    "fraction": corrupted_count / len(paths),
                    "sample_size": sample_size,
                    "detection_rate": detected / trials,
                    "server_packets": len(paths),
                }
            )
            print(f"  detection beta={fraction} s={sample_size}: {detected}/{trials}")

    attack = targeted_attack_model(args)
    save_json(args.data_dir, "detection", {"empirical": empirical, "attack": attack})
    plot_detection(empirical, fractions, sample_sizes, args.figure_dir)
    plot_attack(attack, args.figure_dir)


def detection_probability(packets, corrupted, sample_size):
    """P(a sample without replacement hits a corrupted packet): 1 - C(N-c, s) / C(N, s)."""
    return 1 - math.comb(packets - corrupted, sample_size) / math.comb(
        packets, sample_size
    )


def plot_detection(empirical, fractions, sample_sizes, figure_dir):
    figure, axis = plt.subplots()
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
        axis.plot(
            [row["sample_size"] for row in rows],
            [100 * row["detection_rate"] for row in rows],
            linestyle="none",
            marker=MARKERS[slot],
            markersize=6,
            color=COLORS[slot],
            markeredgecolor="white",
            label=rf"auditoria medida, $\beta$ = {100 * beta:.1f}%",
        )
    axis.set_xscale("log")
    axis.set_xlabel("pacotes amostrados por provedor ($s$)")
    axis.set_ylabel("rodadas que detectam corrupção (%)")
    axis.legend(loc="upper left")
    save_figure(figure, figure_dir, "audit_detection")


def chunk_failure_by_hits(k, repair):
    """P(chunk lost | h of its packets corrupted), over every h-subset.

    R10 is not MDS: whether a chunk survives depends on which packets are hit,
    not only on how many, so each of the 2^(K + r) subsets is checked by rank.
    """
    total = k + repair
    supports = [raptor.symbol_support(k, esi) for esi in range(total)]
    failures = [0] * (total + 1)
    counts = [0] * (total + 1)
    for lost_mask in range(1 << total):
        system = raptor.Gf2System(k)
        for index in range(total):
            if not lost_mask >> index & 1:
                system.add(supports[index])
        hits = lost_mask.bit_count()
        counts[hits] += 1
        failures[hits] += system.rank < k
    return [failure / count for failure, count in zip(failures, counts)]


def targeted_attack_model(args):
    """P(file lost) when a fraction of packets is corrupted uniformly at random.

    With sealing the adversary cannot tell chunks apart, so its corruption is
    spread uniformly; without it, the smallest set of one chunk's packets whose
    loss drops the rank below K suffices.
    """

    k, repair = default_chunk_code()
    per_chunk = k + repair
    failure_by_hits = np.asarray(chunk_failure_by_hits(k, repair))
    smallest_attack = int(np.flatnonzero(failure_by_hits > 0)[0])
    chunk_size = POLYNOMIAL_LAMBDA * 512
    files = {"1 MiB": MIB, "64 MiB": 64 * MIB, "1 GiB": 1024 * MIB}
    fractions = np.concatenate(
        [np.geomspace(1e-5, 0.08, 40), np.linspace(0.085, 0.3, 30)]
    )
    trials = 50 if args.quick else 400
    rng = np.random.default_rng(6)
    results = {}
    for label, size in files.items():
        chunks = math.ceil(size / chunk_size)
        total = chunks * per_chunk
        losses = []
        for fraction in fractions:
            corrupted = int(round(fraction * total))
            if corrupted == 0:
                losses.append(0.0)
                continue
            lost = 0
            for _ in range(trials):
                hits = rng.multivariate_hypergeometric([per_chunk] * chunks, corrupted)
                lost += bool((rng.random(chunks) < failure_by_hits[hits]).any())
            losses.append(lost / trials)
        results[label] = {
            "chunks": chunks,
            "packets": total,
            "fractions": fractions.tolist(),
            "random_loss": losses,
            "targeted_packets": smallest_attack,
            "targeted_fraction": smallest_attack / total,
        }
    results["chunk_failure_by_hits"] = failure_by_hits.tolist()
    return results


def plot_attack(attack, figure_dir):
    figure, axis = plt.subplots()
    files = {label: data for label, data in attack.items() if isinstance(data, dict)}
    for slot, (label, data) in enumerate(files.items()):
        axis.plot(
            100 * np.asarray(data["fractions"]),
            100 * np.asarray(data["random_loss"]),
            color=COLORS[slot],
            linestyle=LINESTYLES[slot],
            label=f"{label}, com ocultação",
        )
        axis.axvline(
            100 * data["targeted_fraction"],
            color=COLORS[slot],
            linestyle=":",
            linewidth=1.4,
            label=f"{label}, sem ocultação ({data['targeted_packets']} pacotes)",
        )
    axis.set_xscale("log")
    axis.set_xlabel("pacotes corrompidos pelo adversário (% do arquivo)")
    axis.set_ylabel("probabilidade de perda do arquivo (%)")
    handles, labels = axis.get_legend_handles_labels()
    order = [0, 2, 4, 1, 3, 5]
    axis.legend(
        [handles[index] for index in order],
        [labels[index] for index in order],
        ncol=2,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.18),
    )
    save_figure(figure, figure_dir, "targeted_attack")


# ---------------------------------------------------------------------------
# Hy-SAIL: the file sizes of Hy-SAIL's own experiments
# ---------------------------------------------------------------------------


def experiment_hysail(args):
    sizes_mb = [1, 5] if args.quick else [50, 100, 500]
    deployment = Deployment(Path(args.work_dir) / "hysail")
    inputs_dir = Path(args.work_dir) / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for size_mb in sizes_mb:
        input_file = inputs_dir / f"hysail_{size_mb}mb.bin"
        if not input_file.exists():
            write_input(input_file, size_mb * MB, seed=size_mb)
        for scheme, seal in ((COMPACT_SCHEME, True), ("none", False)):
            print(f"  hysail {size_mb} MB scheme={scheme} seal={seal}")
            encoded = encode_file(deployment, input_file, scheme, seal=seal)
            decode_seconds, output_file = decode_file(
                deployment, encoded["metadata_file"], proof=scheme != "none"
            )
            results.append(
                {
                    "size_mb": size_mb,
                    "scheme": scheme,
                    "sealed": seal,
                    "encode_seconds": encoded["runtime"],
                    "stages": encoded["stages"],
                    "decode_seconds": decode_seconds,
                    "packets": encoded["packets"],
                    "metadata_bytes": encoded["metadata_bytes"],
                    "decoded_ok": output_file.read_bytes() == input_file.read_bytes(),
                    "hysail": HYSAIL_CODEC_SECONDS.get(size_mb),
                }
            )
        input_file.unlink()
    save_json(args.data_dir, "hysail", results)
    plot_hysail(results, args.figure_dir)
    return results


def plot_hysail(results, figure_dir):
    sizes_mb = sorted({record["size_mb"] for record in results})
    figure, axes = plt.subplots(1, 2, figsize=(6.2, 2.8), sharey=True)
    for axis, key, title in (
        (axes[0], "encode", "codificação"),
        (axes[1], "decode", "decodificação"),
    ):
        positions = np.arange(len(sizes_mb))
        bars = [
            (
                "HySAIL (2019), melhor n",
                lambda size: (HYSAIL_CODEC_SECONDS.get(size) or {}).get(key, 0),
            ),
            (
                "HyBolt, só R10",
                lambda size: _hysail_value(results, size, "none", key, codec_only=True),
            ),
            (
                "HyBolt, sem prova",
                lambda size: _hysail_value(results, size, "none", key),
            ),
            (
                "HyBolt, compacto + ocultação",
                lambda size: _hysail_value(results, size, COMPACT_SCHEME, key),
            ),
        ]
        width = 0.8 / len(bars)
        for slot, (label, value) in enumerate(bars):
            values = [value(size) or np.nan for size in sizes_mb]
            axis.bar(
                positions + (slot - (len(bars) - 1) / 2) * width,
                values,
                width=width,
                color=COLORS[(1, 0, 2, 3)[slot]],
                edgecolor="white",
                linewidth=1,
                label=label,
            )
        axis.set_xticks(positions, [f"{size} MB" for size in sizes_mb])
        axis.set_title(title)
        axis.set_yscale("log")
        axis.grid(axis="x", visible=False)
    axes[0].set_ylabel("tempo (s)")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(
        handles, labels, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 0.02)
    )
    save_figure(figure, figure_dir, "hysail_comparison")


def _hysail_value(results, size_mb, scheme, key, codec_only=False):
    for record in results:
        if record["size_mb"] == size_mb and record["scheme"] == scheme:
            if codec_only:
                # Decoding has no separate codec stage to report.
                return record["stages"].get("R10", 0.0) if key == "encode" else 0.0
            return record[f"{key}_seconds"]
    return 0.0


# ---------------------------------------------------------------------------
# Degrees: degree distributions of the three fountain codes
# ---------------------------------------------------------------------------

# RFC 6330, Section 5.3.5.2: degree d is drawn when f[d - 1] <= v < f[d] for a
# uniform v in [0, 2^20).
RAPTORQ_DEGREE_TABLE = (
    0,
    5243,
    529531,
    704294,
    791675,
    844104,
    879057,
    904023,
    922747,
    937311,
    948962,
    958494,
    966438,
    973160,
    978921,
    983914,
    988283,
    992138,
    995565,
    998631,
    1001391,
    1003887,
    1006157,
    1008229,
    1010129,
    1011876,
    1013490,
    1014983,
    1016370,
    1017662,
    1048576,
)


def raptorq_degree_distribution():
    table = np.asarray(RAPTORQ_DEGREE_TABLE, dtype=float)
    return np.diff(table) / table[-1]


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
        r"Online Codes ($\varepsilon$ = 0,01)": online_degree_distribution(0.01),
        "Raptor R10 (RFC 5053)": r10_degree_distribution(),
        "RaptorQ (RFC 6330)": raptorq_degree_distribution(),
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
    plot_attack(detection["attack"], args.figure_dir)
    plot_hysail(json.loads((data_dir / "hysail.json").read_text()), args.figure_dir)
    plot_overhead(json.loads((data_dir / "overhead.json").read_text()), args.figure_dir)


EXPERIMENTS = {
    "degrees": experiment_degrees,
    "mac": experiment_mac,
    "overhead": experiment_overhead,
    "loss": experiment_loss,
    "pipeline": experiment_pipeline,
    "detection": experiment_detection,
    "hysail": experiment_hysail,
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
