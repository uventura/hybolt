"""Redraw the SBC article figures at single-column width from saved thesis data.

Reads the JSON written by ``scripts/thesis_benchmarks.py`` (``logs/thesis``)
and writes ``reception_overhead``, ``codec_loss`` and ``codec_times`` to
``doc/article/figures``, comparing Raptor R10 and Online Codes.
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from thesis_benchmarks import CATEGORICAL_COLORS as COLORS, LINESTYLES, configure_style, save_figure  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
COLUMN_WIDTH = 3.4
CODES = (("r10", "Raptor R10"), ("online", "Online Codes"))
# (label, timing field suffix): the code alone, and the whole flow without the proof.
TIMING_CONFIGS = (("código", "_codec_seconds"), ("fluxo", "_seconds"))


def load(data_dir, name):
    return json.loads((Path(data_dir) / f"{name}.json").read_text())


def decimal(value):
    return f"{value:g}".replace(".", ",")


def configure_column_style():
    configure_style()
    plt.rcParams.update(
        {
            "font.size": 7.5,
            "axes.titlesize": 7.5,
            "axes.labelsize": 7.5,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "legend.fontsize": 7,
            "lines.linewidth": 1.4,
        }
    )


def plot_overhead(results, figure_dir):
    ks = sorted(int(k) for k in results)
    figure, axes = plt.subplots(
        1, len(ks), figsize=(COLUMN_WIDTH, 1.65), sharey=True, layout="constrained"
    )
    for axis, k in zip(axes, ks):
        limit = 3.0 if k < 100 else 1.6
        ratios = np.linspace(0.9, limit, 400)
        needed = results[str(k)]["needed"]
        for slot, (code, label) in enumerate(CODES):
            values = np.asarray([np.inf if v is None else v for v in needed[code]])
            success = [100 * np.mean(values <= ratio * k) for ratio in ratios]
            axis.step(
                ratios,
                success,
                where="post",
                label=label,
                color=COLORS[slot],
                linestyle=LINESTYLES[slot],
            )
        axis.set_title(f"K = {k}")
    axes[0].set_ylabel("decodificações (%)")
    axes[len(axes) // 2].set_xlabel("símbolos recebidos / K")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, ncol=2, loc="outside lower center")
    save_figure(figure, figure_dir, "reception_overhead")


def plot_codec_times(timings, figure_dir):
    timings = [record for record in timings if record["scheme"] == "none"]
    sizes = sorted({record["size_mb"] for record in timings})
    figure, axes = plt.subplots(
        1, 2, figsize=(COLUMN_WIDTH, 1.9), sharey=True, layout="constrained"
    )
    for axis, key, title in (
        (axes[0], "encode", "codificação"),
        (axes[1], "decode", "decodificação"),
    ):
        for codec_slot, (codec, codec_label) in enumerate(CODES):
            by_size = {r["size_mb"]: r for r in timings if r["codec"] == codec}
            for config_slot, (config_label, suffix) in enumerate(TIMING_CONFIGS):
                axis.plot(
                    sizes,
                    [by_size[size][f"{key}{suffix}"] for size in sizes],
                    color=COLORS[codec_slot],
                    linestyle=LINESTYLES[config_slot],
                    marker="o",
                    markersize=3,
                    label=f"{codec_label}, {config_label}",
                )
        axis.set_xscale("log")
        axis.set_yscale("log")
        axis.set_xticks(sizes, [str(size) for size in sizes])
        axis.minorticks_off()
        axis.set_title(title)
        axis.set_xlabel("arquivo (MB)")
    axes[0].set_ylabel("tempo (s)")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(handles, labels, ncol=2, loc="outside lower center")
    save_figure(figure, figure_dir, "codec_times")


def plot_codec_loss(rows, figure_dir):
    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 1.75), layout="constrained")
    labels = dict(CODES)
    for row in rows:
        codec_slot = [code for code, _ in CODES].index(row["codec"])
        style_slot = 0 if row["redundancy"] == 0.25 else 1
        total = row["total"]
        axis.plot(
            [100 * lost / total for lost in range(total + 1)],
            [100 * rate for rate in row["success_rate"]],
            color=COLORS[codec_slot],
            linestyle=LINESTYLES[style_slot],
            label=(
                f"{labels[row['codec']]}, "
                rf"$\varepsilon$ = {decimal(row['redundancy'])} ({total})"
            ),
        )
    axis.set_xlabel("blocos perdidos no chunk (%)")
    axis.set_ylabel("recuperados (%)")
    axis.set_xlim(0, 40)
    figure.legend(ncol=2, loc="outside lower center")
    save_figure(figure, figure_dir, "codec_loss")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", default=ROOT / "logs" / "thesis")
    parser.add_argument("--figure-dir", default=ROOT / "doc" / "article" / "figures")
    args = parser.parse_args()

    configure_column_style()
    plot_overhead(load(args.data_dir, "overhead"), args.figure_dir)
    codecs = load(args.data_dir, "codecs")
    plot_codec_loss(codecs["loss"], args.figure_dir)
    plot_codec_times(codecs["timings"], args.figure_dir)


if __name__ == "__main__":
    main()
