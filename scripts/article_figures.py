"""Redraw the SBC article figures at single-column width from saved thesis data.

Reads the JSON written by ``scripts/thesis_benchmarks.py`` (``logs/thesis``)
and writes ``reception_overhead``, ``codec_loss`` and ``targeted_attack`` to
``doc/article/figures``, comparing only Raptor R10 and Online Codes.
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from thesis_benchmarks import COLORS, LINESTYLES, configure_style, save_figure  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
COLUMN_WIDTH = 3.4
CODES = (("r10", "Raptor R10"), ("online", "Online Codes"))


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


def plot_codec_loss(rows, figure_dir):
    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 1.9), layout="constrained")
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
    axis.set_xlabel("pacotes perdidos no chunk (%)")
    axis.set_ylabel("chunks recuperados (%)")
    axis.set_xlim(0, 40)
    figure.legend(ncol=2, loc="outside lower center")
    save_figure(figure, figure_dir, "codec_loss")


def plot_attack(attack, figure_dir):
    figure, axis = plt.subplots(figsize=(COLUMN_WIDTH, 2.0), layout="constrained")
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
            linewidth=1.1,
            label=f"{label}, sem ocultação",
        )
    axis.set_xscale("log")
    axis.set_xlabel("pacotes corrompidos (% do arquivo)")
    axis.set_ylabel("perda do arquivo (%)")
    handles, labels = axis.get_legend_handles_labels()
    order = [0, 2, 4, 1, 3, 5]
    figure.legend(
        [handles[i] for i in order],
        [labels[i] for i in order],
        ncol=2,
        loc="outside lower center",
    )
    save_figure(figure, figure_dir, "targeted_attack")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", default=ROOT / "logs" / "thesis")
    parser.add_argument("--figure-dir", default=ROOT / "doc" / "article" / "figures")
    args = parser.parse_args()

    configure_column_style()
    plot_overhead(load(args.data_dir, "overhead"), args.figure_dir)
    plot_codec_loss(load(args.data_dir, "codecs")["loss"], args.figure_dir)
    plot_attack(load(args.data_dir, "detection")["attack"], args.figure_dir)


if __name__ == "__main__":
    main()
