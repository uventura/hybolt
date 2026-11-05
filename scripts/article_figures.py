"""Redraw the SBC article figure at single-column width from saved thesis data.

Reads the JSON written by ``scripts/thesis_benchmarks.py`` (``logs/thesis``)
and writes ``codec_loss`` to ``doc/article/figures``, comparing Raptor R10
and Online Codes.
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

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
    plot_codec_loss(load(args.data_dir, "codecs")["loss"], args.figure_dir)


if __name__ == "__main__":
    main()
