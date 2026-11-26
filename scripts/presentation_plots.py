#!/usr/bin/env python3
"""Redraw the thesis result plots used by doc/presentation with slide wording.

The slides call each stored encoding symbol a "bloco", while the thesis calls
it a "pacote". This script redraws, from the data saved by
``scripts/thesis_benchmarks.py`` (``logs/thesis/*.json``), the plots whose
labels carry that word, writing them to ``doc/presentation/figuras/resultados``.
Nothing is measured again, and the thesis figures are left untouched.

    python scripts/presentation_plots.py
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import thesis_benchmarks as tb  # noqa: E402

# Same sample sizes and corruption fractions as thesis_benchmarks.replot_saved.
DETECTION_FRACTIONS = [0.01, 0.05]
DETECTION_SAMPLE_SIZES = [1, 2, 5, 10, 20, 50, 100, 200]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, default=ROOT / "logs" / "thesis")
    parser.add_argument(
        "--figure-dir",
        type=Path,
        default=ROOT / "doc" / "presentation" / "figuras" / "resultados",
    )
    args = parser.parse_args()

    def load(name):
        return json.loads((args.data_dir / f"{name}.json").read_text())

    tb.configure_style()
    tb.PACKETS_LABEL = "blocos"

    tb.plot_loss(load("loss"), args.figure_dir)
    tb.plot_detection(
        load("detection")["empirical"],
        DETECTION_FRACTIONS,
        DETECTION_SAMPLE_SIZES,
        args.figure_dir,
    )
    # Also writes codec_comparison.pdf, which the slides do not use.
    tb.plot_codecs(load("codecs"), args.figure_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
