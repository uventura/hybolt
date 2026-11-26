"""Draw the figures used in the article presentation.

``commercial_data_volumes`` (slide 2) shows data volumes of commercial services;
``codes_comparison_table`` (slide 4) compares Online Codes and Raptor R10.


Data volumes come from Clissa, Lassnig and Rinaldi (2023), "How big is Big Data?",
Frontiers in Big Data 6:1271639, the survey the article cites as
``frontiersbigdata``; the table follows Table 1 and the results of the article.
Writes PDF and PNG versions of both to ``doc/article/figures``.

The figure uses its own slide theme (white surface, tonal blues, Inter,
lollipop marks), not
the article's plotting style.
"""

import argparse
from functools import partial
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.ticker import FixedLocator, NullLocator  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

SURFACE = "#ffffff"
TEXT_PRIMARY = "#0f1b2d"
TEXT_SECONDARY = "#5b6b80"
GRID = "#dfe5ee"
# Tonal steps of one blue, dark to light; validated as an ordinal scale
# (monotone lightness, >= 3:1 contrast) against SURFACE. Groups are also
# named by their headers, so color is never the only cue.
BLUE_DEEP, BLUE_MID, BLUE_LIGHT = "#0b2e6b", "#1f5fc4", "#4a8fe6"

# (group header, color, rows). Each measure is its own group, so stored,
# transferred and new data are never read as the same quantity.
# Volumes in PB; 1 EB = 1e3 PB.
GROUPS = (
    ("ARMAZENADO (ACUMULADO)", BLUE_DEEP, (("Amazon S3, até 2021", 500e3),)),
    (
        "TRÁFEGO POR ANO",
        BLUE_MID,
        (("Netflix, streaming (2021)", 51.1e3), ("E-mails e spam (2021)", 5.7e3)),
    ),
    (
        "NOVOS DADOS POR ANO",
        BLUE_LIGHT,
        (
            ("Dropbox, novos usuários (2020)", 768),
            ("YouTube, vídeos enviados", 263),
            ("Facebook, fotos", 252),
            ("Instagram, fotos", 68),
        ),
    ),
)
BASELINE = 10  # PB; the log axis needs a positive origin for the stems.


def pick_font():
    for path in Path("/usr/share/fonts").glob("**/Inter-*.otf"):
        font_manager.fontManager.addfont(str(path))
    available = {font.name for font in font_manager.fontManager.ttflist}
    for family in ("Inter", "Clear Sans", "DejaVu Sans"):
        if family in available:
            return family
    return "sans-serif"


def configure_slide_style():
    plt.rcParams.update(
        {
            "font.family": pick_font(),
            "font.size": 12,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "axes.edgecolor": GRID,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "axes.spines.bottom": False,
            "axes.axisbelow": True,
            "xtick.color": TEXT_SECONDARY,
            "xtick.labelsize": 11,
            "xtick.major.size": 0,
            "ytick.major.size": 0,
            "mathtext.fontset": "custom",
            "mathtext.rm": "Inter",
            "mathtext.it": "Inter",
            "mathtext.bf": "Inter:bold",
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.25,
        }
    )


def human_volume(pb):
    if pb >= 1e3:
        return f"{pb / 1e3:g} EB".replace(".", ",")
    return f"{pb:g} PB"


def save(figure, figure_dir, name):
    figure_dir.mkdir(parents=True, exist_ok=True)
    for suffix, options in ((".pdf", {}), (".png", {"dpi": 220})):
        path = figure_dir / f"{name}{suffix}"
        figure.savefig(path, **options)
        print(f"  figure written to {path}")
    plt.close(figure)


def layout_rows():
    """Yield (y, kind, payload) top to bottom, leaving room for each header."""
    y = 0.0
    for header, color, rows in GROUPS:
        yield y, "header", (header, color)
        y -= 0.75
        for label, value in rows:
            yield y, "row", (label, value, color)
            y -= 0.85
        y -= 0.35


def plot_commercial_volumes(figure_dir):
    items = list(layout_rows())
    figure, axis = plt.subplots(figsize=(8.6, 5.2))
    row_labels = []

    for y, kind, payload in items:
        if kind == "header":
            header, color = payload
            axis.text(
                BASELINE, y, header,
                color=color, fontsize=10.5, fontweight="bold", va="center", ha="left",
            )
            continue
        label, value, color = payload
        axis.hlines(y, BASELINE, value, color=color, linewidth=3, alpha=0.3, capstyle="round")
        axis.scatter(value, y, s=260, color=color, edgecolor=SURFACE, linewidth=2.5, zorder=3)
        row_labels.append(axis.text(
            BASELINE / 1.25, y, label,
            color=TEXT_PRIMARY, fontsize=12.5, va="center", ha="right",
        ))
        axis.text(
            value * 1.55, y, human_volume(value),
            color=TEXT_PRIMARY, fontsize=13, fontweight="bold", va="center", ha="left",
        )

    axis.set_xscale("log")
    axis.set_xlim(BASELINE, 4e6)
    ys = [y for y, _, _ in items]
    axis.set_ylim(min(ys) - 0.6, max(ys) + 0.5)
    axis.set_yticks([])
    ticks = [1e2, 1e3, 1e4, 1e5, 1e6]
    axis.xaxis.set_major_locator(FixedLocator(ticks))
    axis.xaxis.set_minor_locator(NullLocator())
    axis.set_xticklabels(["100 PB", "1 EB", "10 EB", "100 EB", "1.000 EB"])
    axis.grid(axis="x", color=GRID, linewidth=1, linestyle=(0, (2, 3)))
    axis.text(
        1.0, -0.1, "escala logarítmica: cada linha vertical = 10x",
        transform=axis.transAxes, ha="right", va="top", color=TEXT_SECONDARY, fontsize=10,
    )
    # Align the title and the source with the left edge of the row labels.
    renderer = figure.canvas.get_renderer()
    left = min(text.get_window_extent(renderer).x0 for text in row_labels)
    left = figure.transFigure.inverted().transform((left, 0))[0]
    figure.suptitle(
        "Quanto dado os serviços do dia a dia guardam e movimentam",
        x=left, ha="left", fontsize=16, fontweight="bold", color=TEXT_PRIMARY,
    )
    figure.text(
        left, -0.02, "Fonte: Clissa, Lassnig e Rinaldi (2023), Frontiers in Big Data.",
        ha="left", color=TEXT_SECONDARY, fontsize=9.5,
    )
    save(figure, figure_dir, "commercial_data_volumes")


# (section header, rows); each row is (aspect, online codes, raptor r10), and a
# cell may hold a second, secondary line after "\n".
COMPARISON = (
    (
        "ESTRUTURA",
        (
            ("Sistemático", "não", "sim"),
            ("Decodificação", "peeling", "eliminação gaussiana"),
            ("Padronização", "não", "RFC 5053"),
        ),
    ),
    (
        "OVERHEAD DE RECEPÇÃO",
        (
            ("Overhead esperado", "≈ 3·" + r"$\varepsilon_o$" + "·K\ncresce com K: O(K)",
             "constante c\nnão depende de K: O(1)"),
            ("Blocos para recuperar", "≈ (1 + 3" + r"$\varepsilon_o$" + ")·K", "K + c, com c ≈ 2"),
        ),
    ),
    (
        "COMPLEXIDADE (POR CHUNK, EM XORs)",
        (
            ("Codificação", "O(K·T)", "≈ O(K·T) na prática\nO(K²·T) no pior caso"),
            ("Decodificação", "O(K·T)", "≈ O(K·T) na prática\nO(K²·T) no pior caso"),
            ("Medido, K = 100", "2,6 ms / 3,2 ms\ncodificação / decodificação",
             "2,8 ms / 3,5 ms\ncodificação / decodificação"),
        ),
    ),
)
R10_TINT = "#eef4fd"


def draw_table(sections, footnote, figure_dir, name, columns=(0.0, 3.3, 6.9), width=10.6):
    """Online Codes x Raptor R10 table in the slide theme, R10 column tinted.

    ``columns`` holds the left edge of each column, in data units.
    """
    single, double, section_gap = 0.62, 0.95, 0.75

    rows = []  # (y_top, height, kind, payload)
    y = 0.0
    header_height = 0.8
    rows.append((y, header_height, "header", None))
    y -= header_height
    for title, entries in sections:
        rows.append((y, section_gap, "section", title))
        y -= section_gap
        for entry in entries:
            height = double if any("\n" in cell for cell in entry) else single
            rows.append((y, height, "row", entry))
            y -= height
    bottom = y

    figure, axis = plt.subplots(figsize=(9.2 * width / 10.6, 0.62 * -bottom + 0.4))
    axis.set_xlim(0, width)
    axis.set_ylim(bottom - 0.05, 0.05)
    axis.axis("off")

    # Tint the R10 column from below the header to the bottom.
    axis.add_patch(plt.Rectangle(
        (columns[2] - 0.15, bottom), width - columns[2] + 0.15, -bottom - header_height,
        color=R10_TINT, zorder=0, linewidth=0,
    ))
    pad = 0.15
    for top, height, kind, payload in rows:
        middle = top - height / 2
        if kind == "header":
            axis.add_patch(plt.Rectangle((0, top - height), width, height, color=BLUE_DEEP, linewidth=0))
            for x, text in zip(columns, ("", "Online Codes", "Raptor R10")):
                axis.text(x + pad, middle, text, color="white", fontsize=14,
                          fontweight="bold", va="center")
            continue
        if kind == "section":
            axis.text(pad, top - height + 0.2, payload, color=BLUE_MID, fontsize=10.5,
                      fontweight="bold", va="bottom")
            continue
        axis.plot([0, width], [top - height, top - height], color=GRID, linewidth=1)
        aspect, online, r10 = payload
        axis.text(pad, middle, aspect, color=TEXT_PRIMARY, fontsize=12.5, va="center")
        for x, cell, strong in ((columns[1], online, False), (columns[2], r10, True)):
            main, _, note = cell.partition("\n")
            offset = 0.17 if note else 0
            axis.text(x + pad, middle + offset, main, color=TEXT_PRIMARY, fontsize=13,
                      fontweight="bold" if strong else "normal", va="center")
            if note:
                axis.text(x + pad, middle - 0.2, note, color=TEXT_SECONDARY,
                          fontsize=10.5, va="center")

    axis.text(0, bottom - 0.3, footnote, color=TEXT_SECONDARY, fontsize=9.5, va="top")
    save(figure, figure_dir, name)


def plot_comparison_table(figure_dir):
    draw_table(
        COMPARISON,
        "K = blocos de origem por chunk; T = bytes por bloco (6.500); "
        r"$\varepsilon_o$ = parâmetro de projeto dos Online Codes.",
        figure_dir,
        "codes_comparison_table",
    )


# Slide 8: performance, from Table 2 of the article.
PERFORMANCE = (
    (
        "CÓDIGO FOUNTAIN (UM CHUNK)",
        (
            ("Codificação", "2,6 ms", "2,8 ms"),
            ("Decodificação", "3,2 ms", "3,5 ms"),
        ),
    ),
    (
        "FLUXO COMPLETO (ARQUIVO DE 500 MB)",
        (
            ("Codificação", "28,1 s", "24,0 s"),
            ("Decodificação", "13,1 s", "9,8 s"),
        ),
    ),
    (
        "BLOCOS",
        (
            ("Armazenados por chunk", "143", "125"),
            ("Lidos na decodificação, média", "136,3", "101,5"),
            ("Armazenamento / arquivo", "1,45x", "1,27x"),
        ),
    ),
)


def plot_performance_table(figure_dir):
    draw_table(
        PERFORMANCE,
        "Chunks de K = 100 blocos, redundância ε = 0,25, sem os MACs.\n"
        "Intel Core i7-11390H, provedores simulados em disco local.",
        figure_dir,
        "performance_table",
        columns=(0.0, 4.0, 7.3),
        width=10.6,
    )


# Slide 6: local repair of a K = 4 chunk, the example of the article.
# (name, content, role); role is "kept", "corrupted" or "used".
XOR = r"$\oplus$"
REPAIR_BLOCKS = (
    ("c₀", "d₁", "kept"),
    ("c₁", "d₂", "corrupted"),
    ("c₂", "d₃", "used"),
    ("c₃", "d₄", "used"),
    ("c₄", f"d₁ {XOR} d₂ {XOR} d₄", "kept"),
    ("c₅", f"d₂ {XOR} d₃", "used"),
)
REPAIR_STEPS = (
    ("Auditoria detecta", "c₁ corrompido"),
    ("Metadados: x₆ = {2, 4}", f"x₆ = x₅ {XOR} x₂ {XOR} x₃"),
    ("Transfere só 3 blocos", f"c₆ = c₅ {XOR} c₂ {XOR} c₃"),
)
CORRUPTED_FILL = "#eef1f5"


def rounded_box(axis, x, y, width, height, face, edge, **kwargs):
    from matplotlib.patches import FancyBboxPatch

    axis.add_patch(FancyBboxPatch(
        (x, y), width, height, boxstyle="round,pad=0,rounding_size=0.12",
        facecolor=face, edgecolor=edge, linewidth=1.6, **kwargs,
    ))


def plot_local_repair(figure_dir):
    figure, axis = plt.subplots(figsize=(11.0, 6.4))
    axis.set_xlim(0, 12)
    axis.set_ylim(0, 7)
    axis.set_aspect("equal")
    axis.axis("off")
    # Inter's own circled plus is oversized; draw the XOR sign from DejaVu.
    text = partial(axis.text, math_fontfamily="dejavusans")

    width, height, gap, top = 1.75, 1.15, 0.2, 5.0
    left = (12 - (len(REPAIR_BLOCKS) * width + (len(REPAIR_BLOCKS) - 1) * gap)) / 2
    text(left, top + height + 0.35, "BLOCOS ARMAZENADOS DO CHUNK (K = 4)",
              color=BLUE_MID, fontsize=11, fontweight="bold", va="bottom")

    xor_center = (6.0, 2.85)
    used_bottoms = []
    for index, (name, content, role) in enumerate(REPAIR_BLOCKS):
        x = left + index * (width + gap)
        if role == "used":
            face, edge, ink, note = BLUE_MID, BLUE_MID, "white", None
        elif role == "corrupted":
            face, edge, ink, note = CORRUPTED_FILL, TEXT_SECONDARY, TEXT_SECONDARY, "× corrompido"
        else:
            face, edge, ink, note = SURFACE, GRID, TEXT_PRIMARY, None
        rounded_box(axis, x, top, width, height, face, edge,
                    linestyle="--" if role == "corrupted" else "-")
        text(x + width / 2, top + height * 0.66, name, color=ink, fontsize=15,
                  fontweight="bold", ha="center", va="center")
        text(x + width / 2, top + height * 0.28, content, color=ink, fontsize=11.5,
                  ha="center", va="center")
        if note:
            text(x + width / 2, top - 0.22, note, color=TEXT_SECONDARY, fontsize=11,
                      fontweight="bold", ha="center", va="top")
        if role == "used":
            used_bottoms.append((x + width / 2, top))

    for x, y in used_bottoms:
        axis.annotate("", xy=xor_center, xytext=(x, y - 0.05), arrowprops={
            "arrowstyle": "-|>", "color": BLUE_MID, "lw": 2,
            "shrinkA": 0, "shrinkB": 22, "mutation_scale": 16,
        })
    axis.add_patch(plt.Circle(xor_center, 0.36, facecolor=SURFACE, edgecolor=BLUE_DEEP,
                              linewidth=2, zorder=3))
    text(xor_center[0], xor_center[1], "+", color=BLUE_DEEP, fontsize=26,
              fontweight="bold", ha="center", va="center", zorder=4)
    text(xor_center[0] - 0.55, xor_center[1], "XOR", color=TEXT_SECONDARY, fontsize=11,
              ha="right", va="center")

    new_x, new_width = 8.6, 2.3
    rounded_box(axis, new_x, xor_center[1] - height / 2, new_width, height, BLUE_DEEP, BLUE_DEEP)
    text(new_x + new_width / 2, xor_center[1] + 0.2, "c₆", color="white", fontsize=15,
              fontweight="bold", ha="center", va="center")
    text(new_x + new_width / 2, xor_center[1] - 0.22, f"d₂ {XOR} d₄", color="white",
              fontsize=11.5, ha="center", va="center")
    text(new_x + new_width / 2, xor_center[1] - height / 2 - 0.15,
              "novo bloco de reparo\nenviado a outro provedor", color=TEXT_SECONDARY,
              fontsize=10.5, ha="center", va="top")
    axis.annotate("", xy=(new_x, xor_center[1]), xytext=xor_center, arrowprops={
        "arrowstyle": "-|>", "color": BLUE_DEEP, "lw": 2,
        "shrinkA": 24, "shrinkB": 4, "mutation_scale": 16,
    })

    card_width, card_gap, card_y, card_height = 3.6, 0.3, 0.25, 1.05
    card_left = (12 - (3 * card_width + 2 * card_gap)) / 2
    for index, (title, detail) in enumerate(REPAIR_STEPS):
        x = card_left + index * (card_width + card_gap)
        rounded_box(axis, x, card_y, card_width, card_height, "#eef4fd", "#eef4fd")
        axis.add_patch(plt.Circle((x + 0.42, card_y + card_height / 2), 0.25,
                                  facecolor=BLUE_DEEP, edgecolor="none"))
        text(x + 0.42, card_y + card_height / 2, str(index + 1), color="white",
                  fontsize=12, fontweight="bold", ha="center", va="center")
        text(x + 0.85, card_y + card_height * 0.68, title, color=TEXT_SECONDARY,
                  fontsize=10.5, va="center")
        text(x + 0.85, card_y + card_height * 0.32, detail, color=TEXT_PRIMARY,
                  fontsize=12, fontweight="bold", va="center")

    text(
        6.0, -0.2,
        "Sem decodificar o chunk e sem usar o bloco corrompido. "
        "Com K = 100, cada reparo transfere em média ~49 blocos (~320 KB).",
        color=TEXT_SECONDARY, fontsize=10.5, ha="center", va="top",
    )
    save(figure, figure_dir, "local_repair")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--figure-dir", type=Path, default=ROOT / "doc" / "article" / "figures")
    args = parser.parse_args()
    configure_slide_style()
    plot_commercial_volumes(args.figure_dir)
    plot_comparison_table(args.figure_dir)
    plot_performance_table(args.figure_dir)
    plot_local_repair(args.figure_dir)


if __name__ == "__main__":
    main()
