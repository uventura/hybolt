#!/usr/bin/env bash
# Builds doc/presentation/apresentacao.pdf.
#
# Usage: scripts/build_presentation.sh [--figures]
#   --figures  also regenerates the article figures reused by the slides
#              (scripts/presentation_figures.py) before compiling.
#
# On Windows, run it inside WSL: wsl bash scripts/build_presentation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRESENTATION_DIR="${SCRIPT_DIR}/../doc/presentation"
PRESENTATION_NAME="apresentacao"
PRESENTATION_TEX="${PRESENTATION_NAME}.tex"
LATEX_FLAGS=("-interaction=nonstopmode" "-halt-on-error" "-file-line-error")

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Error: required command not found: ${command_name}" >&2
        exit 1
    fi
}

run_pdflatex() {
    local log_file="$1"

    if ! pdflatex "${LATEX_FLAGS[@]}" "${PRESENTATION_TEX}" >"${log_file}" 2>&1; then
        cat "${log_file}" >&2
        echo "Presentation compilation failed. See ${PRESENTATION_DIR}/${log_file} for details." >&2
        exit 1
    fi
}

# Overfull boxes mean content spilling past the slide borders. The metropolis
# title page always reports an overfull \vbox, even in an empty document, so
# the warning at the \maketitle line is skipped.
check_overfull() {
    local log_file="$1"
    local title_line
    local overfull

    title_line="$(grep -n '^\\maketitle' "${PRESENTATION_TEX}" | cut -d: -f1)"
    overfull="$(grep -A1 '^Overfull' "${log_file}" | grep -v "detected at line ${title_line}\$" || true)"

    if grep -q '^Overfull' <<<"${overfull}"; then
        echo "Warning: overfull boxes in ${PRESENTATION_DIR}/${log_file}:" >&2
        echo "${overfull}" >&2
    fi
}

if [[ "${1:-}" == "--figures" ]]; then
    require_command python3
    python3 "${SCRIPT_DIR}/presentation_figures.py"
fi

require_command pdflatex

cd "${PRESENTATION_DIR}"

rm -f "${PRESENTATION_NAME}".{aux,log,nav,out,snm,toc,vrb} \
    "${PRESENTATION_NAME}".pdflatex.{1,2}.log

# Two passes: the first writes the table of contents and the slide count.
run_pdflatex "${PRESENTATION_NAME}.pdflatex.1.log"
run_pdflatex "${PRESENTATION_NAME}.pdflatex.2.log"
check_overfull "${PRESENTATION_NAME}.pdflatex.2.log"

echo "Presentation PDF generated: ${PRESENTATION_DIR}/${PRESENTATION_NAME}.pdf"
