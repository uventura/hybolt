#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THESIS_DIR="${SCRIPT_DIR}/../doc/thesis"
THESIS_NAME="monografia"
THESIS_TEX="${THESIS_NAME}.tex"
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

    if ! pdflatex "${LATEX_FLAGS[@]}" "${THESIS_TEX}" >"${log_file}" 2>&1; then
        cat "${log_file}" >&2
        echo "Thesis compilation failed. See ${THESIS_DIR}/${log_file} for details." >&2
        exit 1
    fi
}

require_command pdflatex
require_command bibtex
require_command makeglossaries

cd "${THESIS_DIR}"

rm -f "${THESIS_NAME}".{acn,acr,alg,aux,bbl,blg,glg,glo,gls,glsdefs,ist,lof,log,out,toc} \
    "${THESIS_NAME}".pdflatex.{1,2,3}.log

run_pdflatex "${THESIS_NAME}.pdflatex.1.log"

if grep -Fq '\citation{' "${THESIS_NAME}.aux"; then
    bibtex "${THESIS_NAME}"
fi

makeglossaries "${THESIS_NAME}"
run_pdflatex "${THESIS_NAME}.pdflatex.2.log"
run_pdflatex "${THESIS_NAME}.pdflatex.3.log"

echo "Thesis PDF generated: ${THESIS_DIR}/${THESIS_NAME}.pdf"