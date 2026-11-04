#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTICLE_DIR="${SCRIPT_DIR}/../doc/article"
ARTICLE_NAME="${1:-main-pt}"
ARTICLE_NAME="${ARTICLE_NAME%.tex}"
ARTICLE_TEX="${ARTICLE_NAME}.tex"
LATEX_FLAGS=("-interaction=nonstopmode" "-halt-on-error" "-file-line-error")

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Error: required command not found: ${command_name}" >&2
        exit 1
    fi
}

# The sbc2025 class refuses pdflatex, so prefer lualatex and fall back to xelatex.
select_engine() {
    local engine

    for engine in lualatex xelatex; do
        if command -v "${engine}" >/dev/null 2>&1; then
            echo "${engine}"
            return
        fi
    done

    echo "Error: lualatex or xelatex is required to build the article" >&2
    exit 1
}

run_latex() {
    local log_file="$1"

    if ! "${LATEX_ENGINE}" "${LATEX_FLAGS[@]}" "${ARTICLE_TEX}" >"${log_file}" 2>&1; then
        cat "${log_file}" >&2
        echo "Article compilation failed. See ${ARTICLE_DIR}/${log_file} for details." >&2
        exit 1
    fi
}

LATEX_ENGINE="$(select_engine)"
require_command bibtex

cd "${ARTICLE_DIR}"

if [[ ! -f "${ARTICLE_TEX}" ]]; then
    echo "Error: article source not found: ${ARTICLE_DIR}/${ARTICLE_TEX}" >&2
    exit 1
fi

rm -f "${ARTICLE_NAME}".{aux,bbl,blg,log,out} "${ARTICLE_NAME}".latex.{1,2,3}.log

run_latex "${ARTICLE_NAME}.latex.1.log"

if grep -Fq '\citation{' "${ARTICLE_NAME}.aux"; then
    bibtex "${ARTICLE_NAME}"
fi

run_latex "${ARTICLE_NAME}.latex.2.log"
run_latex "${ARTICLE_NAME}.latex.3.log"

echo "Article PDF generated: ${ARTICLE_DIR}/${ARTICLE_NAME}.pdf"
