#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/migration_report"
ARCHIVE_NAME="${OUTPUT_DIR}.tar.gz"

"${SCRIPT_DIR}/collect.sh"

if [[ -f "$ARCHIVE_NAME" ]]; then
  tar -xzf "$ARCHIVE_NAME" -C "$(dirname "$OUTPUT_DIR")"
fi

"${SCRIPT_DIR}/generate_report.py" "$OUTPUT_DIR"
