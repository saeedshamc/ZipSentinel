#!/usr/bin/env bash
# End-to-end smoke example: generate samples, scan, extract.
set -euo pipefail

BIN="${ZIPSENTINEL:-zipsentinel}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$BIN" generate --profile high-compression --size 1MB --output "$WORK/bomb.zip"
"$BIN" scan "$WORK/bomb.zip" || true   # expect HIGH RISK (exit 2)

"$BIN" generate --profile standard --output "$WORK/standard.zip"
"$BIN" analyze "$WORK/standard.zip"
"$BIN" extract "$WORK/standard.zip" --output "$WORK/out"
"$BIN" benchmark "$WORK"
