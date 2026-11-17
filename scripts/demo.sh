#!/usr/bin/env bash
# Smoke-test zipsentinel on Linux/macOS: generate -> scan -> extract -> benchmark.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="$ROOT/target/release/zipsentinel"
[ -x "$EXE" ] || EXE="$ROOT/target/debug/zipsentinel"
[ -x "$EXE" ] || { echo "error: binary not found — run scripts/build.sh first" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> generate high-compression sample"
"$EXE" generate --profile high-compression --size 512KiB --output "$WORK/bomb.zip"

echo "==> scan (expect HIGH RISK, exit code 2)"
"$EXE" scan "$WORK/bomb.zip" && rc=0 || rc=$?
echo "scan exit code: $rc"

echo "==> generate + extract standard sample"
"$EXE" generate --profile standard --entries 4 --output "$WORK/standard.zip"
"$EXE" extract "$WORK/standard.zip" --output "$WORK/out"

echo "==> benchmark"
"$EXE" benchmark "$WORK"

echo "Demo complete."
