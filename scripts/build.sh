#!/usr/bin/env bash
# Build ZipSentinel on Linux or macOS.
# Usage: ./scripts/build.sh [--debug] [--test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OS="$(uname -s)"
echo "==> Repo root: $ROOT"
echo "==> OS: $OS"

command -v cargo >/dev/null 2>&1 || {
    echo "error: cargo not found. Install Rust via https://rustup.rs and re-run." >&2
    exit 1
}
cargo --version
rustc --version

MODE="--release"
RUN_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --debug) MODE="" ;;
        --test)  RUN_TESTS=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if [ -n "$MODE" ]; then
    echo "==> cargo build --release -p zipsentinel-cli"
    cargo build --release -p zipsentinel-cli
    EXE="$ROOT/target/release/zipsentinel"
else
    echo "==> cargo build -p zipsentinel-cli"
    cargo build -p zipsentinel-cli
    EXE="$ROOT/target/debug/zipsentinel"
fi

[ -x "$EXE" ] || { echo "error: $EXE not produced" >&2; exit 1; }

echo "==> Verifying binary"
"$EXE" --version
"$EXE" --help | head -12

if [ "$RUN_TESTS" -eq 1 ]; then
    echo "==> cargo test --workspace"
    cargo test --workspace
fi

echo
echo "Done. Binary: $EXE"
echo "Run it directly or symlink into PATH, e.g.:"
echo "  sudo ln -sf \"$EXE\" /usr/local/bin/zipsentinel"
