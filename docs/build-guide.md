# Build & Run Guide

ZipSentinel is a pure-Rust workspace — the only prerequisite is a Rust
toolchain. Everything below works on Windows, Linux, and macOS.

## 1. Install Rust (once per machine)

### Windows

1. Download and run [`rustup-init.exe`](https://rustup.rs) (accept defaults).
2. Open a **new** PowerShell or Command Prompt.
3. Verify:

   ```powershell
   rustc --version
   cargo --version
   ```

### Linux / macOS

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# restart your shell or: source "$HOME/.cargo/env"
rustc --version
cargo --version
```

## 2. Get the source

```sh
git clone https://github.com/zipsentinel/zipsentinel.git
cd zipsentinel
```

## 3. Build (scripted)

| OS       | Command                                             |
|----------|-----------------------------------------------------|
| Windows  | `powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1` |
| Linux/macOS | `./scripts/build.sh`                            |

Optional flags: `-Tests` / `--test` also runs `cargo test --workspace`;
`-Debug` / `--debug` builds an unoptimized binary (faster compile).

The release binary lands at:

- Windows: `target\release\zipsentinel.exe`
- Linux/macOS: `target/release/zipsentinel`

## 4. Build manually (without the scripts)

The scripts are thin wrappers around cargo — you can always do it by hand.

### Windows (PowerShell or cmd)

```powershell
cargo build --release -p zipsentinel-cli
.\target\release\zipsentinel.exe --help
```

### Linux / macOS

```sh
cargo build --release -p zipsentinel-cli
./target/release/zipsentinel --help
```

### Run the test suite

```sh
cargo test --workspace        # all OSes
cargo fmt --all -- --check    # formatting gate
cargo clippy --workspace --all-targets -- -D warnings
cargo bench -p zipsentinel-detector   # benchmarks (needs bench profile)
```

## 5. Smoke test

### Windows

```powershell
.\scripts\demo-windows.ps1
```

### Linux / macOS

```sh
chmod +x scripts/*.sh
./scripts/demo.sh
```

Or manually:

```sh
zipsentinel generate --profile high-compression --size 1MB --output bomb.zip
zipsentinel scan bomb.zip          # expect HIGH RISK, exit code 2
zipsentinel extract bomb.zip --output ./out --strict
```

## 6. Put it on PATH (optional)

```sh
# Linux/macOS
sudo ln -sf "$(pwd)/target/release/zipsentinel" /usr/local/bin/zipsentinel

# Windows (PowerShell, user-level PATH)
[Environment]::SetEnvironmentVariable('Path',
  $env:Path + ';' + (Resolve-Path '.\target\release').Path, 'User')
```

## Troubleshooting

- **`cargo` not found** — install rustup and open a *new* terminal so PATH
  refreshes.
- **PowerShell won't run scripts** — use
  `powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1`, or
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
- **Slow first build** — dependencies compile once; subsequent builds are
  incremental. Use `cargo build` (debug) for faster iteration.
- **Antivirus flags the binary** — common for new Rust CLI tools; submit a
  false-positive report if needed.
