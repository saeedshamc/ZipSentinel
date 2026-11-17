# راهنمای Build و اجرا (فارسی)

ZipSentinel کاملاً به زبان Rust نوشته شده — تنها پیش‌نیاز، toolchain رپسّت.
همه مراحل زیر روی Windows، Linux و macOS یکسان است.

## ۱. نصب Rust (یک‌بار برای هر سیستم)

### ویندوز

1. فایل [`rustup-init.exe`](https://rustup.rs) را دانلود و اجرا کنید
   (گزینه‌های پیش‌فرض OK است).
2. یک PowerShell یا Command Prompt **جدید** باز کنید.
3. بررسی:

   ```powershell
   rustc --version
   cargo --version
   ```

### لینوکس / مک

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# ترمینال را ببندید و دوباره باز کنید یا:
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

## ۲. گرفتن سورس

```sh
git clone https://github.com/zipsentinel/zipsentinel.git
cd zipsentinel
```

## ۳. Build با اسکریپت

| سیستم‌عامل | دستور |
|---|---|
| ویندوز | `powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1` |
| لینوکس/مک | `./scripts/build.sh` |

فلگ‌های اختیاری: `-Tests` (PowerShell) یا `--test` (bash) علاوه بر build،
`cargo test --workspace` را هم اجرا می‌کند؛ `-Debug` یا `--debug` بیلد
بهینه‌نشده می‌گیرد (کامپایل سریع‌تر).

محل باینری خروجی:

- ویندوز: `target\release\zipsentinel.exe`
- لینوکس/مک: `target/release/zipsentinel`

## ۴. Build دستی (بدون اسکریپت)

اسکریپت‌ها فقط wrapper نازکی دور cargo هستند — همیشه می‌توانید دستی انجام دهید.

### ویندوز (PowerShell یا cmd)

```powershell
cargo build --release -p zipsentinel-cli
.\target\release\zipsentinel.exe --help
```

### لینوکس / مک

```sh
cargo build --release -p zipsentinel-cli
./target/release/zipsentinel --help
```

### اجرای تست‌ها

```sh
cargo test --workspace        # همه سیستم‌عامل‌ها
cargo fmt --all -- --check    # بررسی فرمت
cargo clippy --workspace --all-targets -- -D warnings
cargo bench -p zipsentinel-detector   # بنچمارک
```

## ۵. تست اجرا (smoke test)

### ویندوز

```powershell
.\scripts\demo-windows.ps1
```

### لینوکس / مک

```sh
chmod +x scripts/*.sh
./scripts/demo.sh
```

یا دستی:

```sh
zipsentinel generate --profile high-compression --size 1MB --output bomb.zip
zipsentinel scan bomb.zip          # انتظار: HIGH RISK با exit code 2
zipsentinel extract bomb.zip --output ./out --strict
```

## ۶. اضافه کردن به PATH (اختیاری)

```sh
# لینوکس/مک
sudo ln -sf "$(pwd)/target/release/zipsentinel" /usr/local/bin/zipsentinel

# ویندوز (PowerShell، در سطح کاربر)
[Environment]::SetEnvironmentVariable('Path',
  $env:Path + ';' + (Resolve-Path '.\target\release').Path, 'User')
```

## عیب‌یابی

- **`cargo` پیدا نمی‌شود** — rustup را نصب کنید و یک ترمینال **جدید** باز کنید
  تا PATH تازه شود.
- **PowerShell اسکریپت اجرا نمی‌کند** — از
  `powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1` استفاده
  کنید یا یک‌بار `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` بزنید.
- **اولین build کند است** — وابستگی‌ها فقط یک‌بار کامپایل می‌شوند؛ buildهای
  بعدی incremental هستند. برای سریع از `cargo build` (debug) استفاده کنید.
- **آنتی‌ویروس باینری را flag می‌کند** — برای ابزارهای CLI جدید Rust رایج است.
