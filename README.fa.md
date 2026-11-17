# ZipSentinel (راهنمای فارسی)

**ابزار امنیت و تحقیق در زمینه آرشیوها** — یک workspace چند-کِریتی به زبان Rust
برای تولید نمونه‌های آزمایشی کنترل‌شده ZIP، تحلیل ساختار آرشیو، تشخیص
احتمالی ZIP bomb، و استخراج امن آرشیوهای نامعتبر.

> این پروژه برای تحقیق دفاعی، مهندسی تشخیص و آزمایش‌های کنترل‌شده طراحی شده
> است؛ یک ابزار فشرده‌سازی عمومی نیست.

## قابلیت‌ها

- **تولید کنترل‌شده** — نمونه‌های آزمایشی قطعی (deterministic) با پروفایل‌های
  standard، high-compression، many-files، nested، corrupted و empty؛ با محدودیت
  سخت روی حجم، تعداد entry، عمق تودرتو و زمان اجرا.
- **تحلیل ساختاری** — پارس دستی و امن central directory با پشتیبانی ZIP64،
  تطبیق local header با central directory، تشخیص نام‌های تکراری/مشکوک، پرچم
  رمزنگاری و متدهای فشرده‌سازی پشتیبانی‌نشده.
- **موتور تشخیص** — امتیازدهی چند‌شاخصی (نه تک‌heuristic) که متادیتای اعلامی را
  با رفتار واقعی decompress ترکیب می‌کند و آرشیوهای تو در تو را بازگشتی اسکن
  می‌کند. یافته‌ها `MEASURED` را از `ESTIMATED` تفکیک می‌کنند.
- **استخراج امن** — محافظت در برابر ZIP Slip، مسیر مطلق، symlink و نام
  تکراری؛ بودجه حجم/entry/عمق/زمان؛ نوشتن atomic با temp-file + rename.
- **گزارش‌گیری** — JSON (قابل خواندن مجدد)، گزارش ترمینال و HTML مستقل.
- **بنچمارک** — Criterion برای parse و detect.

## نصب و ساخت

فقط به Rust toolchain نیاز است (rustup). اسکریپت‌ها:

| سیستم‌عامل | build | demo |
|---|---|---|
| Windows | `scripts\build-windows.ps1` | `scripts\demo-windows.ps1` |
| Linux/macOS | `./scripts/build.sh` | `./scripts/demo.sh` |

خروجی: `target/release/zipsentinel[.exe]`
راهنمای کامل دستی در [docs/build-guide.md](docs/build-guide.md) (نسخه فارسی:
[docs/build-guide.fa.md](docs/build-guide.fa.md)).

## مثال‌ها

```sh
# اسکن سریع ریسک
zipsentinel scan archive.zip
zipsentinel scan archive.zip --json

# تحلیل دقیق + گزارش HTML
zipsentinel analyze archive.zip --html report.html

# تولید نمونه آزمایشی
zipsentinel generate --profile high-compression --size 1MB --output bomb.zip
zipsentinel generate --profile nested --depth 3 --output nested.zip
zipsentinel generate --profile corrupted --corruption truncated --output bad.zip

# استخراج امن
zipsentinel extract archive.zip --output ./safe-output --recursive

# بنچمارک روی پوشه‌ای از آرشیوها
zipsentinel benchmark ./fixtures/ --json

# نمایش کانفیگ پیش‌فرض
zipsentinel config show
```

### کدهای خروجی

| کد | معنی |
|---|---|
| 0 | SAFE یا LOW RISK |
| 1 | MEDIUM RISK |
| 2 | HIGH RISK |
| 3 | BLOCKED |
| 4 | خطای عملیاتی (I/O، parse، limits) |

### محدودیت‌های منابع

`--strict` محدودیت‌های محافظه‌کارانه‌تری اعمال می‌کند (۶۴MiB برای هر entry،
۲۵۶MiB مجموع، ۱۰هزار entry، عمق ۲، ۶۰ ثانیه). پیش‌فرض‌ها بازتر هستند.
عبور از هر محدودیت همیشه خطای کنترل‌شده `LimitExceeded` تولید می‌کند —
هیچ‌وقت بی‌صدا نادیده گرفته نمی‌شود.

## معماری

```
cli → detector → analyzer → parser → core
     extractor → guard → core
     generator → guard → core
     report → core
```

| Crate | مسئولیت |
|---|---|
| `zipsentinel-core` | تایپ‌های مشترک، محدودیت‌ها، یافته‌ها، خطاها |
| `zipsentinel-parser` | پارس EOCD/CD/ZIP64 با bounds-check، تشخیص تودرتو |
| `zipsentinel-analyzer` | یافته‌های ساختاری، تطبیق local header |
| `zipsentinel-detector` | امتیاز ریسک، decompress اندازه‌گیری‌شده، اسکن تو در تو |
| `zipsentinel-generator` | تولید قطعی و محدود نمونه‌های آزمایشی |
| `zipsentinel-extractor` | استخراج امن با اعمال مسیر و منابع |
| `zipsentinel-guard` | بودجه منابع و writer محافظت‌شده |
| `zipsentinel-report` | رندر JSON / ترمینال / HTML |
| `zipsentinel-cli` | باینری `zipsentinel` |

مدل تهدید در [docs/threat-model.md](docs/threat-model.md).

## توسعه

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p zipsentinel-detector
```

تست‌ها کنار هر crate در `crates/*/tests/` قرار دارند + تست‌های end-to-end
CLI در `crates/zipsentinel-cli/tests/`. پایداری parser با proptest mutation
پوشش داده شده؛ همه fixtureها در tempdir ساخته می‌شوند.

## لایسنس

MIT — برای جزئیات به [LICENSE](LICENSE) مراجعه کنید.
