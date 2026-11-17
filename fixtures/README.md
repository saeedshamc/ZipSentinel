# Fixtures

Test fixtures are generated on demand — no binary blobs are committed.

Generate samples with the CLI:

```sh
cargo run -p zipsentinel-cli -- generate --profile standard --output fixtures/standard.zip
cargo run -p zipsentinel-cli -- generate --profile high-compression --size 1MB --output fixtures/high-compression.zip
cargo run -p zipsentinel-cli -- generate --profile nested --depth 3 --output fixtures/nested.zip
cargo run -p zipsentinel-cli -- generate --profile corrupted --corruption truncated --output fixtures/corrupted.zip
```

Then benchmark them:

```sh
cargo run -p zipsentinel-cli -- benchmark ./fixtures/
```
