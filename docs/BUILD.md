# Building, reproducibly

```sh
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=."
cargo build --release --locked --workspace
sha256sum target/release/eigen target/release/eigen-relay
```

- `Cargo.lock` is committed and every direct dependency is pinned with `=` in the workspace `Cargo.toml`.
- Release profile: `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true` — single codegen unit removes scheduling nondeterminism; stripping removes paths and build ids embedded in debug info.
- Same toolchain version, same target triple and the path remapping above are required for identical hashes. CI (`.github/workflows/ci.yml`) builds twice from clean and diffs the hashes.
- Supply chain: `cargo deny check` (licenses, bans on HTTP/telemetry/logging crates, sources) and `cargo audit` run in CI.
- No `build.rs`, no proc-macro beyond `zeroize_derive`, no network at build time beyond fetching crates.

For maximum assurance build inside a pinned container (e.g. `rust:1.97-slim` by digest) and compare hashes with someone else's build.
