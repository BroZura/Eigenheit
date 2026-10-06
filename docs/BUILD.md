# Reproducible builds

These commands build the release binaries and print their SHA-256 hashes:

```sh
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$HOME=~ --remap-path-prefix=$PWD=."
cargo build --release --locked --workspace
sha256sum target/release/eigen target/release/eigen-relay
```

- `Cargo.lock` is committed. Every direct dependency is pinned with `=` in the workspace `Cargo.toml`.
- The release profile sets `lto = true`, `codegen-units = 1`, `panic = "abort"` and `strip = true`. A single codegen unit makes the output independent of build scheduling. Stripping removes the paths and build IDs stored in the debug information.
- Identical hashes require the same toolchain version, the same target triple and the path remapping shown above.
- CI (`.github/workflows/ci.yml`) builds the binaries twice from a clean state and checks that the hashes are identical.
- CI also runs `cargo deny check` (licenses, sources, and bans on HTTP, telemetry and logging crates) and `cargo audit`.
- The workspace crates have no `build.rs`. Some dependencies run build scripts or procedural macros at build time, for example `libc`, `zeroize_derive`, `tokio-macros` and, through ratatui, `paste`, `strum_macros` and `instability`. The build uses the network only to download crates.

To verify a release independently, build it in a container pinned by digest (for example `rust:1.97-slim@sha256:<digest>`) and compare the hashes with a build made by another person.
