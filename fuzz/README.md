# Coverage-guided fuzzing

This directory is a separate cargo package holding the kernel's coverage-guided
fuzz targets. It is out of tree on purpose: the kernel crate has no
dependencies and its tests run `--offline`, so libFuzzer is not something a
root `cargo build` should ever resolve. The deterministic harnesses in
`tests/parsers/fuzz.rs` stay the fast gate; these targets are the search that
runs on a schedule, where a fixed seed cannot reach.

The property is the harnesses' property, taken to arbitrary input: a malformed
buffer produces a clean `Err`, never a panic, a hang, or an out-of-bounds read.

## Targets

| Target | Boundary |
|--------|----------|
| `elf_loader` | `parse_elf64` and the segment planner behind it |
| `filesystem_images` | every filesystem image opener and the MBR/GPT reader |
| `luks2` | the LUKS2 header, metadata scanner, keyslot decode and `luks2_open` |
| `packet_parsers` | the link, internet, transport and TLS record parsers |

## Running

```sh
cargo install cargo-fuzz
cd fuzz
cargo fuzz run elf_loader --features demo-disk
cargo fuzz run filesystem_images --features demo-disk
cargo fuzz run luks2 --features demo-disk
cargo fuzz run packet_parsers --features demo-disk
```

## Checking the targets

`make fmt-check` formats this package along with the tree, because formatting
never resolves dependencies.  Linting and type-checking it do resolve them, so
those are `make check-fuzz-targets`, which needs the dependencies present:

```sh
cargo fetch --manifest-path fuzz/Cargo.toml
make check-fuzz-targets
```

That target also fails when this package's `Cargo.lock` is stale, which is what
happens whenever the kernel's `version` in the root `Cargo.toml` is bumped: the
lock records that version for the path dependency, and `cargo metadata` is what
rewrites it.  `.github/workflows/fuzz.yml` runs the check on its nightly
schedule; it is not in `make clippy` or in `make verify`, which work from a bare
checkout.

Build output goes to the repository's ignored `target/fuzz` (see
`fuzz/.cargo/config.toml`), and corpora and crash artifacts land in
`fuzz/corpus/` and `fuzz/artifacts/`, both ignored. A crashing input is written
to `fuzz/artifacts/<target>/`; reproduce it by passing the file as the last
argument to `cargo fuzz run`.

The nightly job in `.github/workflows/fuzz.yml` runs each target for a bounded
time and starts from an empty corpus, so it finds new crashes rather than
replaying a checked-in one. Corpus accumulation across runs is deliberately not
enabled yet; that needs a corpus store, which is a separate decision.
