# peam-ssz

[![crates.io](https://img.shields.io/crates/v/peam-ssz.svg)](https://crates.io/crates/peam-ssz)
[![docs.rs](https://img.shields.io/docsrs/peam-ssz)](https://docs.rs/peam-ssz)

`peam-ssz` is a small, performance-focused SSZ encoding, decoding, and merkleization crate extracted from [Peam](https://github.com/malik672/Peam), a Lean/Ethereum consensus client written in Rust.

The design goals are straightforward:

- keep dependencies minimal
- keep the hot path cheap
- stay close to Ethereum SSZ behavior

The crate depends only on `sha2` for hashing. Everything else stays in-tree.

Warning: `peam-ssz` currently enables `sha2`'s `asm` backend on `aarch64`,
`x86_64`, and `x86` builds to favor end-to-end throughput. The upstream `sha2`
documentation treats this as an application-level choice; we keep it enabled
here deliberately.

## Links

- Crate: [crates.io/crates/peam-ssz](https://crates.io/crates/peam-ssz)
- API docs: [docs.rs/peam-ssz](https://docs.rs/peam-ssz)
- Repository: [malik672/Peam-ssz](https://github.com/malik672/Peam-ssz)
- Upstream client: [malik672/Peam](https://github.com/malik672/Peam)

## What It Includes

- core SSZ encode/decode traits and primitives
- fixed and variable-size collection helpers
- container utilities
- bitlist and bitvector support
- progressive SSZ helpers
- hash-tree-root and Merkle utilities

Repository layout:

- `src/`: crate implementation
- `spec-tests/`: Ethereum consensus spec-vector harness
- `fuzz/`: robustness and differential fuzzing targets
- `benches/`: Criterion differential benchmarks

## Origins

This crate began as an extraction of Peam's internal SSZ code, which itself came from SigmaPrime `ethssz`, and was then shaped into a standalone library with tests, fuzzing, and benchmarks.

The original Peam sources were:

- [`Peam/src/ssz/mod.rs`](https://github.com/malik672/Peam/blob/master/src/ssz/mod.rs)
- [`Peam/src/ssz/hash.rs`](https://github.com/malik672/Peam/blob/master/src/ssz/hash.rs)

## Validation

Run the crate test suite:

```bash
cargo test
```

Run the spec-test harness:

```bash
./spec-tests/download-vectors.sh
cargo test -p spec-tests -- --nocapture
```

The spec harness is wired to the Ethereum consensus spec vectors from [`v1.6.1`](https://github.com/ethereum/consensus-specs/releases/tag/v1.6.1).

## Fuzzing

Fuzzing uses `cargo-fuzz` and `libFuzzer`.

Available targets:

- `decode_robustness`
- `diff_header`
- `diff_list_u64`

Run one target from the fuzz workspace:

```bash
cd fuzz
cargo fuzz run decode_robustness
```

## Benchmarks

`peam-ssz` includes a differential Criterion benchmark harness that compares against:

- `libssz`
- Lighthouse SSZ (`ethereum_ssz`)
- `ssz_rs`

Run the benchmark suite:

```bash
cargo bench --bench peam_differential
```

The benchmark harness is intentionally narrow and focused on hot-path types such as primitives, fixed bytes, `Vec<u64>`, and a `BeaconBlockHeader`-shaped container. For current numbers, rerun the benches on your target machine rather than relying on committed local results.

Local benchmark snapshots are preserved in [BENCHMARKS.md](./BENCHMARKS.md).
