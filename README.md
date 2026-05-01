# peam-ssz

[![crates.io](https://img.shields.io/crates/v/peam-ssz.svg)](https://crates.io/crates/peam-ssz)
[![docs.rs](https://img.shields.io/docsrs/peam-ssz)](https://docs.rs/peam-ssz)

`peam-ssz` is the extracted SSZ/merkleization crate from [Peam](https://github.com/malik672/Peam), a minimal performance-first Lean/Ethereum consensus client written in Rust.

The goal here is simple:

- keep dependencies minimal
- keep the hot path cheap

Right now the crate depends on `sha2` and otherwise keeps the core implementation local.

As a published library, `peam-ssz` intentionally does not enable `sha2`'s `asm`
feature by default. Downstream applications that want architecture-specific SHA
backends can opt into them in their own dependency graph.

## Project Links

- Crate: [crates.io/crates/peam-ssz](https://crates.io/crates/peam-ssz)
- API docs: [docs.rs/peam-ssz](https://docs.rs/peam-ssz)
- Repository: [malik672/Peam-ssz](https://github.com/malik672/Peam-ssz)
- Upstream client: [malik672/Peam](https://github.com/malik672/Peam)

## Origins

This crate started as a direct extraction of Peam's internal SSZ code which was copied from SigmaPrime ethssz and then grew into a standalone testable library.

Core implementation came from:

- [`Peam/src/ssz/mod.rs`](https://github.com/malik672/Peam/blob/master/src/ssz/mod.rs)
- [`Peam/src/ssz/hash.rs`](https://github.com/malik672/Peam/blob/master/src/ssz/hash.rs)

Shared supporting pieces were then pulled out of Peam and wired into this crate:

- `Bytes32`
- collection/container utilities
- `unsafe_vec`
- progressive SSZ helpers

## Repository Layout

- `src/`: core SSZ encode/decode/hash-tree-root implementation
- `spec-tests/`: official Ethereum consensus spec-vector harness
- `fuzz/`: cargo-fuzz targets for robustness and differential checking

## Validation

### Unit and integration tests

Run:

```bash
cd peam-ssz
cargo test
```

### Official Ethereum spec vectors

The spec-test harness uses the official Ethereum consensus spec release archives from `v1.6.1`.

Source:

- `spec-tests/download-vectors.sh`
- release base: [ethereum/consensus-specs `v1.6.1`](https://github.com/ethereum/consensus-specs/releases/tag/v1.6.1)

Download vectors:

```bash
cd peam-ssz
./spec-tests/download-vectors.sh
```

Run spec tests:

```bash
cd peam-ssz
cargo test -p spec-tests -- --nocapture
```

Current status:

- `ssz_generic`: passing
- `ssz_static_mainnet`: passing through `deneb`
- `ssz_static_minimal`: harness is present; real execution depends on the `minimal` archive being downloaded locally

### Fuzzing

Fuzzing uses `cargo-fuzz` / `libFuzzer` via `libfuzzer-sys`.

The fuzz targets are intentionally small and practical:

- `decode_robustness`
  - throws arbitrary bytes at primitive/list decode paths to catch panics and decode bugs
- `diff_header`
  - differential fuzzing against `libssz` for a `BeaconBlockHeader`-shaped fixed container
- `diff_list_u64`
  - differential fuzzing against `libssz_types::SszList<u64, N>`

Reference crates used in the differential fuzz targets:

- `libssz`
- `libssz-types`
- `libssz-merkle`
- `libssz-derive`

Run a fuzz target:

```bash
cd peam-ssz/fuzz
cargo fuzz run decode_robustness
```

Examples:

```bash
cd peam-ssz/fuzz
cargo fuzz run diff_header
cargo fuzz run diff_list_u64
```

## Benchmarks

`peam-ssz` carries its own differential benchmark harness.

Credit: the comparison harness shape and fixture design were adapted from the excellent `libssz` benchmark setup.

Benchmark files:

- `benches/peam_differential.rs`
- `benches/fixtures.rs`

Compared implementations:

- `peam-ssz`
- `libssz`
- Lighthouse SSZ (`lighthouse_ssz` / `ethereum_ssz`)
- `ssz_rs`

Run:

```bash
cd peam-ssz
cargo bench --bench peam_differential
```

The tables below use the median point estimate from the latest local Criterion runs on an M3 Air. For noisier hot-path targets, focused reruns are preferred over one giant all-in bench sweep.

### Encode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `11.521 ns` | `11.449 ns` | `19.996 ns` | `14.300 ns` | `~1.00x` | `1.74x faster` | `1.24x faster` |
| `u64` | `11.458 ns` | `11.446 ns` | `15.421 ns` | `16.201 ns` | `~1.00x` | `1.35x faster` | `1.41x faster` |
| `[u8; 32]` | `14.133 ns` | `14.105 ns` | `17.931 ns` | `704.08 ns` | `~1.00x` | `1.27x faster` | `49.82x faster` |
| `Vec<u64> (1K)` | `111.58 ns` | `119.12 ns` | `434.87 ns` | `19.226 us` | `1.07x faster` | `3.90x faster` | `172.31x faster` |
| `Vec<u64> (100K)` | `42.983 us` | `42.794 us` | `84.693 us` | `2.1747 ms` | `~1.00x` | `1.97x faster` | `50.59x faster` |
| `BeaconBlockHeader` | `14.060 ns` | `13.965 ns` | `108.12 ns` | `1.9966 us` | `~1.00x` | `7.69x faster` | `142.01x faster` |

### Decode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `540.44 ps` | `555.95 ps` | `831.54 ps` | `560.36 ps` | `1.03x faster` | `1.54x faster` | `1.04x faster` |
| `u64` | `452.78 ps` | `839.69 ps` | `539.19 ps` | `1.0824 ns` | `1.85x faster` | `1.19x faster` | `2.39x faster` |
| `[u8; 32]` | `3.7709 ns` | `4.0700 ns` | `3.8532 ns` | `91.437 ns` | `1.08x faster` | `1.02x faster` | `24.25x faster` |
| `Vec<u64> (1K)` | `118.27 ns` | `121.05 ns` | `1.1793 us` | `1.4868 us` | `1.02x faster` | `9.97x faster` | `12.57x faster` |
| `Vec<u64> (100K)` | `38.508 us` | `37.104 us` | `195.59 us` | `160.96 us` | `1.04x slower` | `5.08x faster` | `4.18x faster` |
| `BeaconBlockHeader` | `12.566 ns` | `14.374 ns` | `12.041 ns` | `279.25 ns` | `1.14x faster` | `1.04x slower` | `22.22x faster` |

### Hash Tree Root

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `3.2138 ns` | `3.0469 ns` | `8.5619 ns` | `4.6362 ns` | `1.05x slower` | `2.66x faster` | `1.44x faster` |
| `u64` | `3.1461 ns` | `3.4293 ns` | `3.7429 ns` | `48.848 ns` | `1.09x faster` | `1.19x faster` | `15.53x faster` |
| `[u8; 32]` | `3.5662 ns` | `3.6437 ns` | `5.3615 ns` | `112.56 ns` | `1.02x faster` | `1.50x faster` | `31.56x faster` |
| `Vec<u64> (1K)` | `71.459 us` | `70.126 us` | `n/a` | `72.868 us` | `1.02x slower` | `n/a` | `1.02x faster` |
| `Vec<u64> (100K)` | `6.7942 ms` | `9.0167 ms` | `n/a` | `7.0884 ms` | `1.33x faster` | `n/a` | `1.04x faster` |

Peam-only header HTR measurement in the current harness:

| Type | peam-ssz |
| --- | ---: |
| `BeaconBlockHeader` | `1.6588 us` |

## Notes

- The current benchmark harness is intentionally narrow: primitives, fixed bytes, `Vec<u64>`, and a `BeaconBlockHeader`-shaped container.
- The crate enables `sha2`'s `compress` API, but leaves `sha2/asm` as an
  application-level choice for downstream users.
