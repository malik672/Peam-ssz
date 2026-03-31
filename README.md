# peam-ssz

`peam-ssz` is the extracted SSZ/merkleization crate from [Peam](https://github.com/malik672/Peam), a minimal performance-first Lean/Ethereum consensus client written in Rust.

The goal here is simple:

- keep dependencies minimal
- keep the hot path cheap

Right now the crate depends on `sha2` and otherwise keeps the core implementation local.

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

The tables below use the median point estimate from the latest local Criterion run on a M3 air.

### Encode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `15.375 ns` | `16.974 ns` | `19.645 ns` | `19.377 ns` | `1.10x faster` | `1.28x faster` | `1.26x faster` |
| `u64` | `15.379 ns` | `15.406 ns` | `18.046 ns` | `18.285 ns` | `~1.00x` | `1.17x faster` | `1.19x faster` |
| `[u8; 32]` | `17.942 ns` | `19.635 ns` | `20.415 ns` | `820.09 ns` | `1.09x faster` | `1.14x faster` | `45.71x faster` |
| `Vec<u64> (1K)` | `105.22 ns` | `116.18 ns` | `426.44 ns` | `22.484 us` | `1.10x faster` | `4.05x faster` | `213.69x faster` |
| `Vec<u64> (100K)` | `11.045 us` | `12.394 us` | `55.006 us` | `2.2138 ms` | `1.12x faster` | `4.98x faster` | `200.43x faster` |
| `BeaconBlockHeader` | `18.034 ns` | `19.660 ns` | `134.39 ns` | `2.3907 us` | `1.09x faster` | `7.45x faster` | `132.57x faster` |

### Decode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `540.87 ps` | `559.26 ps` | `827.57 ps` | `557.68 ps` | `1.03x faster` | `1.53x faster` | `1.03x faster` |
| `u64` | `446.70 ps` | `451.08 ps` | `450.20 ps` | `472.91 ps` | `~1.00x` | `~1.00x` | `1.06x faster` |
| `[u8; 32]` | `4.0330 ns` | `4.3548 ns` | `4.1102 ns` | `78.057 ns` | `1.08x faster` | `1.02x faster` | `19.35x faster` |
| `Vec<u64> (1K)` | `106.25 ns` | `113.45 ns` | `1.2193 us` | `762.90 ns` | `1.07x faster` | `11.48x faster` | `7.18x faster` |
| `Vec<u64> (100K)` | `10.108 us` | `12.117 us` | `162.24 us` | `129.38 us` | `1.20x faster` | `16.05x faster` | `12.80x faster` |
| `BeaconBlockHeader` | `12.523 ns` | `14.542 ns` | `12.129 ns` | `319.82 ns` | `1.16x faster` | `1.03x slower` | `25.54x faster` |

### Hash Tree Root

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `3.0366 ns` | `3.0363 ns` | `3.1981 ns` | `3.1296 ns` | `~1.00x` | `1.05x faster` | `1.03x faster` |
| `u64` | `3.0365 ns` | `3.0397 ns` | `3.1523 ns` | `58.072 ns` | `~1.00x` | `1.04x faster` | `19.12x faster` |
| `[u8; 32]` | `3.5222 ns` | `3.5403 ns` | `3.5426 ns` | `103.81 ns` | `~1.00x` | `~1.00x` | `29.47x faster` |

Peam-only header HTR measurement in the current harness:

| Type | peam-ssz |
| --- | ---: |
| `BeaconBlockHeader` | `1.6012 us` |

## Notes

- The current benchmark harness is intentionally narrow: primitives, fixed bytes, `Vec<u64>`, and a `BeaconBlockHeader`-shaped container.
