# Benchmarks

This file keeps machine-specific benchmark snapshots out of the main README while still preserving the local results that shaped the crate.

These numbers come from local Criterion runs on an M3 Air using:

```bash
cargo bench --bench peam_differential
```

They should be read as comparative local measurements, not universal claims across all CPUs, compilers, or workloads.

## Compared Implementations

- `peam-ssz`
- `libssz`
- Lighthouse SSZ (`lighthouse_ssz` / `ethereum_ssz`)
- `ssz_rs`

## Encode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `11.521 ns` | `11.449 ns` | `19.996 ns` | `14.300 ns` | `~1.00x` | `1.74x faster` | `1.24x faster` |
| `u64` | `11.458 ns` | `11.446 ns` | `15.421 ns` | `16.201 ns` | `~1.00x` | `1.35x faster` | `1.41x faster` |
| `[u8; 32]` | `14.133 ns` | `14.105 ns` | `17.931 ns` | `704.08 ns` | `~1.00x` | `1.27x faster` | `49.82x faster` |
| `Vec<u64> (1K)` | `111.58 ns` | `119.12 ns` | `434.87 ns` | `19.226 us` | `1.07x faster` | `3.90x faster` | `172.31x faster` |
| `Vec<u64> (100K)` | `42.983 us` | `42.794 us` | `84.693 us` | `2.1747 ms` | `~1.00x` | `1.97x faster` | `50.59x faster` |
| `BeaconBlockHeader` | `14.060 ns` | `13.965 ns` | `108.12 ns` | `1.9966 us` | `~1.00x` | `7.69x faster` | `142.01x faster` |

## Decode

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `540.44 ps` | `555.95 ps` | `831.54 ps` | `560.36 ps` | `1.03x faster` | `1.54x faster` | `1.04x faster` |
| `u64` | `452.78 ps` | `839.69 ps` | `539.19 ps` | `1.0824 ns` | `1.85x faster` | `1.19x faster` | `2.39x faster` |
| `[u8; 32]` | `3.7709 ns` | `4.0700 ns` | `3.8532 ns` | `91.437 ns` | `1.08x faster` | `1.02x faster` | `24.25x faster` |
| `Vec<u64> (1K)` | `118.27 ns` | `121.05 ns` | `1.1793 us` | `1.4868 us` | `1.02x faster` | `9.97x faster` | `12.57x faster` |
| `Vec<u64> (100K)` | `38.508 us` | `37.104 us` | `195.59 us` | `160.96 us` | `1.04x slower` | `5.08x faster` | `4.18x faster` |
| `BeaconBlockHeader` | `12.566 ns` | `14.374 ns` | `12.041 ns` | `279.25 ns` | `1.14x faster` | `1.04x slower` | `22.22x faster` |

## Hash Tree Root

| Type | peam-ssz | libssz | Lighthouse | ssz_rs | Peam vs libssz | Peam vs Lighthouse | Peam vs ssz_rs |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `bool` | `3.2367 ns` | `3.0469 ns` | `8.5619 ns` | `4.6362 ns` | `1.06x slower` | `2.65x faster` | `1.43x faster` |
| `u64` | `3.0904 ns` | `3.4293 ns` | `3.7429 ns` | `48.848 ns` | `1.11x faster` | `1.21x faster` | `15.81x faster` |
| `[u8; 32]` | `3.5525 ns` | `3.6437 ns` | `5.3615 ns` | `112.56 ns` | `1.03x faster` | `1.51x faster` | `31.68x faster` |
| `Vec<u64> (1K)` | `13.213 us` | `70.126 us` | `n/a` | `72.868 us` | `5.31x faster` | `n/a` | `5.51x faster` |
| `Vec<u64> (100K)` | `1.2079 ms` | `9.0167 ms` | `n/a` | `7.0884 ms` | `7.46x faster` | `n/a` | `5.87x faster` |

Peam-only header HTR measurement from the same harness:

| Type | peam-ssz |
| --- | ---: |
| `BeaconBlockHeader` | `251.27 ns` |

## Notes

- These runs are intentionally narrow and hot-path focused.
- The harness covers primitives, fixed bytes, `Vec<u64>`, and a `BeaconBlockHeader`-shaped container.
- When making public performance claims, prefer wording like "fastest in our local differential benchmarks" rather than universal claims.
