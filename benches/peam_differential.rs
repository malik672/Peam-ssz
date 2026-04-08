//! Differential benchmark for `peam-ssz`.
//!
//! Adapted from the `libssz` benchmark harness and comparison setup in:
//! `libssz/benches/benches/peam_differential.rs`

#[path = "fixtures.rs"]
mod fixtures;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fixtures::{make_header, make_nested_vec_u64, make_vec_u64, pre_encode, BeaconBlockHeader};
use libssz::{SszDecode as LibSszDecode, SszEncode as LibSszEncode};
use libssz_merkle::HashTreeRoot as LibHashTreeRoot;
use peam_ssz::ssz::hash::{hash_nodes, merkleize_unsafe};
use peam_ssz::ssz::{
    HashTreeRoot as PeamHashTreeRoot, SszDecode as PeamSszDecode, SszEncode as PeamSszEncode,
};
use peam_ssz::types::beacon::BeaconBlockHeader as PeamBeaconBlockHeader;
use peam_ssz::types::bytes::Bytes32;
use peam_ssz::types::bytes::Bytes32 as PeamBytes32;
use peam_ssz::types::collections::SszList as PeamList;
use std::sync::OnceLock;

const PEAM_VEC_LIMIT: usize = 100_000;

fn merkleize_old(chunks: &[Bytes32]) -> Bytes32 {
    let limit = chunks.len();

    if limit == 0 {
        return Bytes32::zero();
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if width == 1 {
        return chunks[0];
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;

    while subtree_size < width {
        let next_len = level.len().div_ceil(2);
        let mut next = vec![Bytes32::zero(); next_len];
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i < level.len() {
            let left = &level[i];
            i += 1;
            let right = if i < level.len() {
                let r = &level[i];
                i += 1;
                r
            } else {
                &bench_zero_tree_root(subtree_size)
            };
            next[out_idx] = hash_nodes(left, right);
            out_idx += 1;
        }
        level = next;
        subtree_size <<= 1;
    }

    level[0]
}

fn merkleize_new(chunks: &[Bytes32]) -> Bytes32 {
    let limit = chunks.len();

    if limit == 0 {
        return Bytes32::zero();
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if width == 1 {
        return chunks[0];
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;

    while subtree_size < width {
        let next_len = level.len().div_ceil(2);
        let mut next = vec![Bytes32::zero(); next_len];
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i + 1 < level.len() {
            next[out_idx] = hash_nodes(&level[i], &level[i + 1]);
            i += 2;
            out_idx += 1;
        }
        if i != level.len() {
            next[out_idx] = hash_nodes(&level[i], &bench_zero_tree_root(subtree_size));
        }
        level = next;
        subtree_size <<= 1;
    }

    level[0]
}

fn bench_zero_tree_root(width: usize) -> Bytes32 {
    static ZERO_HASHES: OnceLock<Vec<Bytes32>> = OnceLock::new();

    let zero_hashes = ZERO_HASHES.get_or_init(|| {
        let mut hashes = Vec::with_capacity(64);
        hashes.push(Bytes32::zero());
        for idx in 1..64 {
            let prev = hashes[idx - 1];
            hashes.push(hash_nodes(&prev, &prev));
        }
        hashes
    });

    let depth = width.trailing_zeros() as usize;
    zero_hashes[depth]
}

fn make_chunks(n: usize) -> Vec<Bytes32> {
    (0..n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            bytes[8..16].copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9).to_le_bytes());
            Bytes32::from(bytes)
        })
        .collect()
}

/// Converts the shared benchmark fixture into the real `peam-ssz` header type.
fn peam_header_from_fixture(value: &BeaconBlockHeader) -> PeamBeaconBlockHeader {
    PeamBeaconBlockHeader {
        slot: value.slot,
        proposer_index: value.proposer_index,
        parent_root: PeamBytes32::from(value.parent_root),
        state_root: PeamBytes32::from(value.state_root),
        body_root: PeamBytes32::from(value.body_root),
    }
}

/// Encodes the shared header fixture through Lighthouse's SSZ traits.
fn lighthouse_encode_header(h: &BeaconBlockHeader) -> Vec<u8> {
    let mut buf = Vec::new();
    <u64 as lighthouse_ssz::Encode>::ssz_append(&h.slot, &mut buf);
    <u64 as lighthouse_ssz::Encode>::ssz_append(&h.proposer_index, &mut buf);
    <[u8; 32] as lighthouse_ssz::Encode>::ssz_append(&h.parent_root, &mut buf);
    <[u8; 32] as lighthouse_ssz::Encode>::ssz_append(&h.state_root, &mut buf);
    <[u8; 32] as lighthouse_ssz::Encode>::ssz_append(&h.body_root, &mut buf);
    buf
}

/// Decodes the fixed 112-byte header layout using Lighthouse's SSZ traits.
fn lighthouse_decode_header(bytes: &[u8]) -> (u64, u64, [u8; 32], [u8; 32], [u8; 32]) {
    let slot = <u64 as lighthouse_ssz::Decode>::from_ssz_bytes(&bytes[0..8]).unwrap();
    let proposer_index = <u64 as lighthouse_ssz::Decode>::from_ssz_bytes(&bytes[8..16]).unwrap();
    let parent_root = <[u8; 32] as lighthouse_ssz::Decode>::from_ssz_bytes(&bytes[16..48]).unwrap();
    let state_root = <[u8; 32] as lighthouse_ssz::Decode>::from_ssz_bytes(&bytes[48..80]).unwrap();
    let body_root = <[u8; 32] as lighthouse_ssz::Decode>::from_ssz_bytes(&bytes[80..112]).unwrap();
    (slot, proposer_index, parent_root, state_root, body_root)
}

/// Encodes the shared header fixture through `ssz_rs`.
fn ssz_rs_encode_header(h: &BeaconBlockHeader) -> Vec<u8> {
    let mut buf = Vec::new();
    ssz_rs::Serialize::serialize(&h.slot, &mut buf).unwrap();
    ssz_rs::Serialize::serialize(&h.proposer_index, &mut buf).unwrap();
    ssz_rs::Serialize::serialize(&h.parent_root, &mut buf).unwrap();
    ssz_rs::Serialize::serialize(&h.state_root, &mut buf).unwrap();
    ssz_rs::Serialize::serialize(&h.body_root, &mut buf).unwrap();
    buf
}

/// Decodes the fixed 112-byte header layout using `ssz_rs`.
fn ssz_rs_decode_header(bytes: &[u8]) -> (u64, u64, [u8; 32], [u8; 32], [u8; 32]) {
    let slot = <u64 as ssz_rs::Deserialize>::deserialize(&bytes[0..8]).unwrap();
    let proposer_index = <u64 as ssz_rs::Deserialize>::deserialize(&bytes[8..16]).unwrap();
    let parent_root = <[u8; 32] as ssz_rs::Deserialize>::deserialize(&bytes[16..48]).unwrap();
    let state_root = <[u8; 32] as ssz_rs::Deserialize>::deserialize(&bytes[48..80]).unwrap();
    let body_root = <[u8; 32] as ssz_rs::Deserialize>::deserialize(&bytes[80..112]).unwrap();
    (slot, proposer_index, parent_root, state_root, body_root)
}

/// Compares primitive encode throughput across the four implementations.
fn diff_peam_encode_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode/primitives");

    macro_rules! bench_encode {
        ($name:expr, $value:expr) => {{
            let value = $value;
            group.bench_function(concat!("libssz/", $name), |b| {
                b.iter(|| black_box(value).to_ssz())
            });
            group.bench_function(concat!("lighthouse/", $name), |b| {
                b.iter(|| lighthouse_ssz::Encode::as_ssz_bytes(black_box(&value)))
            });
            group.bench_function(concat!("ssz_rs/", $name), |b| {
                b.iter(|| {
                    let mut buf = Vec::new();
                    ssz_rs::Serialize::serialize(black_box(&value), &mut buf).unwrap();
                    buf
                })
            });
            group.bench_function(concat!("peam/", $name), |b| {
                b.iter(|| PeamSszEncode::encode_ssz(black_box(&value)))
            });
        }};
    }

    bench_encode!("bool", true);
    bench_encode!("u64", 0x1234_5678_9ABC_DEF0u64);

    group.finish();
}

/// Compares fixed 32-byte encode throughput without container overhead.
fn diff_peam_encode_bytes32(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode/bytes32");
    let value = [0xABu8; 32];
    let peam_value = PeamBytes32::from(value);

    group.bench_function("libssz/bytes32", |b| b.iter(|| black_box(&value).to_ssz()));
    group.bench_function("lighthouse/bytes32", |b| {
        b.iter(|| lighthouse_ssz::Encode::as_ssz_bytes(black_box(&value)))
    });
    group.bench_function("ssz_rs/bytes32", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            ssz_rs::Serialize::serialize(black_box(&value), &mut buf).unwrap();
            buf
        })
    });
    group.bench_function("peam/bytes32", |b| b.iter(|| peam_value.encode_ssz()));

    group.finish();
}

/// Compares large fixed-element list encode throughput at two practical sizes.
fn diff_peam_encode_vec_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode/vec_u64");
    for &size in &[1_000usize, 100_000] {
        let data = make_vec_u64(size); 
        let peam = PeamList::<u64, PEAM_VEC_LIMIT>::new(data.clone()).unwrap();
        let ssz_rs = ssz_rs::List::<u64, PEAM_VEC_LIMIT>::try_from(data.clone()).unwrap();

        group.throughput(Throughput::Bytes((size * 8) as u64));
        group.bench_with_input(BenchmarkId::new("libssz", size), &data, |b, data| {
            b.iter(|| black_box(data).to_ssz());
        });
        group.bench_with_input(BenchmarkId::new("lighthouse", size), &data, |b, data| {
            b.iter(|| lighthouse_ssz::Encode::as_ssz_bytes(black_box(data)));
        });
        group.bench_with_input(BenchmarkId::new("ssz_rs", size), &ssz_rs, |b, data| {
            b.iter(|| {
                let mut buf = Vec::new();
                ssz_rs::Serialize::serialize(black_box(data), &mut buf).unwrap();
                buf
            });
        });
        group.bench_with_input(BenchmarkId::new("peam", size), &peam, |b, data| {
            b.iter(|| black_box(data).encode_ssz());
        });
    }
    group.finish();
}

/// Compares fixed-layout header encode throughput across implementations.
fn diff_peam_encode_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode/header");
    let header = make_header(42);
    let peam_header = peam_header_from_fixture(&header);

    group.bench_function("libssz", |b| b.iter(|| black_box(&header).to_ssz()));
    group.bench_function("lighthouse", |b| {
        b.iter(|| lighthouse_encode_header(black_box(&header)))
    });
    group.bench_function("ssz_rs", |b| {
        b.iter(|| ssz_rs_encode_header(black_box(&header)))
    });
    group.bench_function("peam", |b| b.iter(|| black_box(&peam_header).encode_ssz()));

    group.finish();
}

/// Exercises Peam's variable-size list encoding with nested `SszList<u64>` payloads.
fn diff_peam_encode_var_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode/var_list");
    for &(outer, inner) in &[(256usize, 16usize), (1024, 16)] {
        let nested = make_nested_vec_u64(outer, inner);
        let peam = PeamList::<PeamList<u64, PEAM_VEC_LIMIT>, PEAM_VEC_LIMIT>::new(
            nested
                .into_iter()
                .map(|inner| PeamList::<u64, PEAM_VEC_LIMIT>::new(inner).unwrap())
                .collect(),
        )
        .unwrap();

        group.throughput(Throughput::Elements(outer as u64));
        group.bench_with_input(
            BenchmarkId::new("peam", format!("{outer}x{inner}")),
            &peam,
            |b, data| {
                b.iter(|| black_box(data).encode_ssz());
            },
        );
    }
    group.finish();
}

/// Exercises Peam's direct append path for nested variable-size list encoding.
fn diff_peam_encode_into_var_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/encode_into/var_list");
    for &(outer, inner) in &[(256usize, 16usize), (1024, 16)] {
        let nested = make_nested_vec_u64(outer, inner);
        let peam = PeamList::<PeamList<u64, PEAM_VEC_LIMIT>, PEAM_VEC_LIMIT>::new(
            nested
                .into_iter()
                .map(|inner| PeamList::<u64, PEAM_VEC_LIMIT>::new(inner).unwrap())
                .collect(),
        )
        .unwrap();

        group.throughput(Throughput::Elements(outer as u64));
        group.bench_with_input(
            BenchmarkId::new("peam", format!("{outer}x{inner}")),
            &peam,
            |b, data| {
                let mut out = Vec::new();
                b.iter(|| {
                    out.clear();
                    black_box(data).encode_ssz_into(&mut out);
                    black_box(&out);
                });
            },
        );
    }
    group.finish();
}

/// Compares primitive decode throughput using bytes that were pre-encoded once.
fn diff_peam_decode_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/decode/primitives");

    macro_rules! bench_decode {
        ($name:expr, $ty:ty, $value:expr) => {{
            let bytes = pre_encode(&$value);
            group.bench_function(concat!("libssz/", $name), |b| {
                b.iter(|| <$ty as LibSszDecode>::from_ssz_bytes(black_box(&bytes)).unwrap())
            });
            group.bench_function(concat!("lighthouse/", $name), |b| {
                b.iter(|| {
                    <$ty as lighthouse_ssz::Decode>::from_ssz_bytes(black_box(&bytes)).unwrap()
                })
            });
            group.bench_function(concat!("ssz_rs/", $name), |b| {
                b.iter(|| <$ty as ssz_rs::Deserialize>::deserialize(black_box(&bytes)).unwrap())
            });
            group.bench_function(concat!("peam/", $name), |b| {
                b.iter(|| <$ty as PeamSszDecode>::decode_ssz(black_box(&bytes)).unwrap())
            });
        }};
    }

    bench_decode!("bool", bool, true);
    bench_decode!("u64", u64, 0x1234_5678_9ABC_DEF0u64);

    group.finish();
}

/// Compares decode speed for a fixed 32-byte value.
fn diff_peam_decode_bytes32(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/decode/bytes32");
    let bytes = pre_encode(&[0xABu8; 32]);

    group.bench_function("libssz/bytes32", |b| {
        b.iter(|| <[u8; 32] as LibSszDecode>::from_ssz_bytes(black_box(&bytes)).unwrap())
    });
    group.bench_function("lighthouse/bytes32", |b| {
        b.iter(|| <[u8; 32] as lighthouse_ssz::Decode>::from_ssz_bytes(black_box(&bytes)).unwrap())
    });
    group.bench_function("ssz_rs/bytes32", |b| {
        b.iter(|| <[u8; 32] as ssz_rs::Deserialize>::deserialize(black_box(&bytes)).unwrap())
    });
    group.bench_function("peam/bytes32", |b| {
        b.iter(|| PeamBytes32::decode_ssz(black_box(&bytes)).unwrap())
    });

    group.finish();
}

/// Compares large fixed-element list decode throughput at two practical sizes.
fn diff_peam_decode_vec_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/decode/vec_u64");
    for &size in &[1_000usize, 100_000] {
        let bytes = pre_encode(&make_vec_u64(size));
        group.throughput(Throughput::Bytes((size * 8) as u64));
        group.bench_with_input(BenchmarkId::new("libssz", size), &bytes, |b, bytes| {
            b.iter(|| <Vec<u64> as LibSszDecode>::from_ssz_bytes(black_box(bytes)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("lighthouse", size), &bytes, |b, bytes| {
            b.iter(|| {
                <Vec<u64> as lighthouse_ssz::Decode>::from_ssz_bytes(black_box(bytes)).unwrap()
            });
        });
        group.bench_with_input(BenchmarkId::new("ssz_rs", size), &bytes, |b, bytes| {
            b.iter(|| {
                <ssz_rs::List<u64, PEAM_VEC_LIMIT> as ssz_rs::Deserialize>::deserialize(black_box(
                    bytes,
                ))
                .unwrap()
            });
        });
        group.bench_with_input(BenchmarkId::new("peam", size), &bytes, |b, bytes| {
            b.iter(|| {
                PeamList::<u64, PEAM_VEC_LIMIT>::decode_ssz_checked(black_box(bytes)).unwrap()
            });
        });
    }
    group.finish();
}

/// Compares fixed-layout header decode throughput across implementations.
fn diff_peam_decode_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/decode/header");
    let bytes = pre_encode(&make_header(42));

    group.bench_function("libssz", |b| {
        b.iter(|| BeaconBlockHeader::from_ssz_bytes(black_box(&bytes)).unwrap())
    });
    group.bench_function("lighthouse", |b| {
        b.iter(|| lighthouse_decode_header(black_box(&bytes)))
    });
    group.bench_function("ssz_rs", |b| {
        b.iter(|| ssz_rs_decode_header(black_box(&bytes)))
    });
    group.bench_function("peam", |b| {
        b.iter(|| PeamBeaconBlockHeader::decode_ssz(black_box(&bytes)).unwrap())
    });

    group.finish();
}

/// Compares hash-tree-root performance for simple fixed-size values and the Peam header type.
fn diff_peam_htr(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/htr");

    let bool_value = true;
    group.bench_function("libssz/bool", |b| {
        b.iter(|| {
            LibHashTreeRoot::hash_tree_root(&black_box(bool_value), &libssz_merkle::Sha2Hasher)
        })
    });
    group.bench_function("lighthouse/bool", |b| {
        b.iter(|| tree_hash::TreeHash::tree_hash_root(black_box(&bool_value)).0)
    });
    group.bench_function("ssz_rs/bool", |b| {
        b.iter(|| {
            let mut value = *black_box(&bool_value);
            ssz_rs::Merkleized::hash_tree_root(&mut value).unwrap()
        })
    });
    group.bench_function("peam/bool", |b| {
        b.iter(|| PeamHashTreeRoot::hash_tree_root(&black_box(bool_value)))
    });

    let u64_value = 0x1234_5678_9ABC_DEF0u64;
    group.bench_function("libssz/u64", |b| {
        b.iter(|| {
            LibHashTreeRoot::hash_tree_root(&black_box(u64_value), &libssz_merkle::Sha2Hasher)
        })
    });
    group.bench_function("lighthouse/u64", |b| {
        b.iter(|| tree_hash::TreeHash::tree_hash_root(black_box(&u64_value)).0)
    });
    group.bench_function("ssz_rs/u64", |b| {
        b.iter(|| {
            let mut value = *black_box(&u64_value);
            ssz_rs::Merkleized::hash_tree_root(&mut value).unwrap()
        })
    });
    group.bench_function("peam/u64", |b| {
        b.iter(|| PeamHashTreeRoot::hash_tree_root(&black_box(u64_value)))
    });

    let bytes32_value = [0xABu8; 32];
    let peam_bytes32 = PeamBytes32::from(bytes32_value);
    group.bench_function("libssz/bytes32", |b| {
        b.iter(|| {
            LibHashTreeRoot::hash_tree_root(black_box(&bytes32_value), &libssz_merkle::Sha2Hasher)
        })
    });
    group.bench_function("lighthouse/bytes32", |b| {
        b.iter(|| tree_hash::TreeHash::tree_hash_root(black_box(&bytes32_value)).0)
    });
    group.bench_function("ssz_rs/bytes32", |b| {
        b.iter(|| {
            let mut value = *black_box(&bytes32_value);
            ssz_rs::Merkleized::hash_tree_root(&mut value).unwrap()
        })
    });
    group.bench_function("peam/bytes32", |b| b.iter(|| peam_bytes32.hash_tree_root()));

    let header = peam_header_from_fixture(&make_header(42));
    group.bench_function("peam/header", |b| {
        b.iter(|| black_box(&header).hash_tree_root())
    });

    group.finish();
}

/// Compares hash-tree-root performance for large fixed-element lists.
fn diff_peam_htr_vec_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/htr/vec_u64");
    for &size in &[1_000usize, 100_000] {
        let data = make_vec_u64(size);
        let ssz_rs = ssz_rs::List::<u64, PEAM_VEC_LIMIT>::try_from(data.clone()).unwrap();
        let peam = PeamList::<u64, PEAM_VEC_LIMIT>::new(data.clone()).unwrap();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("libssz", size), &data, |b, data| {
            b.iter(|| {
                LibHashTreeRoot::hash_tree_root(black_box(data), &libssz_merkle::Sha2Hasher)
            });
        });
        group.bench_with_input(BenchmarkId::new("ssz_rs", size), &ssz_rs, |b, data| {
            b.iter(|| {
                let mut value = black_box(data).clone();
                ssz_rs::Merkleized::hash_tree_root(&mut value).unwrap()
            });
        });
        group.bench_with_input(BenchmarkId::new("peam", size), &peam, |b, data| {
            b.iter(|| black_box(data).hash_tree_root());
        });
    }
    group.finish();
}

/// Compares the old branchy inner Merkle loop against the hoisted-tail version.
fn diff_peam_merkleize_internal(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_peam/hash_internal/merkleize");
    for &size in &[3usize, 5, 31, 32, 33, 255, 256, 257, 1023, 1024, 1025] {
        let chunks = make_chunks(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("old", size), &chunks, |b, chunks| {
            b.iter(|| merkleize_old(black_box(chunks)));
        });
        group.bench_with_input(BenchmarkId::new("new", size), &chunks, |b, chunks| {
            b.iter(|| merkleize_new(black_box(chunks)));
        });
        group.bench_with_input(BenchmarkId::new("crate", size), &chunks, |b, chunks| {
            b.iter(|| merkleize_unsafe(black_box(chunks)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    diff_peam_encode_primitives,
    diff_peam_encode_bytes32,
    diff_peam_encode_vec_u64,
    diff_peam_encode_var_list,
    diff_peam_encode_into_var_list,
    diff_peam_encode_header,
    diff_peam_decode_primitives,
    diff_peam_decode_bytes32,
    diff_peam_decode_vec_u64,
    diff_peam_decode_header,
    diff_peam_htr,
    diff_peam_htr_vec_u64,
    diff_peam_merkleize_internal,
);
criterion_main!(benches);
