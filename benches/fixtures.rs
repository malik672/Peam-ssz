//! Minimal benchmark fixtures for `peam-ssz`.
//!
//! Adapted from the `libssz` benchmark harness in:
//! `libssz/benches/src/fixtures.rs`

use libssz::SszEncode;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

/// Ethereum consensus BeaconBlockHeader (112 bytes, all fixed-size fields).
#[derive(Clone, Debug, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

/// Builds a deterministic fixed-layout header so every library sees identical input.
pub fn make_header(seed: u64) -> BeaconBlockHeader {
    let mut parent_root = [0u8; 32];
    let mut state_root = [0u8; 32];
    let mut body_root = [0u8; 32];
    for (i, chunk) in parent_root.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_add(i as u64).to_le_bytes());
    }
    for (i, chunk) in state_root.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_mul(7).wrapping_add(i as u64).to_le_bytes());
    }
    for (i, chunk) in body_root.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_mul(13).wrapping_add(i as u64).to_le_bytes());
    }
    BeaconBlockHeader {
        slot: seed,
        proposer_index: seed.wrapping_mul(3),
        parent_root,
        state_root,
        body_root,
    }
}

/// Builds a simple ascending `Vec<u64>` for list encode/decode throughput checks.
pub fn make_vec_u64(n: usize) -> Vec<u64> {
    (0..n).map(|i| i as u64).collect()
}

/// Builds a deterministic nested list so Peam exercises the variable-size list path.
pub fn make_nested_vec_u64(outer: usize, inner: usize) -> Vec<Vec<u64>> {
    (0..outer)
        .map(|i| {
            (0..inner)
                .map(|j| (i as u64).wrapping_mul(1_000_003).wrapping_add(j as u64))
                .collect()
        })
        .collect()
}

/// Encodes a reference value once so decode benches do not measure setup work.
pub fn pre_encode<T: SszEncode>(value: &T) -> Vec<u8> {
    value.to_ssz()
}
