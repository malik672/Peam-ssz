//! Low-level SSZ hashing and merkleization utilities.
//!
//! This module contains the chunking and tree-building primitives used by
//! containers, collections, bitfields, and progressive types.
use sha2::{Digest, Sha256};

use crate::types::bytes::Bytes32;
use crate::unsafe_vec::write_at;

include!(concat!(env!("OUT_DIR"), "/zero_hashes.rs"));

/// Size of a single SSZ Merkle chunk in bytes.
pub const BYTES_PER_CHUNK: usize = 32;

/// Hashes two already-chunked nodes into their parent Merkle node.
#[inline]
pub fn hash_nodes(left: &Bytes32, right: &Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(left.as_array());
    hasher.update(right.as_array());
    let out = hasher.finalize();
    // Extract the first 32 bytes and return it as Bytes32.
    // We can optimize this later with a direct wrap/ptr, if needed.
    Bytes32::from_slice(&out)
}

/// Splits fixed bytes into 32-byte chunks, zero-padding the tail chunk.
#[inline]
pub fn chunkify_fixed(data: &[u8]) -> Vec<Bytes32> {
    if data.is_empty() {
        return vec![Bytes32::zero()];
    }
    chunkify_fixed_non_empty(data)
}

/// Splits a non-empty fixed byte slice into 32-byte chunks, zero-padding the
/// tail chunk.
#[inline]
pub fn chunkify_fixed_non_empty(data: &[u8]) -> Vec<Bytes32> {
    debug_assert!(!data.is_empty());

    // This is at most 32
    let chunk_count = (data.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
    let mut out: Vec<Bytes32> = Vec::with_capacity(chunk_count);
    unsafe { out.set_len(chunk_count) };
    let mut i = 0usize;
    let mut out_idx = 0usize;
    while i < data.len() {
        let end = (i + BYTES_PER_CHUNK).min(data.len());
        let mut chunk = [0u8; 32];
        chunk[..end - i].copy_from_slice(&data[i..end]);
        unsafe { write_at(&mut out, out_idx, Bytes32::from(chunk)) };
        out_idx += 1;
        i = end;
    }
    out
}

/// Packs bytes into SSZ chunks for basic-value merkleization.
#[inline]
pub fn pack_bytes(data: &[u8]) -> Vec<Bytes32> {
    if data.is_empty() {
        return Vec::new();
    }
    chunkify_fixed_non_empty(data)
}

/// Merkleizes a chunk list using the chunk count as the width limit.
#[inline]
pub fn merkleize(chunks: &[Bytes32]) -> Bytes32 {
    merkleize_with_limit(chunks, chunks.len()).unwrap()
}

/// Merkleizes a chunk list with minimal checks.
///
/// This follows the same result as [`merkleize_with_limit`] when the caller is
/// already sure the chunk slice is valid and the limit is exactly `chunks.len()`.
#[inline]
pub fn merkleize_unsafe(chunks: &[Bytes32]) -> Bytes32 {
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
        let next_len = (level.len() + 1) / 2;
        let mut next: Vec<Bytes32> = Vec::with_capacity(next_len);
        unsafe { next.set_len(next_len) };
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i + 1 < level.len() {
            let left = &level[i];
            let right = &level[i + 1];
            unsafe { write_at(&mut next, out_idx, hash_nodes(left, right)) };
            i += 2;
            out_idx += 1;
        }
        if i != level.len() {
            let left = &level[i];
            unsafe {
                write_at(
                    &mut next,
                    out_idx,
                    hash_nodes(left, &zero_tree_root_no_check(subtree_size)),
                )
            };
        }
        level = next;
        subtree_size <<= 1;
    }

    level[0]
}

/// Specialized merkleization for exactly 5 field roots.
///
/// This matches the fixed-width tree shape used by 5-field containers such as
/// `BeaconBlockHeader`.
#[inline]
pub fn merkleize_tree_root(chunks: &[Bytes32]) -> Bytes32 {
    // width fixed to 8 for 5 field roots
    let z0 = zero_tree_root_no_check(1);
    let z1: Bytes32 = zero_tree_root_no_check(2);

    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &chunks[3]);
    let c = hash_nodes(&chunks[4], &z0);
    let d = z1;

    let e = hash_nodes(&a, &b);
    let f = hash_nodes(&c, &d);
    hash_nodes(&e, &f)
}

/// Specialized merkleization for exactly 4 field roots.
#[inline]
pub fn merkleize_tree_root_4(chunks: &[Bytes32]) -> Bytes32 {
    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &chunks[3]);
    hash_nodes(&a, &b)
}

/// Specialized merkleization for exactly 3 field roots.
#[inline]
pub fn merkleize_tree_root_3(chunks: &[Bytes32]) -> Bytes32 {
    let z0 = zero_tree_root_no_check(1);

    let a = hash_nodes(&chunks[0], &chunks[1]);
    let b = hash_nodes(&chunks[2], &z0);
    hash_nodes(&a, &b)
}

/// Specialized merkleization for exactly 11 field roots.
#[inline]
pub fn merkleize_tree_root_11(chunks: &[Bytes32]) -> Bytes32 {
    let z0 = zero_tree_root_no_check(1);
    let z1 = zero_tree_root_no_check(2);

    let h0 = hash_nodes(&chunks[0], &chunks[1]);
    let h1 = hash_nodes(&chunks[2], &chunks[3]);
    let h2 = hash_nodes(&chunks[4], &chunks[5]);
    let h3 = hash_nodes(&chunks[6], &chunks[7]);
    let h4 = hash_nodes(&chunks[8], &chunks[9]);
    let h5 = hash_nodes(&chunks[10], &z0);
    let h6 = z1;
    let h7 = z1;

    let k0 = hash_nodes(&h0, &h1);
    let k1 = hash_nodes(&h2, &h3);
    let k2 = hash_nodes(&h4, &h5);
    let k3 = hash_nodes(&h6, &h7);

    let m0 = hash_nodes(&k0, &k1);
    let m1 = hash_nodes(&k2, &k3);
    hash_nodes(&m0, &m1)
}

/// Merkleizes `chunks` against an explicit SSZ width limit.
///
/// This is the general-purpose entry point used by collection and container
/// types. `limit` is expressed in chunks, not bytes.
#[inline]
pub fn merkleize_with_limit(chunks: &[Bytes32], limit: usize) -> Result<Bytes32, String> {
    if limit < chunks.len() {
        return Err("merkleize limit smaller than input".to_string());
    }
    if limit == 0 {
        return Ok(Bytes32::zero());
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if chunks.is_empty() {
        return Ok(zero_tree_root_no_check(width));
    }
    if width == 1 {
        return Ok(chunks[0]);
    }

    let mut level: Vec<Bytes32> = chunks.to_vec();
    let mut subtree_size = 1usize;

    while subtree_size < width {
        let next_len = (level.len() + 1) / 2;
        let mut next: Vec<Bytes32> = Vec::with_capacity(next_len);
        unsafe { next.set_len(next_len) };
        let mut i = 0usize;
        let mut out_idx = 0usize;
        while i + 1 < level.len() {
            let left = &level[i];
            unsafe {
                write_at(&mut next, out_idx, hash_nodes(left, &level[i + 1]));
                // safety: level.len() is bound by usize::MAX and based on the iteration pattern, out_idx will always be less than next_len.
                out_idx = out_idx.unchecked_add(1);
                i = i.unchecked_add(2);
            };
        }
        if i != level.len() {
            let left = &level[i];
            unsafe {
                write_at(
                    &mut next,
                    out_idx,
                    hash_nodes(left, &zero_tree_root_no_check(subtree_size)),
                );
            };
        }
        level = next;
        subtree_size <<= 1;
    }

    Ok(level[0])
}

/// Merkleizes a progressive chunk sequence using the EIP-7916 tree shape.
#[inline]
pub fn merkleize_progressive(chunks: &[Bytes32]) -> Bytes32 {
    merkleize_progressive_inner(chunks, 1)
}

/// Recursive worker for progressive merkleization.
fn merkleize_progressive_inner(chunks: &[Bytes32], num_leaves: usize) -> Bytes32 {
    if chunks.is_empty() {
        return Bytes32::zero();
    }

    let take = num_leaves.min(chunks.len());
    let subtree =
        merkleize_with_limit(&chunks[..take], num_leaves).unwrap_or_else(|_| Bytes32::zero());
    let rest = merkleize_progressive_inner(&chunks[take..], num_leaves * 4);
    hash_nodes(&rest, &subtree)
}

/// Mixes a list length into an existing SSZ root.
#[inline]
pub fn mix_in_length(root: &Bytes32, length: usize) -> Bytes32 {
    let mut length_bytes = [0u8; 32];
    let len_u64 = length as u64;
    length_bytes[..8].copy_from_slice(&len_u64.to_le_bytes());
    let length_node = Bytes32::from(length_bytes);
    hash_nodes(root, &length_node)
}

/// Mixes a union selector into an existing SSZ root.
#[inline]
pub fn mix_in_selector(root: &Bytes32, selector: u8) -> Bytes32 {
    let mut selector_bytes = [0u8; 32];
    selector_bytes[0] = selector;
    let selector_node = Bytes32::from(selector_bytes);
    hash_nodes(root, &selector_node)
}

/// Returns the cached zero root for an exact power-of-two chunk width.
#[inline]
fn zero_tree_root_no_check(width: usize) -> Bytes32 {
    let depth = width.trailing_zeros() as usize;
    let bytes = ZERO_HASHES[depth];
    Bytes32::from(bytes)
}

#[inline]
fn _zero_tree_root(width: usize) -> Bytes32 {
    if width <= 1 {
        return Bytes32::zero();
    }
    let depth = width.trailing_zeros() as usize;
    let bytes = ZERO_HASHES[depth];
    Bytes32::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes32(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    #[test]
    fn hash_nodes_zero_pair_matches_first_zero_hash() {
        let zero = Bytes32::zero();
        assert_eq!(hash_nodes(&zero, &zero), Bytes32::from(ZERO_HASHES[1]));
    }

    #[test]
    fn chunkify_fixed_empty_returns_single_zero_chunk() {
        assert_eq!(chunkify_fixed(&[]), vec![Bytes32::zero()]);
    }

    #[test]
    fn chunkify_fixed_pads_partial_tail() {
        let chunks = chunkify_fixed(&[1, 2, 3, 4, 5]);
        assert_eq!(chunks.len(), 1);

        let mut expected = [0u8; 32];
        expected[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(chunks[0], Bytes32::from(expected));
    }

    #[test]
    fn merkleize_with_limit_rejects_small_limit() {
        let chunks = vec![bytes32(1), bytes32(2)];
        assert!(merkleize_with_limit(&chunks, 1).is_err());
    }

    #[test]
    fn merkleize_with_limit_empty_returns_zero_root_for_width() {
        assert_eq!(
            merkleize_with_limit(&[], 1).unwrap(),
            Bytes32::from(ZERO_HASHES[0])
        );
        assert_eq!(
            merkleize_with_limit(&[], 8).unwrap(),
            Bytes32::from(ZERO_HASHES[3])
        );
    }

    #[test]
    fn merkleize_single_chunk_is_identity() {
        let chunk = bytes32(7);
        assert_eq!(merkleize_with_limit(&[chunk], 1).unwrap(), chunk);
    }

    #[test]
    fn specialized_tree_root_3_matches_generic_merkleize() {
        let chunks = vec![bytes32(1), bytes32(2), bytes32(3)];
        assert_eq!(
            merkleize_tree_root_3(&chunks),
            merkleize_with_limit(&chunks, 4).unwrap()
        );
    }

    #[test]
    fn specialized_tree_root_4_matches_generic_merkleize() {
        let chunks = vec![bytes32(1), bytes32(2), bytes32(3), bytes32(4)];
        assert_eq!(
            merkleize_tree_root_4(&chunks),
            merkleize_with_limit(&chunks, 4).unwrap()
        );
    }

    #[test]
    fn specialized_tree_root_11_matches_generic_merkleize() {
        let chunks: Vec<_> = (0..11).map(|i| bytes32(i as u8)).collect();
        assert_eq!(
            merkleize_tree_root_11(&chunks),
            merkleize_with_limit(&chunks, 16).unwrap()
        );
    }

    #[test]
    fn mix_in_length_hashes_root_with_length_node() {
        let root = bytes32(9);
        let mut length_bytes = [0u8; 32];
        length_bytes[..8].copy_from_slice(&(42u64).to_le_bytes());
        let expected = hash_nodes(&root, &Bytes32::from(length_bytes));

        assert_eq!(mix_in_length(&root, 42), expected);
    }

    #[test]
    fn mix_in_selector_hashes_root_with_selector_node() {
        let root = bytes32(9);
        let mut selector_bytes = [0u8; 32];
        selector_bytes[0] = 3;
        let expected = hash_nodes(&root, &Bytes32::from(selector_bytes));

        assert_eq!(mix_in_selector(&root, 3), expected);
    }

    #[test]
    fn progressive_merkleize_empty_is_zero() {
        assert_eq!(merkleize_progressive(&[]), Bytes32::zero());
    }

    #[test]
    fn progressive_merkleize_single_chunk_is_identity() {
        let chunk = bytes32(7);
        assert_eq!(merkleize_progressive(&[chunk]), hash_nodes(&Bytes32::zero(), &chunk));
    }
}
