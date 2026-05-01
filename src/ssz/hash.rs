//! Low-level SSZ hashing and merkleization utilities.
//!
//! This module contains the chunking and tree-building primitives used by
//! containers, collections, bitfields, and progressive types.
use super::SszEncode;
use sha2::{
    compress256,
    digest::generic_array::GenericArray,
};

use crate::types::bytes::Bytes32;
use crate::unsafe_vec::write_at;

include!(concat!(env!("OUT_DIR"), "/zero_hashes.rs"));

/// Size of a single SSZ Merkle chunk in bytes.
pub const BYTES_PER_CHUNK: usize = 32;

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_PAD_BLOCK_512: [u8; 64] = {
    let mut block = [0u8; 64];
    block[0] = 0x80;
    block[62] = 0x02;
    block[63] = 0x00;
    block
};

/// Hashes two already-chunked nodes into their parent Merkle node.
#[inline]
pub fn hash_nodes(left: &Bytes32, right: &Bytes32) -> Bytes32 {
    let mut state = SHA256_IV;

    let mut first_block = GenericArray::default();
    first_block[..BYTES_PER_CHUNK].copy_from_slice(&left.as_array());
    first_block[BYTES_PER_CHUNK..].copy_from_slice(&right.as_array());

    let second_block = GenericArray::from(SHA256_PAD_BLOCK_512);
    let blocks = [first_block, second_block];
    compress256(&mut state, &blocks);

    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    Bytes32::from(out)
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

#[inline]
fn append_subtree(partials: &mut Vec<Option<Bytes32>>, mut level: usize, mut node: Bytes32) {
    loop {
        if level == partials.len() {
            partials.push(Some(node));
            return;
        }
        if let Some(left) = partials[level].take() {
            node = hash_nodes(&left, &node);
            level += 1;
            continue;
        }
        partials[level] = Some(node);
        return;
    }
}

#[inline]
fn merkleize_owned(mut level: Vec<Bytes32>, limit: usize) -> Result<Bytes32, String> {
    if limit < level.len() {
        return Err("merkleize limit smaller than input".to_string());
    }
    if limit == 0 {
        return Ok(Bytes32::zero());
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }

    if level.is_empty() {
        return Ok(zero_tree_root_no_check(width));
    }
    if width == 1 {
        return Ok(level[0]);
    }

    let mut subtree_size = 1usize;
    while subtree_size < width {
        let active = level.len();
        let mut read = 0usize;
        let mut write = 0usize;
        while read + 1 < active {
            let left = level[read];
            let right = level[read + 1];
            level[write] = hash_nodes(&left, &right);
            read += 2;
            write += 1;
        }
        if read != active {
            let left = level[read];
            level[write] = hash_nodes(&left, &zero_tree_root_no_check(subtree_size));
            write += 1;
        }
        level.truncate(write);
        subtree_size <<= 1;
    }

    Ok(level[0])
}

#[inline]
pub(crate) fn merkleize_owned_with_limit(level: Vec<Bytes32>, limit: usize) -> Result<Bytes32, String> {
    merkleize_owned(level, limit)
}

#[inline]
pub(crate) fn merkleize_packed_basic_with_limit<T>(
    items: &[T],
    elem_len: usize,
    limit: usize,
) -> Result<Bytes32, String>
where
    T: SszEncode,
{
    if limit == 0 {
        return Ok(Bytes32::zero());
    }
    if elem_len > BYTES_PER_CHUNK {
        let total = items
            .len()
            .checked_mul(elem_len)
            .expect("packed basic total length overflows usize");
        let mut bytes = Vec::with_capacity(total);
        for item in items {
            item.encode_ssz_into(&mut bytes);
        }
        let chunks = chunkify_fixed_non_empty(&bytes);
        return merkleize_owned(chunks, limit);
    }

    let total = items
        .len()
        .checked_mul(elem_len)
        .expect("packed basic total length overflows usize");
    let chunk_count = total.div_ceil(BYTES_PER_CHUNK);
    if limit < chunk_count {
        return Err("merkleize limit smaller than input".to_string());
    }

    let mut width = 1usize;
    while width < limit {
        width <<= 1;
    }
    if chunk_count == 0 {
        return Ok(zero_tree_root_no_check(width));
    }

    let max_level = width.trailing_zeros() as usize;
    let mut partials = vec![None; max_level + 1];
    let mut chunk = [0u8; 32];
    let mut filled = 0usize;
    let mut leaves = 0usize;

    for item in items {
        let space = BYTES_PER_CHUNK - filled;
        if elem_len <= space {
            unsafe { item.write_fixed_ssz(chunk.as_mut_ptr().add(filled)) };
            filled += elem_len;
            if filled == BYTES_PER_CHUNK {
                append_subtree(&mut partials, 0, Bytes32::from(chunk));
                chunk = [0u8; 32];
                filled = 0;
                leaves += 1;
            }
            continue;
        }

        let mut elem_buf = [0u8; 32];
        unsafe { item.write_fixed_ssz(elem_buf.as_mut_ptr()) };
        let mut src_start = 0usize;
        while src_start < elem_len {
            let space = BYTES_PER_CHUNK - filled;
            let to_copy = (elem_len - src_start).min(space);
            chunk[filled..filled + to_copy]
                .copy_from_slice(&elem_buf[src_start..src_start + to_copy]);
            filled += to_copy;
            src_start += to_copy;

            if filled == BYTES_PER_CHUNK {
                append_subtree(&mut partials, 0, Bytes32::from(chunk));
                chunk = [0u8; 32];
                filled = 0;
                leaves += 1;
            }
        }
    }

    if filled != 0 {
        append_subtree(&mut partials, 0, Bytes32::from(chunk));
        leaves += 1;
    }

    let mut remaining = width - leaves;
    let mut level = 0usize;
    while remaining != 0 {
        if remaining & 1 == 1 {
            append_subtree(
                &mut partials,
                level,
                zero_tree_root_no_check(1usize << level),
            );
        }
        remaining >>= 1;
        level += 1;
    }

    partials
        .into_iter()
        .rev()
        .flatten()
        .next()
        .ok_or_else(|| "merkleize limit smaller than input".to_string())
}

/// Merkleizes a chunk list with minimal checks.
///
/// This follows the same result as [`merkleize_with_limit`] when the caller is
/// already sure the chunk slice is valid and the limit is exactly `chunks.len()`.
#[inline]
pub fn merkleize_unsafe(chunks: &[Bytes32]) -> Bytes32 {
    merkleize_owned(chunks.to_vec(), chunks.len()).unwrap()
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
    merkleize_owned(chunks.to_vec(), limit)
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
    use sha2::{Digest, Sha256};

    fn bytes32(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    #[test]
    fn hash_nodes_zero_pair_matches_first_zero_hash() {
        let zero = Bytes32::zero();
        assert_eq!(hash_nodes(&zero, &zero), Bytes32::from(ZERO_HASHES[1]));
    }

    #[test]
    fn merkleize_packed_basic_matches_chunked_path_for_u64() {
        let items = [1u64, 2, 3, 4, 5];

        let mut bytes = Vec::new();
        for item in items {
            bytes.extend_from_slice(&item.to_le_bytes());
        }
        let chunks = chunkify_fixed_non_empty(&bytes);
        let expected = merkleize_with_limit(&chunks, 4).unwrap();

        assert_eq!(
            merkleize_packed_basic_with_limit(&items, 8, 4).unwrap(),
            expected
        );
    }

    #[test]
    fn merkleize_packed_basic_matches_chunked_path_for_bytes32() {
        let items = [bytes32(0x11), bytes32(0x22), bytes32(0x33)];

        let chunks: Vec<Bytes32> = items.into_iter().collect();
        let expected = merkleize_with_limit(&chunks, 4).unwrap();

        assert_eq!(
            merkleize_packed_basic_with_limit(&items, 32, 4).unwrap(),
            expected
        );
    }

    #[test]
    fn hash_nodes_matches_sha256_digest_of_concat() {
        let left = bytes32(0x11);
        let right = bytes32(0x22);

        let mut expected_input = [0u8; 64];
        expected_input[..32].copy_from_slice(&left.as_array());
        expected_input[32..].copy_from_slice(&right.as_array());
        let expected = Sha256::digest(expected_input);

        assert_eq!(hash_nodes(&left, &right), Bytes32::from_slice(&expected));
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
        assert_eq!(
            merkleize_progressive(&[chunk]),
            hash_nodes(&Bytes32::zero(), &chunk)
        );
    }
}
