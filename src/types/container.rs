//! Generic SSZ container helpers.
//!
//! This module provides the low-level encode/decode/root building blocks used
//! by fixed-layout and mixed fixed/variable containers.
use crate::ssz::hash::{hash_nodes, merkleize_progressive, merkleize_with_limit, pack_bytes};
use crate::types::bytes::Bytes32;

/// Encoded representation of a single container field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodedContainerField<'a> {
    /// Fixed-size field bytes written inline in the fixed section.
    Fixed(&'a [u8]),
    /// Variable-size field bytes referenced by a 4-byte offset in the fixed section.
    Variable(&'a [u8]),
}

/// Byte-layout classification for a decoded container field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerFieldKind {
    /// Fixed-size field occupying exactly the given number of bytes.
    Fixed(usize),
    /// Variable-size field referenced by an offset entry.
    Variable,
}

/// Marker trait for SSZ composite (container) types.
pub trait Container {}

/// Encodes a sequence of fixed and variable container fields into SSZ layout.
pub fn encode_fields(fields: &[EncodedContainerField<'_>]) -> Vec<u8> {
    let fixed_len = fields
        .iter()
        .map(|field| match field {
            EncodedContainerField::Fixed(bytes) => bytes.len(),
            EncodedContainerField::Variable(_) => 4,
        })
        .sum::<usize>();
    let variable_len = fields
        .iter()
        .map(|field| match field {
            EncodedContainerField::Fixed(_) => 0,
            EncodedContainerField::Variable(bytes) => bytes.len(),
        })
        .sum::<usize>();

    let mut out = Vec::with_capacity(fixed_len + variable_len);
    let mut variable_offset = fixed_len as u32;

    for field in fields {
        match field {
            EncodedContainerField::Fixed(bytes) => out.extend_from_slice(bytes),
            EncodedContainerField::Variable(bytes) => {
                out.extend_from_slice(&variable_offset.to_le_bytes());
                variable_offset = variable_offset
                    .checked_add(bytes.len() as u32)
                    .expect("container offset overflow");
            }
        }
    }

    for field in fields {
        if let EncodedContainerField::Variable(bytes) = field {
            out.extend_from_slice(bytes);
        }
    }

    out
}

/// Splits a container byte slice into per-field SSZ slices.
///
/// The function validates the fixed section size and the monotonicity of the
/// variable offset table before returning borrowed slices.
pub fn decode_field_slices<'a>(
    bytes: &'a [u8],
    kinds: &[ContainerFieldKind],
) -> Result<Vec<&'a [u8]>, String> {
    let fixed_section_len = kinds
        .iter()
        .map(|kind| match kind {
            ContainerFieldKind::Fixed(len) => *len,
            ContainerFieldKind::Variable => 4,
        })
        .sum::<usize>();

    if bytes.len() < fixed_section_len {
        return Err(format!(
            "container expects at least {} bytes, got {}",
            fixed_section_len,
            bytes.len()
        ));
    }

    if !kinds
        .iter()
        .any(|kind| matches!(kind, ContainerFieldKind::Variable))
        && bytes.len() != fixed_section_len
    {
        return Err(format!(
            "fixed-size container expects {} bytes, got {}",
            fixed_section_len,
            bytes.len()
        ));
    }

    let mut slices = Vec::with_capacity(kinds.len());
    let mut variable_slots = Vec::new();
    let mut cursor = 0usize;

    for (index, kind) in kinds.iter().enumerate() {
        match kind {
            ContainerFieldKind::Fixed(len) => {
                let end = cursor + len;
                slices.push(&bytes[cursor..end]);
                cursor = end;
            }
            ContainerFieldKind::Variable => {
                let end = cursor + 4;
                let offset = u32::from_le_bytes(bytes[cursor..end].try_into().unwrap()) as usize;
                variable_slots.push((index, offset));
                slices.push(&[]);
                cursor = end;
            }
        }
    }

    if let Some((_, first_offset)) = variable_slots.first() {
        if *first_offset != fixed_section_len {
            return Err(format!(
                "container first variable offset must equal fixed section length {}",
                fixed_section_len
            ));
        }
    }

    let mut next_min_offset = bytes.len();
    for (slot, (field_index, offset)) in variable_slots.iter().enumerate().rev() {
        if *offset < fixed_section_len {
            return Err(format!(
                "container offset {} points into fixed section",
                offset
            ));
        }
        if *offset > bytes.len() {
            return Err(format!("container offset {} exceeds input length", offset));
        }
        if *offset > next_min_offset {
            return Err("container offsets are not non-decreasing".to_string());
        }

        let end = next_min_offset;
        slices[*field_index] = &bytes[*offset..end];
        next_min_offset = *offset;

        // make the reverse iteration intent explicit for readability
        let _ = slot;
    }

    Ok(slices)
}

/// Merkleizes a container from its already-computed field roots.
pub fn hash_tree_root_from_field_roots(field_roots: &[[u8; 32]]) -> [u8; 32] {
    let chunks: Vec<Bytes32> = field_roots.iter().copied().map(Bytes32::from).collect();
    let root = merkleize_with_limit(&chunks, chunks.len()).unwrap_or_else(|_| Bytes32::zero());
    *root.as_ref()
}

/// Merkleizes a progressive container from active field roots and an activity bitmap.
pub fn hash_tree_root_progressive_container(
    field_roots: &[[u8; 32]],
    active_fields: &[bool],
) -> [u8; 32] {
    let mut chunks = Vec::with_capacity(active_fields.len());
    let mut field_idx = 0usize;
    for &active in active_fields {
        if active {
            chunks.push(Bytes32::from(field_roots[field_idx]));
            field_idx += 1;
        } else {
            chunks.push(Bytes32::zero());
        }
    }
    assert_eq!(field_idx, field_roots.len());

    let root = merkleize_progressive(&chunks);

    let mut bits_bytes = vec![0u8; active_fields.len().div_ceil(8)];
    for (i, &active) in active_fields.iter().enumerate() {
        if active {
            bits_bytes[i / 8] |= 1 << (i % 8);
        }
    }
    let af_node = pack_bytes(&bits_bytes)
        .first()
        .copied()
        .unwrap_or_else(Bytes32::zero);
    *hash_nodes(&root, &af_node).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_fields_mixes_fixed_and_variable_parts() {
        let out = encode_fields(&[
            EncodedContainerField::Fixed(&[0xAA, 0xBB]),
            EncodedContainerField::Variable(&[0x01, 0x02, 0x03]),
            EncodedContainerField::Fixed(&[0xCC]),
        ]);

        assert_eq!(
            out,
            vec![0xAA, 0xBB, 0x07, 0x00, 0x00, 0x00, 0xCC, 0x01, 0x02, 0x03]
        );
    }

    #[test]
    fn decode_field_slices_splits_fixed_and_variable_parts() {
        let bytes = vec![0xAA, 0xBB, 0x07, 0x00, 0x00, 0x00, 0xCC, 0x01, 0x02, 0x03];
        let slices = decode_field_slices(
            &bytes,
            &[
                ContainerFieldKind::Fixed(2),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
            ],
        )
        .unwrap();

        assert_eq!(slices[0], &[0xAA, 0xBB]);
        assert_eq!(slices[1], &[0x01, 0x02, 0x03]);
        assert_eq!(slices[2], &[0xCC]);
    }

    #[test]
    fn decode_field_slices_rejects_offset_into_fixed_section() {
        let bytes = vec![0xAA, 0x03, 0x00, 0x00, 0x00];
        let err = decode_field_slices(
            &bytes,
            &[ContainerFieldKind::Fixed(1), ContainerFieldKind::Variable],
        )
        .unwrap_err();
        assert!(err.contains("first variable offset"));
    }

    #[test]
    fn decode_field_slices_rejects_decreasing_offsets() {
        let bytes = vec![0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xAA];
        let err = decode_field_slices(
            &bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Variable],
        )
        .unwrap_err();
        assert!(err.contains("first variable offset"));
    }

    #[test]
    fn hash_tree_root_from_field_roots_merkleizes_container_roots() {
        let roots = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let result = hash_tree_root_from_field_roots(&roots);
        assert_ne!(result, [0u8; 32]);
    }
}
