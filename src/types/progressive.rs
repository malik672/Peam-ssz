//! Progressive SSZ collection types.
//!
//! These helpers model the progressive merkleization rules used by EIP-7916.
use crate::ssz::hash::{merkleize_progressive, mix_in_length, pack_bytes};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode};
use crate::types::bytes::Bytes32;
use crate::unsafe_vec::{write_at, write_bytes_at};

/// Progressive SSZ list.
///
/// Encoding matches the normal SSZ list rules, but `hash_tree_root` uses
/// progressive merkleization instead of the standard bounded Merkle tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgressiveList<T> {
    /// Backing elements in SSZ order.
    pub data: Vec<T>,
}

impl<T> ProgressiveList<T> {
    /// Wraps already-owned list data.
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }
}

impl<T> SszEncode for ProgressiveList<T>
where
    T: SszEncode + SszElement,
{
    /// Encodes the list using standard SSZ list layout rules.
    fn encode_ssz(&self) -> Vec<u8> {
        if let Some(elem_len) = T::fixed_len_opt() {
            let total = elem_len * self.data.len();
            let mut out = Vec::with_capacity(total);
            unsafe { out.set_len(total) };
            let mut cursor = 0usize;
            for item in &self.data {
                let bytes = item.encode_ssz();
                unsafe { write_bytes_at(&mut out, cursor, &bytes) };
                cursor += bytes.len();
            }
            return out;
        }

        let count = self.data.len();
        let mut offsets = Vec::with_capacity(count);
        let mut elems = Vec::with_capacity(count);
        let mut cursor = 4 * count;
        for item in &self.data {
            let bytes = item.encode_ssz();
            offsets.push(cursor as u32);
            cursor += bytes.len();
            elems.push(bytes);
        }
        let mut out = Vec::with_capacity(cursor);
        unsafe { out.set_len(cursor) };
        let mut cursor = 0usize;
        for off in offsets {
            unsafe { write_bytes_at(&mut out, cursor, &off.to_le_bytes()) };
            cursor += 4;
        }
        for bytes in elems {
            unsafe { write_bytes_at(&mut out, cursor, &bytes) };
            cursor += bytes.len();
        }
        out
    }

    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        if let Some(elem_len) = T::fixed_len_opt() {
            let total = elem_len * self.data.len();
            let start = out.len();
            out.reserve(total);
            unsafe { out.set_len(start + total) };
            for (idx, item) in self.data.iter().enumerate() {
                let offset = start + idx * elem_len;
                unsafe { item.write_fixed_ssz(out.as_mut_ptr().add(offset)) };
            }
            return;
        }

        let count = self.data.len();
        let table_start = out.len();
        let table_len = 4 * count;
        out.reserve(table_len);
        unsafe { out.set_len(table_start + table_len) };
        for (idx, item) in self.data.iter().enumerate() {
            let offset = (out.len() - table_start) as u32;
            unsafe { write_bytes_at(out, table_start + idx * 4, &offset.to_le_bytes()) };
            item.encode_ssz_into(out);
        }
    }

    unsafe fn write_fixed_ssz(&self, _dst: *mut u8) {
        panic!("ProgressiveList is variable-size and cannot be written via write_fixed_ssz");
    }
}

impl<T> SszDecode for ProgressiveList<T>
where
    T: SszDecode + SszElement,
{
    /// Decodes the list from standard SSZ list layout.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if let Some(elem_len) = T::fixed_len_opt() {
            if elem_len == 0 || !bytes.len().is_multiple_of(elem_len) {
                return Err("ProgressiveList length is not a multiple of element size".to_string());
            }
            let len = bytes.len() / elem_len;
            let mut data = Vec::with_capacity(len);
            unsafe { data.set_len(len) };
            for i in 0..len {
                let start = i * elem_len;
                let end = start + elem_len;
                let x = match T::decode_ssz(&bytes[start..end]) {
                    Ok(val) => val,
                    Err(err) => {
                        unsafe {
                            let ptr: *mut T = data.as_mut_ptr();
                            for j in 0..i {
                                core::ptr::drop_in_place(ptr.add(j));
                            }
                            data.set_len(0);
                        }
                        return Err(err);
                    }
                };
                unsafe { write_at(&mut data, i, x) };
            }
            return Ok(Self { data });
        }

        if bytes.is_empty() {
            return Ok(Self { data: Vec::new() });
        }
        if bytes.len() < 4 {
            return Err("ProgressiveList missing offset table".to_string());
        }

        let first = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if !first.is_multiple_of(4) {
            return Err("ProgressiveList first offset must be multiple of 4".to_string());
        }
        if first > bytes.len() {
            return Err("ProgressiveList offset table exceeds input length".to_string());
        }
        let len = first / 4;

        let mut prev = first;
        for i in 1..len {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let off = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            if off < prev || off > bytes.len() {
                return Err("ProgressiveList offsets are invalid".to_string());
            }
            prev = off;
        }

        let mut data = Vec::with_capacity(len);
        unsafe { data.set_len(len) };
        for i in 0..len {
            let off_start = i * 4;
            let off_end = off_start + 4;
            let start = u32::from_le_bytes(bytes[off_start..off_end].try_into().unwrap()) as usize;
            let end = if i + 1 < len {
                let next_start = (i + 1) * 4;
                let next_end = next_start + 4;
                u32::from_le_bytes(bytes[next_start..next_end].try_into().unwrap()) as usize
            } else {
                bytes.len()
            };
            let x = match T::decode_ssz(&bytes[start..end]) {
                Ok(val) => val,
                Err(err) => {
                    unsafe {
                        let ptr: *mut T = data.as_mut_ptr();
                        for j in 0..i {
                            core::ptr::drop_in_place(ptr.add(j));
                        }
                        data.set_len(0);
                    }
                    return Err(err);
                }
            };
            unsafe { write_at(&mut data, i, x) };
        }
        Ok(Self { data })
    }
}

impl<T> HashTreeRoot for ProgressiveList<T>
where
    T: SszEncode + SszElement + HashTreeRoot,
{
    /// Computes the progressive list root and mixes in the current length.
    fn hash_tree_root(&self) -> [u8; 32] {
        let chunks: Vec<Bytes32> = if T::tree_pack_basic() {
            let bytes = self.encode_ssz();
            pack_bytes(&bytes)
        } else {
            self.data
                .iter()
                .map(|item| Bytes32::from(item.hash_tree_root()))
                .collect()
        };
        let root = merkleize_progressive(&chunks);
        let mixed = mix_in_length(&root, self.data.len());
        *mixed.as_ref()
    }
}

impl<T> SszElement for ProgressiveList<T> {}

/// Progressive SSZ bitlist.
///
/// Wire encoding matches a normal bitlist with a terminator bit, but
/// `hash_tree_root` uses progressive merkleization over packed chunks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgressiveBitlist {
    /// Packed little-endian bit storage without the terminator bit.
    pub data: Vec<u8>,
    /// Logical number of bits represented in `data`.
    pub len: usize,
}

impl ProgressiveBitlist {
    /// Packs a boolean vector into progressive bitlist storage.
    pub fn new(data: Vec<bool>) -> Self {
        let len = data.len();
        let byte_len = len.div_ceil(8);
        let mut packed = vec![0u8; byte_len];
        for (i, bit) in data.iter().enumerate() {
            if *bit {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        Self { data: packed, len }
    }

    fn pack_bits_with_terminator(&self) -> Vec<u8> {
        let out_len = (self.len + 1).div_ceil(8);
        let mut out = vec![0u8; out_len];
        let copy_len = self.data.len().min(out_len);
        out[..copy_len].copy_from_slice(&self.data[..copy_len]);
        let term_index = self.len;
        out[term_index / 8] |= 1u8 << (term_index % 8);
        out
    }

    fn unpack_bits_with_terminator(bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
        if bytes.is_empty() {
            return Err("bitlist missing length marker".to_string());
        }
        let last_byte = *bytes.last().unwrap();
        if last_byte == 0 {
            return Err("bitlist missing length marker".to_string());
        }

        let highest_bit = 7 - last_byte.leading_zeros() as usize;
        let bit_len = (bytes.len() - 1) * 8 + highest_bit;

        let mut data = bytes.to_vec();
        let needed_bytes = bit_len.div_ceil(8);
        data.truncate(needed_bytes);
        if needed_bytes == bytes.len() && !data.is_empty() {
            data[needed_bytes - 1] &= !(1 << highest_bit);
        }
        Ok((data, bit_len))
    }
}

impl SszEncode for ProgressiveBitlist {
    /// Encodes the bitlist with the SSZ terminator bit.
    fn encode_ssz(&self) -> Vec<u8> {
        self.pack_bits_with_terminator()
    }

    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        let bytes = (self.len + 1).div_ceil(8);
        out.resize(start + bytes, 0);
        let copy_len = self.data.len().min(bytes);
        out[start..start + copy_len].copy_from_slice(&self.data[..copy_len]);
        let term_index = self.len;
        out[start + term_index / 8] |= 1u8 << (term_index % 8);
    }

    unsafe fn write_fixed_ssz(&self, _dst: *mut u8) {
        panic!("ProgressiveBitlist is variable-size and cannot be written via write_fixed_ssz");
    }
}

impl SszDecode for ProgressiveBitlist {
    /// Decodes the bitlist from its SSZ terminator representation.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (data, len) = Self::unpack_bits_with_terminator(bytes)?;
        Ok(Self { data, len })
    }
}

impl HashTreeRoot for ProgressiveBitlist {
    /// Computes the progressive bitlist root and mixes in the logical bit length.
    fn hash_tree_root(&self) -> [u8; 32] {
        let chunks = pack_bytes(&self.data);
        let root = merkleize_progressive(&chunks);
        let mixed = mix_in_length(&root, self.len);
        *mixed.as_ref()
    }
}

impl SszElement for ProgressiveBitlist {}
