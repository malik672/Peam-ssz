//! SSZ bitlist and bitvector helpers.
use crate::ssz::hash::{BYTES_PER_CHUNK, chunkify_fixed, merkleize_with_limit, mix_in_length};
use crate::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode};
use crate::types::bytes::Bytes32;

/// Variable-length bitfield bounded by `LIMIT` bits.
///
/// Backed by packed `Vec<u8>` with the bit count tracked in `len`.
/// SSZ wire format appends a sentinel 1-bit after the last data bit to encode
/// the logical length. `hash_tree_root` merkleizes the packed bytes (without
/// the sentinel) to `ceil(LIMIT / 256)` chunk leaves, then mixes in `len`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitList<const LIMIT: usize> {
    /// Packed little-endian bit storage without the SSZ terminator bit.
    pub data: Vec<u8>,
    /// Logical number of bits represented in `data`.
    pub len: usize,
}

impl<const LIMIT: usize> Default for BitList<LIMIT> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            len: 0,
        }
    }
}

impl<const LIMIT: usize> BitList<LIMIT> {
    /// Packs a boolean vector into SSZ bitlist storage.
    pub fn new(data: Vec<bool>) -> Result<Self, String> {
        let len = data.len();
        if len > LIMIT {
            return Err(format!("BitList length {} exceeds limit {}", len, LIMIT));
        }
        let byte_len = len.div_ceil(8);
        let mut packed = vec![0u8; byte_len];
        for (i, bit) in data.iter().enumerate() {
            if *bit {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        Ok(Self { data: packed, len })
    }

    #[inline]
    fn pack_bits_with_terminator(&self) -> Vec<u8> {
        let out_len = (self.len + 1).div_ceil(8);
        let mut out = vec![0u8; out_len];
        let copy_len = self.data.len().min(out_len);
        out[..copy_len].copy_from_slice(&self.data[..copy_len]);
        let term_index = self.len;
        out[term_index / 8] |= 1u8 << (term_index % 8);
        out
    }

    #[inline]
    fn unpack_bits_with_terminator(bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
        if bytes.last().copied() == Some(0) {
            return Err("bitlist has trailing zero byte".to_string());
        }

        fn highest_set_bit(bytes: &[u8]) -> Option<usize> {
            let mut i = bytes.len();
            while i > 0 {
                let chunk_start = i.saturating_sub(16);
                let chunk_end = i;
                let mut buf = [0u8; 16];
                let len = chunk_end - chunk_start;
                buf[..len].copy_from_slice(&bytes[chunk_start..chunk_end]);
                let chunk = u128::from_le_bytes(buf);
                if chunk != 0 {
                    let msb = 127 - chunk.leading_zeros() as usize;
                    return Some(chunk_start * 8 + msb);
                }
                i = chunk_start;
            }
            None
        }

        let bit_len =
            highest_set_bit(bytes).ok_or_else(|| "bitlist missing length marker".to_string())?;
        let byte_len = bit_len.div_ceil(8);
        let mut data = vec![0u8; byte_len];
        if byte_len != 0 {
            data.copy_from_slice(&bytes[..byte_len]);
        }
        let term_index = bit_len;
        let term_byte = term_index / 8;
        if term_byte < data.len() {
            data[term_byte] &= !(1u8 << (term_index % 8));
        }
        Ok((data, bit_len))
    }

    /// Validates the SSZ bitlist terminator encoding and enforces `LIMIT`.
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        let (data, len) = Self::unpack_bits_with_terminator(bytes)?;
        if len > LIMIT {
            return Err(format!("BitList length {} exceeds limit {}", len, LIMIT));
        }
        Ok(Self { data, len })
    }
}

/// Fixed-length bitfield of exactly `LENGTH` bits.
///
/// Unlike [`BitList`], no sentinel bit is used on the wire: the byte length is
/// always `ceil(LENGTH / 8)`. `hash_tree_root` merkleizes the packed bytes to
/// `ceil(LENGTH / 256)` chunk leaves and does not mix in a length because the
/// size is fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitVector<const LENGTH: usize> {
    /// Packed little-endian bit storage.
    pub data: Vec<u8>,
}

impl<const LENGTH: usize> BitVector<LENGTH> {
    /// Packs a boolean vector into fixed-size SSZ bitvector storage.
    pub fn new(data: Vec<bool>) -> Result<Self, String> {
        if data.len() != LENGTH {
            return Err(format!(
                "BitVector expects {} bits, got {}",
                LENGTH,
                data.len()
            ));
        }
        let byte_len = LENGTH.div_ceil(8);
        let mut packed = vec![0u8; byte_len];
        for (i, bit) in data.iter().enumerate() {
            if *bit {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        Ok(Self { data: packed })
    }

    fn pack_bits(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn unpack_bits(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let expected = LENGTH.div_ceil(8);
        if bytes.len() != expected {
            return Err(format!(
                "BitVector expects {} bytes, got {}",
                expected,
                bytes.len()
            ));
        }
        if !LENGTH.is_multiple_of(8) {
            let used_bits = LENGTH % 8;
            let mask = (1u8 << used_bits) - 1;
            if bytes[expected - 1] & !mask != 0 {
                return Err("BitVector has non-zero unused bits".to_string());
            }
        }
        Ok(bytes.to_vec())
    }

    /// Validates size and unused high bits before decoding.
    pub fn decode_ssz_checked(bytes: &[u8]) -> Result<Self, String> {
        Self::decode_ssz(bytes)
    }
}

impl<const LENGTH: usize> SszEncode for BitVector<LENGTH> {
    fn encode_ssz(&self) -> Vec<u8> {
        self.pack_bits()
    }

    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.data);
    }

    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.data.as_ptr(), dst, self.data.len());
        }
    }
}

impl<const LENGTH: usize> SszDecode for BitVector<LENGTH> {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            data: Self::unpack_bits(bytes)?,
        })
    }
}

impl<const LENGTH: usize> HashTreeRoot for BitVector<LENGTH> {
    fn hash_tree_root(&self) -> [u8; 32] {
        let packed = self.pack_bits();
        let chunks = chunkify_fixed(&packed);
        let limit_chunks = LENGTH.div_ceil(BYTES_PER_CHUNK * 8);
        let root = merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
        *root.as_ref()
    }
}

impl<const LENGTH: usize> SszElement for BitVector<LENGTH> {
    fn fixed_len_opt() -> Option<usize> {
        Some(LENGTH.div_ceil(8))
    }
}

impl<const LIMIT: usize> SszEncode for BitList<LIMIT> {
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
        panic!("BitList is variable-size and cannot be written via write_fixed_ssz");
    }
}

impl<const LIMIT: usize> SszDecode for BitList<LIMIT> {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (data, len) = Self::unpack_bits_with_terminator(bytes)?;
        Ok(Self { data, len })
    }
}

impl<const LIMIT: usize> HashTreeRoot for BitList<LIMIT> {
    fn hash_tree_root(&self) -> [u8; 32] {
        let chunks = chunkify_fixed(&self.data);
        let limit_chunks = LIMIT.div_ceil(BYTES_PER_CHUNK * 8);
        let root = merkleize_with_limit(&chunks, limit_chunks).unwrap_or_else(|_| Bytes32::zero());
        let mixed = mix_in_length(&root, self.len);
        *mixed.as_ref()
    }
}

impl<const LIMIT: usize> SszElement for BitList<LIMIT> {}
