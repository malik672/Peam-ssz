use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::unsafe_vec::write_bytes_at;

/// 32-byte fixed-size value.
///
/// Used for roots and generic SSZ chunks. `hash_tree_root` returns the inner
/// bytes directly because a single 32-byte chunk is already its own root.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Bytes32([u8; 32]);

impl Bytes32 {
    /// Returns the all-zero 32-byte value.
    #[inline]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Copies the first 32 bytes from `bytes`.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        Self(out)
    }

    /// Returns the wrapped bytes by value.
    #[inline]
    pub const fn as_array(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Bytes32 {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 32]> for Bytes32 {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Bytes32 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SszEncode for Bytes32 {
    #[inline]
    fn encode_ssz(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        unsafe { out.set_len(32) };
        unsafe { write_bytes_at(&mut out, 0, &self.0) };
        out
    }

    #[inline]
    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.reserve(32);
        unsafe { out.set_len(start + 32) };
        unsafe { write_bytes_at(out, start, &self.0) };
    }

    #[inline]
    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.0.as_ptr(), dst, 32);
        }
    }
}

impl SszDecode for Bytes32 {
    #[inline]
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err(format!("Bytes32 expects 32 bytes, got {}", bytes.len()));
        }
        Ok(Self::from_slice(bytes))
    }
}

impl HashTreeRoot for Bytes32 {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        self.0
    }
}

impl SszFixedLen for Bytes32 {
    #[inline]
    fn fixed_len() -> usize {
        32
    }

    #[inline]
    fn tree_pack_basic() -> bool {
        true
    }
}
