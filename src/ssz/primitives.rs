use crate::ssz::hash::{chunkify_fixed, hash_nodes, merkleize};
use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;

impl SszEncode for bool {
    #[inline]
    fn encode_ssz(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }

    #[inline]
    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    #[inline]
    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        unsafe { core::ptr::write(dst, u8::from(*self)) };
    }
}

impl SszDecode for bool {
    #[inline]
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        match bytes {
            [0] => Ok(false),
            [1] => Ok(true),
            [x] => Err(format!("invalid boolean byte: {x}")),
            _ => Err(format!("boolean expects 1 byte, got {}", bytes.len())),
        }
    }
}

impl HashTreeRoot for bool {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = u8::from(*self);
        out
    }
}

impl SszFixedLen for bool {
    #[inline]
    fn fixed_len() -> usize {
        1
    }

    #[inline]
    fn tree_pack_basic() -> bool {
        true
    }
}

macro_rules! impl_uint_ssz {
    ($ty:ty, $len:expr) => {
        impl SszEncode for $ty {
            #[inline]
            fn encode_ssz(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }

            #[inline]
            fn encode_ssz_into(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }

            #[inline]
            unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
                let bytes = self.to_le_bytes();
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, $len);
                }
            }
        }

        impl SszDecode for $ty {
            #[inline]
            fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
                let arr: [u8; $len] = bytes.try_into().map_err(|_| {
                    format!(
                        "{} expects {} bytes, got {}",
                        stringify!($ty),
                        $len,
                        bytes.len()
                    )
                })?;
                Ok(<$ty>::from_le_bytes(arr))
            }
        }

        impl HashTreeRoot for $ty {
            #[inline]
            fn hash_tree_root(&self) -> [u8; 32] {
                let mut out = [0u8; 32];
                out[..$len].copy_from_slice(&self.to_le_bytes());
                out
            }
        }

        impl SszFixedLen for $ty {
            #[inline]
            fn fixed_len() -> usize {
                $len
            }

            #[inline]
            fn tree_pack_basic() -> bool {
                true
            }
        }
    };
}

impl_uint_ssz!(u8, 1);
impl_uint_ssz!(u16, 2);
impl_uint_ssz!(u32, 4);
impl_uint_ssz!(u64, 8);
impl_uint_ssz!(u128, 16);

impl<const N: usize> SszEncode for [u8; N] {
    #[inline]
    fn encode_ssz(&self) -> Vec<u8> {
        self.to_vec()
    }

    #[inline]
    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    #[inline]
    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), dst, N);
        }
    }
}

impl<const N: usize> SszDecode for [u8; N] {
    #[inline]
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        bytes
            .try_into()
            .map_err(|_| format!("[u8; {N}] expects {N} bytes, got {}", bytes.len()))
    }
}

impl<const N: usize> HashTreeRoot for [u8; N] {
    #[inline]
    fn hash_tree_root(&self) -> [u8; 32] {
        if N == 0 {
            return Bytes32::zero().as_array();
        }

        if N <= 32 {
            let mut chunk = [0u8; 32];
            chunk[..N].copy_from_slice(self);
            return chunk;
        }

        if N <= 64 {
            let mut left = [0u8; 32];
            left.copy_from_slice(&self[..32]);

            let mut right = [0u8; 32];
            right[..N - 32].copy_from_slice(&self[32..]);

            return hash_nodes(&Bytes32::from(left), &Bytes32::from(right)).as_array();
        }

        let chunks = chunkify_fixed(self);
        *merkleize(&chunks).as_ref()
    }
}

impl<const N: usize> SszFixedLen for [u8; N] {
    #[inline]
    fn fixed_len() -> usize {
        N
    }

    #[inline]
    fn tree_pack_basic() -> bool {
        false
    }
}
