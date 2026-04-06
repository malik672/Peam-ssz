//! Core SSZ traits and hashing helpers.
//!
//! The library keeps the trait surface intentionally small:
//! - [`SszEncode`] and [`SszDecode`] for byte serialization
//! - [`SszFixedLen`] / [`SszElement`] for collection layout decisions
//! - [`HashTreeRoot`] for SSZ merkleization
pub mod hash;
mod primitives;

/// Encodes a value into its SSZ byte representation.
///
/// The library exposes both unchecked and checked entry points:
/// - [`SszEncode::encode_ssz`] is the low-level path and may trust internal
///   invariants for performance.
/// - [`SszEncode::encode_ssz_checked`] is the defensive path for types whose
///   public state can be constructed in non-canonical forms and need explicit
///   validation before producing SSZ bytes.
pub trait SszEncode {
    /// Encodes a value into a freshly allocated SSZ byte buffer.
    fn encode_ssz(&self) -> Vec<u8>;

    /// Encodes a value into a freshly allocated SSZ byte buffer after
    /// performing any type-specific validation needed for canonical output.
    ///
    /// The default implementation preserves backwards compatibility for types
    /// that have no extra checked-vs-unchecked distinction.
    fn encode_ssz_checked(&self) -> Result<Vec<u8>, String> {
        Ok(self.encode_ssz())
    }

    /// Appends the SSZ byte representation to an existing buffer.
    ///
    /// Implementations should prefer writing directly into `out` instead of
    /// allocating a temporary `Vec<u8>` when possible. The default
    /// implementation preserves backwards compatibility for callers that only
    /// implement [`SszEncode::encode_ssz`].
    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encode_ssz());
    }

    /// Writes the fixed-size SSZ representation directly into `dst`.
    ///
    /// This must only be implemented for types whose encoded size is known
    /// statically. Variable-size types should make misuse explicit (for example
    /// by panicking) instead of silently allocating through a fallback path.
    ///
    /// The caller must guarantee that `dst..dst + encoded_len` is valid for
    /// writes, where `encoded_len` is the statically known fixed-size SSZ
    /// length for this type. The default implementation preserves
    /// backwards-compatibility but allocates, so hot fixed-size types should
    /// still override it with a direct write.
    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        let bytes = self.encode_ssz();
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        }
    }
}

/// Fixed-size SSZ encoding into caller-provided storage.
///
/// This is the no-allocation path for types whose encoded length is known
/// statically. Callers provide the destination slice and the implementation
/// writes the fixed-size SSZ bytes directly into it.
pub trait SszEncodeFixed: SszEncode + SszFixedLen {
    /// Encodes the fixed-size SSZ bytes into `out`.
    ///
    /// `out` must be exactly [`SszFixedLen::fixed_len`] bytes long.
    #[inline]
    fn encode_ssz_fixed_into(&self, out: &mut [u8]) {
        let expected = Self::fixed_len();
        debug_assert!(
            out.len() == expected,
            "fixed-size SSZ encode expects {} bytes, got {}",
            expected,
            out.len()
        );
        unsafe { self.write_fixed_ssz(out.as_mut_ptr()) };
    }
}

impl<T> SszEncodeFixed for T where T: SszEncode + SszFixedLen {}

/// Decodes a value from SSZ bytes.
///
/// Most callers should prefer a checked constructor on container/list wrappers
/// before falling back to raw `decode_ssz`. In other words:
/// - [`SszDecode::decode_ssz`] is the low-level path and assumes the caller
///   has already validated the input for the target type.
/// - checked wrappers such as `decode_ssz_checked` on collection/bitfield
///   types perform the additional validation needed for safe public use.
pub trait SszDecode: Sized {
    /// Safety: This assumes the caller validated length/limits/offsets.
    /// Passing malformed input is undefined behavior at the library level.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String>;
}

/// Metadata for values whose SSZ encoding size is known statically.
pub trait SszFixedLen {
    /// Returns the number of SSZ bytes produced by this type.
    fn fixed_len() -> usize;

    /// Returns `true` when this fixed-size type should be packed as basic
    /// elements inside vectors/lists instead of merkleized per element root.
    fn tree_pack_basic() -> bool {
        false
    }
}

/// Collection-facing metadata for SSZ element types.
///
/// This is the trait lists/vectors consult to decide whether they are dealing
/// with fixed-size or variable-size elements and whether fixed-size elements
/// should be tree-packed as basic values.
pub trait SszElement {
    /// Returns the static encoded length when the element is fixed-size.
    fn fixed_len_opt() -> Option<usize> {
        None
    }

    /// Returns `true` when fixed-size values of this type should be tree-packed
    /// as basic bytes inside lists/vectors.
    fn tree_pack_basic() -> bool {
        false
    }
}

impl<T: SszFixedLen> SszElement for T {
    fn fixed_len_opt() -> Option<usize> {
        Some(T::fixed_len())
    }

    fn tree_pack_basic() -> bool {
        T::tree_pack_basic()
    }
}

/// Computes the 32-byte SSZ hash-tree-root for a value.
pub trait HashTreeRoot {
    fn hash_tree_root(&self) -> [u8; 32];
}
