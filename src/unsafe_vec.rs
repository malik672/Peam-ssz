//! Small unsafe helpers for writing into pre-sized vectors.

/// Writes `value` into `vec[index]` without bounds checks or drop handling.
///
/// The caller must guarantee that `index` is in-bounds for the already-initialized
/// backing allocation and that writing here does not leak an old value.
#[inline]
pub unsafe fn write_at<T>(vec: &mut Vec<T>, index: usize, value: T) {
    unsafe {
        core::ptr::write(vec.as_mut_ptr().add(index), value);
    }
}

/// Copies raw bytes into a pre-sized byte vector at `offset` without bounds checks.
///
/// The caller must guarantee that `offset..offset + bytes.len()` is valid inside
/// the existing allocation.
#[inline]
pub unsafe fn write_bytes_at(vec: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), vec.as_mut_ptr().add(offset), bytes.len());
    }
}
