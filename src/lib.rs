//! Minimal SSZ encode/decode and merkleization crate extracted from Peam.
//!
//! The crate is intentionally small: core SSZ traits live in [`ssz`], reusable
//! container/list/bitfield types live in [`types`], and a couple of low-level
//! write helpers live in [`unsafe_vec`].
pub mod ssz;
pub mod types;
pub mod unsafe_vec;
