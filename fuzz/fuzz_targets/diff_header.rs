#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use libssz::SszDecode as _;
use libssz::SszEncode as _;
use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};
use peam_ssz::ssz::{HashTreeRoot as PeamHashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use peam_ssz::types::container::{
    ContainerFieldKind, EncodedContainerField, decode_field_slices, encode_fields,
    hash_tree_root_from_field_roots,
};

#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
struct HeaderFixture {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body_root: [u8; 32],
}

impl SszEncode for HeaderFixture {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body_root = self.body_root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&body_root),
        ])
    }
}

impl SszDecode for HeaderFixture {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body_root: <[u8; 32]>::decode_ssz(slices[4])?,
        })
    }
}

impl PeamHashTreeRoot for HeaderFixture {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            <u64 as PeamHashTreeRoot>::hash_tree_root(&self.slot),
            <u64 as PeamHashTreeRoot>::hash_tree_root(&self.proposer_index),
            <[u8; 32] as PeamHashTreeRoot>::hash_tree_root(&self.parent_root),
            <[u8; 32] as PeamHashTreeRoot>::hash_tree_root(&self.state_root),
            <[u8; 32] as PeamHashTreeRoot>::hash_tree_root(&self.body_root),
        ])
    }
}

impl SszFixedLen for HeaderFixture {
    fn fixed_len() -> usize {
        112
    }
}

#[derive(Debug, Clone, PartialEq, Eq, libssz_derive::SszEncode, libssz_derive::SszDecode, libssz_derive::HashTreeRoot)]
struct LighthouseHeaderFixture {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body_root: [u8; 32],
}

impl From<HeaderFixture> for LighthouseHeaderFixture {
    fn from(value: HeaderFixture) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root,
            state_root: value.state_root,
            body_root: value.body_root,
        }
    }
}

fuzz_target!(|fixture: HeaderFixture| {
    let reference = LighthouseHeaderFixture::from(fixture.clone());

    let peam_bytes = fixture.encode_ssz();
    let ref_bytes = reference.to_ssz();
    assert_eq!(peam_bytes, ref_bytes);

    let decoded_peam = HeaderFixture::decode_ssz(&peam_bytes).unwrap();
    let decoded_ref = LighthouseHeaderFixture::from_ssz_bytes(&ref_bytes).unwrap();
    assert_eq!(decoded_peam, fixture);
    assert_eq!(decoded_ref, reference);

    let peam_root = <HeaderFixture as PeamHashTreeRoot>::hash_tree_root(&fixture);
    let ref_root = reference.hash_tree_root(&Sha2Hasher);
    assert_eq!(peam_root, ref_root);
});
