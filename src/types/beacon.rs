use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;
use crate::types::container::{
    Container, ContainerFieldKind, EncodedContainerField, decode_field_slices, encode_fields,
    hash_tree_root_from_field_roots,
};

/// Minimal fixed-layout beacon block header used for benchmark and fixture parity work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeaconBlockHeader {
    /// Slot of the block being described.
    pub slot: u64,
    /// Proposer index for the block.
    pub proposer_index: u64,
    /// Root of the parent block header.
    pub parent_root: Bytes32,
    /// Root of the post-state for this block.
    pub state_root: Bytes32,
    /// Root of the block body.
    pub body_root: Bytes32,
}

impl Container for BeaconBlockHeader {}

impl SszEncode for BeaconBlockHeader {
    /// Encodes the header as a 112-byte fixed-layout SSZ container.
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

impl SszDecode for BeaconBlockHeader {
    /// Decodes the header from the fixed 112-byte container layout.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let fields = decode_field_slices(
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
            slot: u64::decode_ssz(fields[0])?,
            proposer_index: u64::decode_ssz(fields[1])?,
            parent_root: Bytes32::decode_ssz(fields[2])?,
            state_root: Bytes32::decode_ssz(fields[3])?,
            body_root: Bytes32::decode_ssz(fields[4])?,
        })
    }
}

impl HashTreeRoot for BeaconBlockHeader {
    /// Computes the container root from the five field roots.
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body_root.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for BeaconBlockHeader {
    fn fixed_len() -> usize {
        112
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_block_header_roundtrip() {
        let header = BeaconBlockHeader {
            slot: 42,
            proposer_index: 7,
            parent_root: Bytes32::from([1u8; 32]),
            state_root: Bytes32::from([2u8; 32]),
            body_root: Bytes32::from([3u8; 32]),
        };

        let bytes = header.encode_ssz();
        assert_eq!(bytes.len(), 112);

        let decoded = BeaconBlockHeader::decode_ssz(&bytes).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn beacon_block_header_htr_is_not_zero() {
        let header = BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: Bytes32::from([4u8; 32]),
            state_root: Bytes32::from([5u8; 32]),
            body_root: Bytes32::from([6u8; 32]),
        };

        assert_ne!(header.hash_tree_root(), [0u8; 32]);
    }
}
