use crate::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use crate::types::bytes::Bytes32;
use crate::types::container::{
    Container, EncodedContainerField, encode_fields, hash_tree_root_from_field_roots,
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

    /// Appends the encoded fixed-layout header to an existing buffer.
    fn encode_ssz_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.reserve(112);
        unsafe { out.set_len(start + 112) };
        unsafe {
            self.slot.write_fixed_ssz(out.as_mut_ptr().add(start));
            self.proposer_index
                .write_fixed_ssz(out.as_mut_ptr().add(start + 8));
            self.parent_root
                .write_fixed_ssz(out.as_mut_ptr().add(start + 16));
            self.state_root
                .write_fixed_ssz(out.as_mut_ptr().add(start + 48));
            self.body_root
                .write_fixed_ssz(out.as_mut_ptr().add(start + 80));
        }
    }

    /// Writes the 112-byte fixed header layout directly to `dst`.
    unsafe fn write_fixed_ssz(&self, dst: *mut u8) {
        unsafe {
            self.slot.write_fixed_ssz(dst);
            self.proposer_index.write_fixed_ssz(dst.add(8));
            self.parent_root.write_fixed_ssz(dst.add(16));
            self.state_root.write_fixed_ssz(dst.add(48));
            self.body_root.write_fixed_ssz(dst.add(80));
        }
    }
}

impl SszDecode for BeaconBlockHeader {
    /// Decodes the header from the fixed 112-byte container layout.
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 112 {
            return Err(format!(
                "BeaconBlockHeader expects 112 bytes, got {}",
                bytes.len()
            ));
        }
        let slot = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const u64) };
        let proposer_index =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(8) as *const u64) };
        let parent_root = Bytes32::from(unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(16) as *const [u8; 32])
        });
        let state_root = Bytes32::from(unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(48) as *const [u8; 32])
        });
        let body_root = Bytes32::from(unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(80) as *const [u8; 32])
        });

        Ok(Self {
            slot: u64::from_le(slot),
            proposer_index: u64::from_le(proposer_index),
            parent_root,
            state_root,
            body_root,
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
