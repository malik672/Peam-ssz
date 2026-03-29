#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use libssz::SszDecode as _;
use libssz::SszEncode as _;
use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};
use libssz_types::SszList as RefList;
use peam_ssz::ssz::{HashTreeRoot, SszEncode};
use peam_ssz::types::collections::SszList as PeamList;

const LIMIT: usize = 64;

#[derive(Debug, Clone, Arbitrary)]
struct U64ListInput {
    values: Vec<u64>,
}

fuzz_target!(|input: U64ListInput| {
    let values = if input.values.len() > LIMIT {
        input.values[..LIMIT].to_vec()
    } else {
        input.values
    };

    let peam = PeamList::<u64, LIMIT>::new(values.clone()).unwrap();
    let reference = RefList::<u64, LIMIT>::try_from(values.clone()).unwrap();

    let peam_bytes = peam.encode_ssz();
    let ref_bytes = reference.to_ssz();
    assert_eq!(peam_bytes, ref_bytes);

    let decoded_peam = PeamList::<u64, LIMIT>::decode_ssz_checked(&peam_bytes).unwrap();
    let decoded_ref = RefList::<u64, LIMIT>::from_ssz_bytes(&ref_bytes).unwrap();
    assert_eq!(decoded_peam.data, values);
    assert_eq!(decoded_ref.into_inner(), values);

    let peam_root = peam.hash_tree_root();
    let ref_root = reference.hash_tree_root(&Sha2Hasher);
    assert_eq!(peam_root, ref_root);
});
