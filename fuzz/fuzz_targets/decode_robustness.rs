#![no_main]

use libfuzzer_sys::fuzz_target;
use peam_ssz::ssz::SszDecode;
use peam_ssz::types::collections::SszList;

fuzz_target!(|data: &[u8]| {
    let _ = bool::decode_ssz(data);
    let _ = u64::decode_ssz(data);
    let _ = <[u8; 32]>::decode_ssz(data);
    let _ = SszList::<u64, 64>::decode_ssz_checked(data);
    let _ = SszList::<[u8; 32], 16>::decode_ssz_checked(data);
});
