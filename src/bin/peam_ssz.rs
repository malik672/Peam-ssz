use std::hint::black_box;
use std::time::{Duration, Instant};

use peam_ssz::ssz::{HashTreeRoot, SszDecode, SszEncode};
use peam_ssz::types::beacon::BeaconBlockHeader;
use peam_ssz::types::bytes::Bytes32;
use peam_ssz::types::collections::SszList;

const LIST_LIMIT: usize = 200_000;

fn main() {
    let iters = env_usize("PEAM_SSZ_ITERS").unwrap_or(50_000);
    let list_len = env_usize("PEAM_SSZ_LIST_LEN").unwrap_or(100_000);

    assert!(
        list_len <= LIST_LIMIT,
        "PEAM_SSZ_LIST_LEN must be <= {LIST_LIMIT}"
    );

    eprintln!("peam_ssz: pid={}", std::process::id());
    eprintln!("peam_ssz: waiting 3s so Instruments can attach...");
    std::thread::sleep(Duration::from_secs(3));

    let header = BeaconBlockHeader {
        slot: 42,
        proposer_index: 7,
        parent_root: Bytes32::from([1u8; 32]),
        state_root: Bytes32::from([2u8; 32]),
        body_root: Bytes32::from([3u8; 32]),
    };

    let list_data: Vec<u64> = (0..list_len as u64).collect();
    let list = SszList::<u64, LIST_LIMIT>::new(list_data).unwrap();

    let started = Instant::now();
    let mut checksum = 0u8;

    for i in 0..iters {
        let header_bytes = black_box(header.encode_ssz());
        let decoded_header = BeaconBlockHeader::decode_ssz(black_box(&header_bytes)).unwrap();
        checksum ^= black_box(decoded_header.hash_tree_root()[0]);

        let header_array = black_box(header.encode_ssz_array());
        checksum ^= black_box(header_array[0]);

        let list_bytes = black_box(list.encode_ssz());
        let decoded_list =
            SszList::<u64, LIST_LIMIT>::decode_ssz_checked(black_box(&list_bytes)).unwrap();
        checksum ^= black_box(decoded_list.hash_tree_root()[0]);

        if i % 1_000 == 0 {
            eprintln!("peam_ssz: iter={i}/{iters}");
        }
    }

    eprintln!(
        "peam_ssz: done iters={iters} list_len={list_len} elapsed={:?} checksum={checksum}",
        started.elapsed()
    );
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}
