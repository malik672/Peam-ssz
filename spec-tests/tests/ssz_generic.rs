use peam_ssz::ssz::hash::mix_in_selector;
use peam_ssz::ssz::{HashTreeRoot, SszDecode, SszEncode, SszFixedLen};
use peam_ssz::types::bitlist::{BitList, BitVector};
use peam_ssz::types::bytes::Bytes32;
use peam_ssz::types::collections::{SszList, SszVector};
use peam_ssz::types::container::{
    ContainerFieldKind, EncodedContainerField, decode_field_slices, encode_fields,
    hash_tree_root_from_field_roots, hash_tree_root_progressive_container,
};
use peam_ssz::types::progressive::{ProgressiveBitlist, ProgressiveList};
use serde::Deserialize;
use spec_tests::loader;

macro_rules! dispatch_supported_lengths {
    ($len:expr, $func:ident::<$ty:ty>($($arg:expr),*)) => {
        match $len {
            1 => $func::<$ty, 1>($($arg),*),
            2 => $func::<$ty, 2>($($arg),*),
            3 => $func::<$ty, 3>($($arg),*),
            4 => $func::<$ty, 4>($($arg),*),
            5 => $func::<$ty, 5>($($arg),*),
            6 => $func::<$ty, 6>($($arg),*),
            7 => $func::<$ty, 7>($($arg),*),
            8 => $func::<$ty, 8>($($arg),*),
            9 => $func::<$ty, 9>($($arg),*),
            15 => $func::<$ty, 15>($($arg),*),
            16 => $func::<$ty, 16>($($arg),*),
            17 => $func::<$ty, 17>($($arg),*),
            31 => $func::<$ty, 31>($($arg),*),
            32 => $func::<$ty, 32>($($arg),*),
            33 => $func::<$ty, 33>($($arg),*),
            64 => $func::<$ty, 64>($($arg),*),
            128 => $func::<$ty, 128>($($arg),*),
            256 => $func::<$ty, 256>($($arg),*),
            511 => $func::<$ty, 511>($($arg),*),
            512 => $func::<$ty, 512>($($arg),*),
            513 => $func::<$ty, 513>($($arg),*),
            1024 => $func::<$ty, 1024>($($arg),*),
            2048 => $func::<$ty, 2048>($($arg),*),
            4096 => $func::<$ty, 4096>($($arg),*),
            8192 => $func::<$ty, 8192>($($arg),*),
            other => panic!("unsupported size: {other}"),
        }
    };
    ($len:expr, $func:ident($($arg:expr),*)) => {
        match $len {
            1 => $func::<1>($($arg),*),
            2 => $func::<2>($($arg),*),
            3 => $func::<3>($($arg),*),
            4 => $func::<4>($($arg),*),
            5 => $func::<5>($($arg),*),
            6 => $func::<6>($($arg),*),
            7 => $func::<7>($($arg),*),
            8 => $func::<8>($($arg),*),
            9 => $func::<9>($($arg),*),
            15 => $func::<15>($($arg),*),
            16 => $func::<16>($($arg),*),
            17 => $func::<17>($($arg),*),
            31 => $func::<31>($($arg),*),
            32 => $func::<32>($($arg),*),
            33 => $func::<33>($($arg),*),
            64 => $func::<64>($($arg),*),
            128 => $func::<128>($($arg),*),
            256 => $func::<256>($($arg),*),
            511 => $func::<511>($($arg),*),
            512 => $func::<512>($($arg),*),
            513 => $func::<513>($($arg),*),
            1024 => $func::<1024>($($arg),*),
            2048 => $func::<2048>($($arg),*),
            4096 => $func::<4096>($($arg),*),
            8192 => $func::<8192>($($arg),*),
            other => panic!("unsupported size: {other}"),
        }
    };
}

#[test]
fn boolean_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("boolean") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let yaml_value = loader::read_yaml_value(&case_path.join("value.yaml"));

        let expected = match &yaml_value {
            serde_yaml::Value::Bool(b) => *b,
            serde_yaml::Value::String(s) => s == "true",
            other => panic!("{case_name}: unexpected YAML value: {other:?}"),
        };

        let decoded =
            bool::decode_ssz(&ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
        assert_eq!(decoded, expected, "{case_name}: decoded value mismatch");
        assert_eq!(
            decoded.encode_ssz(),
            ssz,
            "{case_name}: re-encoded bytes mismatch"
        );
        assert_eq!(
            decoded.hash_tree_root(),
            expected_root,
            "{case_name}: hash tree root mismatch"
        );
    }
}

#[test]
fn boolean_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("boolean") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        assert!(bool::decode_ssz(&ssz).is_err(), "{case_name}: should fail");
    }
}

#[test]
fn uints_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("uints") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let yaml_value = loader::read_yaml_value(&case_path.join("value.yaml"));
        let yaml_str = match &yaml_value {
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::String(s) => s.clone(),
            other => panic!("{case_name}: unexpected YAML: {other:?}"),
        };

        match parse_uint_bits(&case_name) {
            8 => check_uint::<u8>(&ssz, &yaml_str, &expected_root, &case_name),
            16 => check_uint::<u16>(&ssz, &yaml_str, &expected_root, &case_name),
            32 => check_uint::<u32>(&ssz, &yaml_str, &expected_root, &case_name),
            64 => check_uint::<u64>(&ssz, &yaml_str, &expected_root, &case_name),
            128 => check_uint::<u128>(&ssz, &yaml_str, &expected_root, &case_name),
            256 => check_uint_256(&ssz, &yaml_str, &expected_root, &case_name),
            other => panic!("{case_name}: unsupported uint bit width: {other}"),
        }
    }
}

#[test]
fn uints_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("uints") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let result_is_err = match parse_uint_bits(&case_name) {
            8 => u8::decode_ssz(&ssz).is_err(),
            16 => u16::decode_ssz(&ssz).is_err(),
            32 => u32::decode_ssz(&ssz).is_err(),
            64 => u64::decode_ssz(&ssz).is_err(),
            128 => u128::decode_ssz(&ssz).is_err(),
            256 => <[u8; 32]>::decode_ssz(&ssz).is_err(),
            other => panic!("{case_name}: unsupported uint bit width: {other}"),
        };
        assert!(result_is_err, "{case_name}: should fail to decode");
    }
}

#[test]
fn basic_vector_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("basic_vector") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let (elem_type, length) = parse_basic_vector_case(&case_name);

        match elem_type {
            "bool" => dispatch_supported_lengths!(
                length,
                check_vector::<bool>(&ssz, &expected_root, &case_name)
            ),
            "uint8" => dispatch_supported_lengths!(
                length,
                check_vector::<u8>(&ssz, &expected_root, &case_name)
            ),
            "uint16" => dispatch_supported_lengths!(
                length,
                check_vector::<u16>(&ssz, &expected_root, &case_name)
            ),
            "uint32" => dispatch_supported_lengths!(
                length,
                check_vector::<u32>(&ssz, &expected_root, &case_name)
            ),
            "uint64" => dispatch_supported_lengths!(
                length,
                check_vector::<u64>(&ssz, &expected_root, &case_name)
            ),
            "uint128" => dispatch_supported_lengths!(
                length,
                check_vector::<u128>(&ssz, &expected_root, &case_name)
            ),
            "uint256" => dispatch_supported_lengths!(
                length,
                check_vector::<[u8; 32]>(&ssz, &expected_root, &case_name)
            ),
            other => panic!("{case_name}: unsupported element type: {other}"),
        }
    }
}

#[test]
fn basic_vector_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("basic_vector") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let (elem_type, length) = parse_basic_vector_case(&case_name);
        if length == 0 {
            continue;
        }

        let failed = match elem_type {
            "bool" => dispatch_vector_failure::<bool>(&ssz, length),
            "uint8" => dispatch_vector_failure::<u8>(&ssz, length),
            "uint16" => dispatch_vector_failure::<u16>(&ssz, length),
            "uint32" => dispatch_vector_failure::<u32>(&ssz, length),
            "uint64" => dispatch_vector_failure::<u64>(&ssz, length),
            "uint128" => dispatch_vector_failure::<u128>(&ssz, length),
            "uint256" => dispatch_vector_failure::<[u8; 32]>(&ssz, length),
            other => panic!("{case_name}: unsupported element type: {other}"),
        };
        assert!(failed, "{case_name}: should fail");
    }
}

#[test]
fn bitlist_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("bitlist") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let limit = parse_bitfield_param(&case_name, "bitlist_");
        dispatch_supported_lengths!(limit, check_bitlist(&ssz, &expected_root, &case_name));
    }
}

#[test]
fn bitlist_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("bitlist") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let limit = parse_bitfield_param(&case_name, "bitlist_");
        let failed = dispatch_bitlist_failure(&ssz, limit);
        assert!(failed, "{case_name}: should fail");
    }
}

#[test]
fn bitvector_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("bitvector") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let length = parse_bitfield_param(&case_name, "bitvec_");
        dispatch_supported_lengths!(length, check_bitvector(&ssz, &expected_root, &case_name));
    }
}

#[test]
fn bitvector_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("bitvector") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let length = parse_bitfield_param(&case_name, "bitvec_");
        if length == 0 {
            continue;
        }
        let failed = dispatch_bitvector_failure(&ssz, length);
        assert!(failed, "{case_name}: should fail");
    }
}

#[test]
fn basic_progressive_list_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("basic_progressive_list") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));

        match parse_proglist_type(&case_name) {
            "bool" => check_progressive_list::<bool>(&ssz, &expected_root, &case_name),
            "uint8" => check_progressive_list::<u8>(&ssz, &expected_root, &case_name),
            "uint16" => check_progressive_list::<u16>(&ssz, &expected_root, &case_name),
            "uint32" => check_progressive_list::<u32>(&ssz, &expected_root, &case_name),
            "uint64" => check_progressive_list::<u64>(&ssz, &expected_root, &case_name),
            "uint128" => check_progressive_list::<u128>(&ssz, &expected_root, &case_name),
            "uint256" => check_progressive_list::<[u8; 32]>(&ssz, &expected_root, &case_name),
            other => panic!("{case_name}: unsupported element type: {other}"),
        }
    }
}

#[test]
fn basic_progressive_list_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("basic_progressive_list") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));

        let failed = match parse_proglist_type(&case_name) {
            "bool" => ProgressiveList::<bool>::decode_ssz(&ssz).is_err(),
            "uint8" => ProgressiveList::<u8>::decode_ssz(&ssz).is_err(),
            "uint16" => ProgressiveList::<u16>::decode_ssz(&ssz).is_err(),
            "uint32" => ProgressiveList::<u32>::decode_ssz(&ssz).is_err(),
            "uint64" => ProgressiveList::<u64>::decode_ssz(&ssz).is_err(),
            "uint128" => ProgressiveList::<u128>::decode_ssz(&ssz).is_err(),
            "uint256" => ProgressiveList::<[u8; 32]>::decode_ssz(&ssz).is_err(),
            other => panic!("{case_name}: unsupported element type: {other}"),
        };

        assert!(failed, "{case_name}: should have failed to decode");
    }
}

#[test]
fn progressive_bitlist_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("progressive_bitlist") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));

        let decoded = ProgressiveBitlist::decode_ssz(&ssz)
            .unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
        assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
        assert_eq!(
            decoded.hash_tree_root(),
            expected_root,
            "{case_name}: hash tree root mismatch"
        );
    }
}

#[test]
fn progressive_bitlist_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("progressive_bitlist") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        assert!(
            ProgressiveBitlist::decode_ssz(&ssz).is_err(),
            "{case_name}: should have failed to decode"
        );
    }
}

fn parse_uint_bits(case_name: &str) -> u32 {
    let after_prefix = case_name.strip_prefix("uint_").unwrap_or(case_name);
    let bits_str = after_prefix.split('_').next().unwrap();
    bits_str.parse().unwrap()
}

trait UintTestable: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug + PartialEq {
    fn from_decimal(s: &str) -> Self;
}

impl UintTestable for u8 {
    fn from_decimal(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl UintTestable for u16 {
    fn from_decimal(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl UintTestable for u32 {
    fn from_decimal(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl UintTestable for u64 {
    fn from_decimal(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl UintTestable for u128 {
    fn from_decimal(s: &str) -> Self {
        s.parse().unwrap()
    }
}

fn check_uint<T: UintTestable>(
    ssz: &[u8],
    yaml_str: &str,
    expected_root: &[u8; 32],
    case_name: &str,
) {
    let expected = T::from_decimal(yaml_str);
    let decoded = T::decode_ssz(ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded, expected, "{case_name}: value mismatch");
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn check_uint_256(ssz: &[u8], yaml_str: &str, expected_root: &[u8; 32], case_name: &str) {
    let decoded =
        <[u8; 32]>::decode_ssz(ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    let expected_bytes = decimal_to_u256_le(yaml_str);
    assert_eq!(decoded, expected_bytes, "{case_name}: value mismatch");
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn decimal_to_u256_le(s: &str) -> [u8; 32] {
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut result = [0u8; 32];

    for byte in &mut result {
        let mut remainder = 0u16;
        for digit in &mut digits {
            let val = remainder * 10 + (*digit as u16);
            *digit = (val / 256) as u8;
            remainder = val % 256;
        }
        *byte = remainder as u8;
        while digits.first() == Some(&0) && digits.len() > 1 {
            digits.remove(0);
        }
    }
    result
}

fn parse_basic_vector_case(case_name: &str) -> (&str, usize) {
    let prefixes = [
        "uint128", "uint256", "uint16", "uint32", "uint64", "uint8", "bool",
    ];
    for prefix in prefixes {
        let full = format!("vec_{prefix}_");
        if let Some(rest) = case_name.strip_prefix(&full) {
            let len = rest.split('_').next().unwrap().parse().unwrap();
            return (prefix, len);
        }
    }
    panic!("cannot parse basic_vector case name: {case_name}");
}

fn parse_bitfield_param(case_name: &str, prefix: &str) -> usize {
    let rest = case_name.strip_prefix(prefix).unwrap_or(case_name);
    if rest.starts_with("no_limit") {
        return 32;
    }
    rest.split('_').next().unwrap().parse().unwrap()
}

fn parse_proglist_type(case_name: &str) -> &str {
    let rest = case_name.strip_prefix("proglist_").unwrap_or(case_name);
    for type_name in &[
        "uint128", "uint256", "uint16", "uint32", "uint64", "uint8", "bool",
    ] {
        if rest.starts_with(type_name) {
            return type_name;
        }
    }
    panic!("cannot parse progressive list case name: {case_name}");
}

fn check_vector<T, const N: usize>(ssz: &[u8], expected_root: &[u8; 32], case_name: &str)
where
    T: SszDecode
        + SszEncode
        + HashTreeRoot
        + peam_ssz::ssz::SszElement
        + std::fmt::Debug
        + PartialEq,
{
    let decoded = SszVector::<T, N>::decode_ssz_checked(ssz)
        .unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn dispatch_vector_failure<T>(ssz: &[u8], length: usize) -> bool
where
    T: SszDecode
        + SszEncode
        + HashTreeRoot
        + peam_ssz::ssz::SszElement
        + std::fmt::Debug
        + PartialEq,
{
    macro_rules! inner {
        ($len:expr) => {
            dispatch_supported_lengths!($len, vector_failure::<T>(ssz))
        };
    }
    inner!(length)
}

fn vector_failure<T, const N: usize>(ssz: &[u8]) -> bool
where
    T: SszDecode
        + SszEncode
        + HashTreeRoot
        + peam_ssz::ssz::SszElement
        + std::fmt::Debug
        + PartialEq,
{
    SszVector::<T, N>::decode_ssz_checked(ssz).is_err()
}

fn check_bitlist<const N: usize>(ssz: &[u8], expected_root: &[u8; 32], case_name: &str) {
    let decoded = BitList::<N>::decode_ssz_checked(ssz)
        .unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn dispatch_bitlist_failure(ssz: &[u8], limit: usize) -> bool {
    dispatch_supported_lengths!(limit, bitlist_failure(ssz))
}

fn bitlist_failure<const N: usize>(ssz: &[u8]) -> bool {
    BitList::<N>::decode_ssz_checked(ssz).is_err()
}

fn check_bitvector<const N: usize>(ssz: &[u8], expected_root: &[u8; 32], case_name: &str) {
    let decoded = BitVector::<N>::decode_ssz_checked(ssz)
        .unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn dispatch_bitvector_failure(ssz: &[u8], length: usize) -> bool {
    dispatch_supported_lengths!(length, bitvector_failure(ssz))
}

fn bitvector_failure<const N: usize>(ssz: &[u8]) -> bool {
    BitVector::<N>::decode_ssz_checked(ssz).is_err()
}

fn check_progressive_list<T>(ssz: &[u8], expected_root: &[u8; 32], case_name: &str)
where
    T: SszDecode
        + SszEncode
        + HashTreeRoot
        + peam_ssz::ssz::SszElement
        + std::fmt::Debug
        + PartialEq,
{
    let decoded = ProgressiveList::<T>::decode_ssz(ssz)
        .unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct SingleFieldTestStruct {
    #[serde(rename = "A")]
    a: u8,
}

impl SszEncode for SingleFieldTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        encode_fields(&[EncodedContainerField::Fixed(&self.a.encode_ssz())])
    }
}

impl SszDecode for SingleFieldTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(bytes, &[ContainerFieldKind::Fixed(1)])?;
        Ok(Self {
            a: u8::decode_ssz(slices[0])?,
        })
    }
}

impl HashTreeRoot for SingleFieldTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[self.a.hash_tree_root()])
    }
}

impl SszFixedLen for SingleFieldTestStruct {
    fn fixed_len() -> usize {
        1
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct SmallTestStruct {
    #[serde(rename = "A")]
    a: u16,
    #[serde(rename = "B")]
    b: u16,
}

impl SszEncode for SmallTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Fixed(&b),
        ])
    }
}

impl SszDecode for SmallTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(2), ContainerFieldKind::Fixed(2)],
        )?;
        Ok(Self {
            a: u16::decode_ssz(slices[0])?,
            b: u16::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SmallTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[self.a.hash_tree_root(), self.b.hash_tree_root()])
    }
}

impl SszFixedLen for SmallTestStruct {
    fn fixed_len() -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct FixedTestStruct {
    #[serde(rename = "A")]
    a: u8,
    #[serde(rename = "B")]
    b: u64,
    #[serde(rename = "C")]
    c: u32,
}

impl SszEncode for FixedTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Fixed(&b),
            EncodedContainerField::Fixed(&c),
        ])
    }
}

impl SszDecode for FixedTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(4),
            ],
        )?;
        Ok(Self {
            a: u8::decode_ssz(slices[0])?,
            b: u64::decode_ssz(slices[1])?,
            c: u32::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for FixedTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            self.b.hash_tree_root(),
            self.c.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for FixedTestStruct {
    fn fixed_len() -> usize {
        13
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct VarTestStruct {
    #[serde(rename = "A")]
    a: u16,
    #[serde(rename = "B")]
    b: Vec<u16>,
    #[serde(rename = "C")]
    c: u8,
}

impl SszEncode for VarTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = SszList::<u16, 1024>::new(self.b.clone())
            .unwrap()
            .encode_ssz();
        let c = self.c.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Fixed(&c),
        ])
    }
}

impl SszDecode for VarTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(2),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
            ],
        )?;
        Ok(Self {
            a: u16::decode_ssz(slices[0])?,
            b: SszList::<u16, 1024>::decode_ssz_checked(slices[1])?.data,
            c: u8::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for VarTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        let b = SszList::<u16, 1024>::new(self.b.clone()).unwrap();
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            b.hash_tree_root(),
            self.c.hash_tree_root(),
        ])
    }
}

impl peam_ssz::ssz::SszElement for VarTestStruct {}

#[derive(Debug, PartialEq, Eq)]
struct ComplexTestStruct {
    a: u16,
    b: SszList<u16, 128>,
    c: u8,
    d: SszList<u8, 256>,
    e: VarTestStruct,
    f: SszVector<FixedTestStruct, 4>,
    g: SszVector<VarTestStruct, 2>,
}

impl SszEncode for ComplexTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        let d = self.d.encode_ssz();
        let e = self.e.encode_ssz();
        let f = self.f.encode_ssz();
        let g = self.g.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Fixed(&c),
            EncodedContainerField::Variable(&d),
            EncodedContainerField::Variable(&e),
            EncodedContainerField::Fixed(&f),
            EncodedContainerField::Variable(&g),
        ])
    }
}

impl SszDecode for ComplexTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(2),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(52),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            a: u16::decode_ssz(slices[0])?,
            b: SszList::<u16, 128>::decode_ssz_checked(slices[1])?,
            c: u8::decode_ssz(slices[2])?,
            d: SszList::<u8, 256>::decode_ssz_checked(slices[3])?,
            e: VarTestStruct::decode_ssz(slices[4])?,
            f: SszVector::<FixedTestStruct, 4>::decode_ssz_checked(slices[5])?,
            g: SszVector::<VarTestStruct, 2>::decode_ssz_checked(slices[6])?,
        })
    }
}

impl HashTreeRoot for ComplexTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            self.b.hash_tree_root(),
            self.c.hash_tree_root(),
            self.d.hash_tree_root(),
            self.e.hash_tree_root(),
            self.f.hash_tree_root(),
            self.g.hash_tree_root(),
        ])
    }
}

impl peam_ssz::ssz::SszElement for ComplexTestStruct {}

#[derive(Debug, PartialEq, Eq)]
struct BitsStruct {
    a: BitList<5>,
    b: BitVector<2>,
    c: BitVector<1>,
    d: BitList<6>,
    e: BitVector<8>,
}

impl SszEncode for BitsStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        let d = self.d.encode_ssz();
        let e = self.e.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&a),
            EncodedContainerField::Fixed(&b),
            EncodedContainerField::Fixed(&c),
            EncodedContainerField::Variable(&d),
            EncodedContainerField::Fixed(&e),
        ])
    }
}

impl SszDecode for BitsStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
            ],
        )?;
        Ok(Self {
            a: BitList::<5>::decode_ssz_checked(slices[0])?,
            b: BitVector::<2>::decode_ssz_checked(slices[1])?,
            c: BitVector::<1>::decode_ssz_checked(slices[2])?,
            d: BitList::<6>::decode_ssz_checked(slices[3])?,
            e: BitVector::<8>::decode_ssz_checked(slices[4])?,
        })
    }
}

impl HashTreeRoot for BitsStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            self.b.hash_tree_root(),
            self.c.hash_tree_root(),
            self.d.hash_tree_root(),
            self.e.hash_tree_root(),
        ])
    }
}

impl peam_ssz::ssz::SszElement for BitsStruct {}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveTestStruct {
    a: ProgressiveList<u8>,
    b: ProgressiveList<u64>,
    c: ProgressiveList<SmallTestStruct>,
    d: ProgressiveList<ProgressiveList<VarTestStruct>>,
}

impl SszEncode for ProgressiveTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        let d = self.d.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Variable(&c),
            EncodedContainerField::Variable(&d),
        ])
    }
}

impl SszDecode for ProgressiveTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            a: ProgressiveList::<u8>::decode_ssz(slices[0])?,
            b: ProgressiveList::<u64>::decode_ssz(slices[1])?,
            c: ProgressiveList::<SmallTestStruct>::decode_ssz(slices[2])?,
            d: ProgressiveList::<ProgressiveList<VarTestStruct>>::decode_ssz(slices[3])?,
        })
    }
}

impl HashTreeRoot for ProgressiveTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            self.b.hash_tree_root(),
            self.c.hash_tree_root(),
            self.d.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveBitsStruct {
    a: BitVector<256>,
    b: BitList<256>,
    c: ProgressiveBitlist,
    d: BitVector<257>,
    e: BitList<257>,
    f: ProgressiveBitlist,
    g: BitVector<1280>,
    h: BitList<1280>,
    i: ProgressiveBitlist,
    j: BitVector<1281>,
    k: BitList<1281>,
    l: ProgressiveBitlist,
}

impl SszEncode for ProgressiveBitsStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        let d = self.d.encode_ssz();
        let e = self.e.encode_ssz();
        let f = self.f.encode_ssz();
        let g = self.g.encode_ssz();
        let h = self.h.encode_ssz();
        let i = self.i.encode_ssz();
        let j = self.j.encode_ssz();
        let k = self.k.encode_ssz();
        let l = self.l.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Variable(&c),
            EncodedContainerField::Fixed(&d),
            EncodedContainerField::Variable(&e),
            EncodedContainerField::Variable(&f),
            EncodedContainerField::Fixed(&g),
            EncodedContainerField::Variable(&h),
            EncodedContainerField::Variable(&i),
            EncodedContainerField::Fixed(&j),
            EncodedContainerField::Variable(&k),
            EncodedContainerField::Variable(&l),
        ])
    }
}

impl SszDecode for ProgressiveBitsStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(33),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(161),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            a: BitVector::<256>::decode_ssz_checked(slices[0])?,
            b: BitList::<256>::decode_ssz_checked(slices[1])?,
            c: ProgressiveBitlist::decode_ssz(slices[2])?,
            d: BitVector::<257>::decode_ssz_checked(slices[3])?,
            e: BitList::<257>::decode_ssz_checked(slices[4])?,
            f: ProgressiveBitlist::decode_ssz(slices[5])?,
            g: BitVector::<1280>::decode_ssz_checked(slices[6])?,
            h: BitList::<1280>::decode_ssz_checked(slices[7])?,
            i: ProgressiveBitlist::decode_ssz(slices[8])?,
            j: BitVector::<1281>::decode_ssz_checked(slices[9])?,
            k: BitList::<1281>::decode_ssz_checked(slices[10])?,
            l: ProgressiveBitlist::decode_ssz(slices[11])?,
        })
    }
}

impl HashTreeRoot for ProgressiveBitsStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.a.hash_tree_root(),
            self.b.hash_tree_root(),
            self.c.hash_tree_root(),
            self.d.hash_tree_root(),
            self.e.hash_tree_root(),
            self.f.hash_tree_root(),
            self.g.hash_tree_root(),
            self.h.hash_tree_root(),
            self.i.hash_tree_root(),
            self.j.hash_tree_root(),
            self.k.hash_tree_root(),
            self.l.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveSingleFieldContainerTestStruct {
    a: u8,
}

impl SszEncode for ProgressiveSingleFieldContainerTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        encode_fields(&[EncodedContainerField::Fixed(&self.a.encode_ssz())])
    }
}

impl SszDecode for ProgressiveSingleFieldContainerTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(bytes, &[ContainerFieldKind::Fixed(1)])?;
        Ok(Self {
            a: u8::decode_ssz(slices[0])?,
        })
    }
}

impl HashTreeRoot for ProgressiveSingleFieldContainerTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_progressive_container(&[self.a.hash_tree_root()], &[true])
    }
}

impl SszFixedLen for ProgressiveSingleFieldContainerTestStruct {
    fn fixed_len() -> usize {
        1
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveSingleListContainerTestStruct {
    c: ProgressiveBitlist,
}

impl SszEncode for ProgressiveSingleListContainerTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let c = self.c.encode_ssz();
        encode_fields(&[EncodedContainerField::Variable(&c)])
    }
}

impl SszDecode for ProgressiveSingleListContainerTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(bytes, &[ContainerFieldKind::Variable])?;
        Ok(Self {
            c: ProgressiveBitlist::decode_ssz(slices[0])?,
        })
    }
}

impl HashTreeRoot for ProgressiveSingleListContainerTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_progressive_container(
            &[self.c.hash_tree_root()],
            &[false, false, false, false, true],
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveVarTestStruct {
    a: u8,
    b: SszList<u16, 123>,
    c: ProgressiveBitlist,
}

impl SszEncode for ProgressiveVarTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Variable(&c),
        ])
    }
}

impl SszDecode for ProgressiveVarTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            a: u8::decode_ssz(slices[0])?,
            b: SszList::<u16, 123>::decode_ssz_checked(slices[1])?,
            c: ProgressiveBitlist::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for ProgressiveVarTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_progressive_container(
            &[
                self.a.hash_tree_root(),
                self.b.hash_tree_root(),
                self.c.hash_tree_root(),
            ],
            &[true, false, true, false, true],
        )
    }
}

impl peam_ssz::ssz::SszElement for ProgressiveVarTestStruct {}

#[derive(Debug, PartialEq, Eq)]
struct ProgressiveComplexTestStruct {
    a: u8,
    b: SszList<u16, 123>,
    c: ProgressiveBitlist,
    d: ProgressiveList<u64>,
    e: ProgressiveList<SmallTestStruct>,
    f: ProgressiveList<ProgressiveList<VarTestStruct>>,
    g: SszList<ProgressiveSingleFieldContainerTestStruct, 10>,
    h: ProgressiveList<ProgressiveVarTestStruct>,
}

impl SszEncode for ProgressiveComplexTestStruct {
    fn encode_ssz(&self) -> Vec<u8> {
        let a = self.a.encode_ssz();
        let b = self.b.encode_ssz();
        let c = self.c.encode_ssz();
        let d = self.d.encode_ssz();
        let e = self.e.encode_ssz();
        let f = self.f.encode_ssz();
        let g = self.g.encode_ssz();
        let h = self.h.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&a),
            EncodedContainerField::Variable(&b),
            EncodedContainerField::Variable(&c),
            EncodedContainerField::Variable(&d),
            EncodedContainerField::Variable(&e),
            EncodedContainerField::Variable(&f),
            EncodedContainerField::Variable(&g),
            EncodedContainerField::Variable(&h),
        ])
    }
}

impl SszDecode for ProgressiveComplexTestStruct {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            a: u8::decode_ssz(slices[0])?,
            b: SszList::<u16, 123>::decode_ssz_checked(slices[1])?,
            c: ProgressiveBitlist::decode_ssz(slices[2])?,
            d: ProgressiveList::<u64>::decode_ssz(slices[3])?,
            e: ProgressiveList::<SmallTestStruct>::decode_ssz(slices[4])?,
            f: ProgressiveList::<ProgressiveList<VarTestStruct>>::decode_ssz(slices[5])?,
            g: SszList::<ProgressiveSingleFieldContainerTestStruct, 10>::decode_ssz_checked(
                slices[6],
            )?,
            h: ProgressiveList::<ProgressiveVarTestStruct>::decode_ssz(slices[7])?,
        })
    }
}

impl HashTreeRoot for ProgressiveComplexTestStruct {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_progressive_container(
            &[
                self.a.hash_tree_root(),
                self.b.hash_tree_root(),
                self.c.hash_tree_root(),
                self.d.hash_tree_root(),
                self.e.hash_tree_root(),
                self.f.hash_tree_root(),
                self.g.hash_tree_root(),
                self.h.hash_tree_root(),
            ],
            &[
                true, false, true, false, true, false, false, false, true, false, false, false,
                true, true, false, false, false, false, false, false, true, true,
            ],
        )
    }
}

#[derive(Debug, PartialEq)]
enum CompatibleUnionA {
    V1(ProgressiveSingleFieldContainerTestStruct),
}

impl SszEncode for CompatibleUnionA {
    fn encode_ssz(&self) -> Vec<u8> {
        match self {
            Self::V1(value) => {
                let mut out = Vec::with_capacity(1 + value.encode_ssz().len());
                out.push(1);
                out.extend_from_slice(&value.encode_ssz());
                out
            }
        }
    }
}

impl SszDecode for CompatibleUnionA {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (selector, payload) = split_union_bytes(bytes)?;
        match selector {
            1 => Ok(Self::V1(
                ProgressiveSingleFieldContainerTestStruct::decode_ssz(payload)?,
            )),
            other => Err(format!("invalid union selector: {other}")),
        }
    }
}

impl HashTreeRoot for CompatibleUnionA {
    fn hash_tree_root(&self) -> [u8; 32] {
        match self {
            Self::V1(value) => mix_selector_into_root(value.hash_tree_root(), 1),
        }
    }
}

#[derive(Debug, PartialEq)]
enum CompatibleUnionBC {
    V2(ProgressiveSingleListContainerTestStruct),
    V3(ProgressiveVarTestStruct),
}

impl SszEncode for CompatibleUnionBC {
    fn encode_ssz(&self) -> Vec<u8> {
        match self {
            Self::V2(value) => encode_union_variant(2, value),
            Self::V3(value) => encode_union_variant(3, value),
        }
    }
}

impl SszDecode for CompatibleUnionBC {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (selector, payload) = split_union_bytes(bytes)?;
        match selector {
            2 => Ok(Self::V2(
                ProgressiveSingleListContainerTestStruct::decode_ssz(payload)?,
            )),
            3 => Ok(Self::V3(ProgressiveVarTestStruct::decode_ssz(payload)?)),
            other => Err(format!("invalid union selector: {other}")),
        }
    }
}

impl HashTreeRoot for CompatibleUnionBC {
    fn hash_tree_root(&self) -> [u8; 32] {
        match self {
            Self::V2(value) => mix_selector_into_root(value.hash_tree_root(), 2),
            Self::V3(value) => mix_selector_into_root(value.hash_tree_root(), 3),
        }
    }
}

#[derive(Debug, PartialEq)]
enum CompatibleUnionABCA {
    V1(ProgressiveSingleFieldContainerTestStruct),
    V2(ProgressiveSingleListContainerTestStruct),
    V3(ProgressiveVarTestStruct),
    V4(ProgressiveSingleFieldContainerTestStruct),
}

impl SszEncode for CompatibleUnionABCA {
    fn encode_ssz(&self) -> Vec<u8> {
        match self {
            Self::V1(value) => encode_union_variant(1, value),
            Self::V2(value) => encode_union_variant(2, value),
            Self::V3(value) => encode_union_variant(3, value),
            Self::V4(value) => encode_union_variant(4, value),
        }
    }
}

impl SszDecode for CompatibleUnionABCA {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let (selector, payload) = split_union_bytes(bytes)?;
        match selector {
            1 => Ok(Self::V1(
                ProgressiveSingleFieldContainerTestStruct::decode_ssz(payload)?,
            )),
            2 => Ok(Self::V2(
                ProgressiveSingleListContainerTestStruct::decode_ssz(payload)?,
            )),
            3 => Ok(Self::V3(ProgressiveVarTestStruct::decode_ssz(payload)?)),
            4 => Ok(Self::V4(
                ProgressiveSingleFieldContainerTestStruct::decode_ssz(payload)?,
            )),
            other => Err(format!("invalid union selector: {other}")),
        }
    }
}

impl HashTreeRoot for CompatibleUnionABCA {
    fn hash_tree_root(&self) -> [u8; 32] {
        match self {
            Self::V1(value) => mix_selector_into_root(value.hash_tree_root(), 1),
            Self::V2(value) => mix_selector_into_root(value.hash_tree_root(), 2),
            Self::V3(value) => mix_selector_into_root(value.hash_tree_root(), 3),
            Self::V4(value) => mix_selector_into_root(value.hash_tree_root(), 4),
        }
    }
}

#[test]
fn containers_single_field_valid() {
    check_container_valid_cases::<SingleFieldTestStruct>("SingleFieldTestStruct", "containers");
}

#[test]
fn containers_single_field_invalid() {
    check_container_invalid_cases::<SingleFieldTestStruct>("SingleFieldTestStruct", "containers");
}

#[test]
fn containers_small_valid() {
    check_container_valid_cases::<SmallTestStruct>("SmallTestStruct", "containers");
}

#[test]
fn containers_small_invalid() {
    check_container_invalid_cases::<SmallTestStruct>("SmallTestStruct", "containers");
}

#[test]
fn containers_fixed_valid() {
    check_container_valid_cases::<FixedTestStruct>("FixedTestStruct", "containers");
}

#[test]
fn containers_fixed_invalid() {
    check_container_invalid_cases::<FixedTestStruct>("FixedTestStruct", "containers");
}

#[test]
fn containers_var_valid() {
    check_container_valid_cases::<VarTestStruct>("VarTestStruct", "containers");
}

#[test]
fn containers_var_invalid() {
    check_container_invalid_cases::<VarTestStruct>("VarTestStruct", "containers");
}

#[test]
fn containers_complex_valid() {
    check_container_roundtrip_cases::<ComplexTestStruct>("ComplexTestStruct", "containers");
}

#[test]
fn containers_complex_invalid() {
    check_container_invalid_cases::<ComplexTestStruct>("ComplexTestStruct", "containers");
}

#[test]
fn containers_bits_valid() {
    check_container_roundtrip_cases::<BitsStruct>("BitsStruct", "containers");
}

#[test]
fn containers_bits_invalid() {
    check_container_invalid_cases::<BitsStruct>("BitsStruct", "containers");
}

#[test]
fn containers_progressive_valid() {
    check_container_roundtrip_cases::<ProgressiveTestStruct>("ProgressiveTestStruct", "containers");
}

#[test]
fn containers_progressive_invalid() {
    check_container_invalid_cases::<ProgressiveTestStruct>("ProgressiveTestStruct", "containers");
}

#[test]
fn containers_progressive_bits_valid() {
    check_container_roundtrip_cases::<ProgressiveBitsStruct>(
        "ProgressiveBitsStruct",
        "containers",
    );
}

#[test]
fn containers_progressive_bits_invalid() {
    check_container_invalid_cases::<ProgressiveBitsStruct>("ProgressiveBitsStruct", "containers");
}

#[test]
fn progressive_containers_valid() {
    check_container_roundtrip_cases::<ProgressiveSingleFieldContainerTestStruct>(
        "ProgressiveSingleFieldContainerTestStruct",
        "progressive_containers",
    );
    check_container_roundtrip_cases::<ProgressiveSingleListContainerTestStruct>(
        "ProgressiveSingleListContainerTestStruct",
        "progressive_containers",
    );
    check_container_roundtrip_cases::<ProgressiveVarTestStruct>(
        "ProgressiveVarTestStruct",
        "progressive_containers",
    );
    check_container_roundtrip_cases::<ProgressiveComplexTestStruct>(
        "ProgressiveComplexTestStruct",
        "progressive_containers",
    );
}

#[test]
fn progressive_containers_invalid() {
    check_container_invalid_cases::<ProgressiveSingleFieldContainerTestStruct>(
        "ProgressiveSingleFieldContainerTestStruct",
        "progressive_containers",
    );
    check_container_invalid_cases::<ProgressiveSingleListContainerTestStruct>(
        "ProgressiveSingleListContainerTestStruct",
        "progressive_containers",
    );
    check_container_invalid_cases::<ProgressiveVarTestStruct>(
        "ProgressiveVarTestStruct",
        "progressive_containers",
    );
    check_container_invalid_cases::<ProgressiveComplexTestStruct>(
        "ProgressiveComplexTestStruct",
        "progressive_containers",
    );
}

#[test]
fn compatible_unions_valid() {
    for (case_path, case_name) in loader::ssz_generic_valid_cases("compatible_unions") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));

        if case_name.starts_with("CompatibleUnionABCA") {
            check_union_roundtrip::<CompatibleUnionABCA>(&ssz, &expected_root, &case_name);
        } else if case_name.starts_with("CompatibleUnionBC") {
            check_union_roundtrip::<CompatibleUnionBC>(&ssz, &expected_root, &case_name);
        } else if case_name.starts_with("CompatibleUnionA") {
            check_union_roundtrip::<CompatibleUnionA>(&ssz, &expected_root, &case_name);
        } else {
            panic!("{case_name}: unknown compatible union type");
        }
    }
}

#[test]
fn compatible_unions_invalid() {
    for (case_path, case_name) in loader::ssz_generic_invalid_cases("compatible_unions") {
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));

        if case_name.starts_with("CompatibleUnionABCA") {
            assert!(CompatibleUnionABCA::decode_ssz(&ssz).is_err(), "{case_name}");
        } else if case_name.starts_with("CompatibleUnionBC") {
            assert!(CompatibleUnionBC::decode_ssz(&ssz).is_err(), "{case_name}");
        } else if case_name.starts_with("CompatibleUnionA") {
            assert!(CompatibleUnionA::decode_ssz(&ssz).is_err(), "{case_name}");
        } else {
            panic!("{case_name}: unknown compatible union type");
        }
    }
}

fn check_container_valid_cases<T>(prefix: &str, handler: &str)
where
    T: for<'de> Deserialize<'de>
        + SszDecode
        + SszEncode
        + HashTreeRoot
        + std::fmt::Debug
        + PartialEq,
{
    for (case_path, case_name) in loader::ssz_generic_valid_cases(handler) {
        if !case_name.starts_with(prefix) {
            continue;
        }
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let expected: T =
            serde_yaml::from_value(loader::read_yaml_value(&case_path.join("value.yaml")))
                .unwrap_or_else(|e| panic!("{case_name}: yaml parse failed: {e}"));

        let decoded =
            T::decode_ssz(&ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
        assert_eq!(decoded, expected, "{case_name}: decoded value mismatch");
        assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
        assert_eq!(
            decoded.hash_tree_root(),
            expected_root,
            "{case_name}: hash tree root mismatch"
        );
    }
}

fn check_union_roundtrip<T>(ssz: &[u8], expected_root: &[u8; 32], case_name: &str)
where
    T: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug,
{
    let decoded =
        T::decode_ssz(ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn split_union_bytes(bytes: &[u8]) -> Result<(u8, &[u8]), String> {
    let (selector, payload) = bytes
        .split_first()
        .ok_or_else(|| "union requires at least one selector byte".to_string())?;
    if *selector > 127 {
        return Err(format!("invalid union selector: {selector}"));
    }
    Ok((*selector, payload))
}

fn encode_union_variant<T: SszEncode>(selector: u8, value: &T) -> Vec<u8> {
    let payload = value.encode_ssz();
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(selector);
    out.extend_from_slice(&payload);
    out
}

fn mix_selector_into_root(root: [u8; 32], selector: u8) -> [u8; 32] {
    mix_in_selector(&Bytes32::from(root), selector).as_array()
}

fn check_container_invalid_cases<T>(prefix: &str, handler: &str)
where
    T: SszDecode,
{
    for (case_path, case_name) in loader::ssz_generic_invalid_cases(handler) {
        if !case_name.starts_with(prefix) {
            continue;
        }
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        assert!(T::decode_ssz(&ssz).is_err(), "{case_name}: should fail");
    }
}

fn check_container_roundtrip_cases<T>(prefix: &str, handler: &str)
where
    T: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug,
{
    for (case_path, case_name) in loader::ssz_generic_valid_cases(handler) {
        if !case_name.starts_with(prefix) {
            continue;
        }
        let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
        let expected_root = loader::parse_root(&case_path.join("meta.yaml"));
        let decoded =
            T::decode_ssz(&ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
        assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
        assert_eq!(
            decoded.hash_tree_root(),
            expected_root,
            "{case_name}: hash tree root mismatch"
        );
    }
}
