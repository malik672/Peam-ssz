use peam_ssz::ssz::{HashTreeRoot, SszDecode, SszElement, SszEncode, SszFixedLen};
use peam_ssz::types::bitlist::{BitList, BitVector};
use peam_ssz::types::collections::{SszList, SszVector};
use peam_ssz::types::container::{
    ContainerFieldKind, EncodedContainerField, decode_field_slices, encode_fields,
    hash_tree_root_from_field_roots,
};
use spec_tests::loader::{self, Archive};

const MINIMAL_FORKS: &[&str] = &[
    "phase0",
    "altair",
    "bellatrix",
    "capella",
    "deneb",
    "electra",
    "fulu",
    "gloas",
    "eip7805",
];
const LEGACY_ATTESTATION_FORKS: &[&str] = &["phase0", "altair", "bellatrix", "capella", "deneb"];
const ALTAIR_PLUS_FORKS: &[&str] = &[
    "altair", "bellatrix", "capella", "deneb", "electra", "fulu", "gloas", "eip7805",
];
const ALTAIR_ONLY_FORKS: &[&str] = &["altair"];

const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
const SLOTS_PER_HISTORICAL_ROOT: usize = 64;
const DEPOSIT_PROOF_LEN: usize = 33;
const HISTORICAL_ROOTS_LIMIT: usize = 16_777_216;
const VALIDATOR_REGISTRY_LIMIT: usize = 1_099_511_627_776;
const EPOCHS_PER_HISTORICAL_VECTOR: usize = 64;
const EPOCHS_PER_SLASHINGS_VECTOR: usize = 64;
const EPOCHS_PER_ETH1_VOTING_PERIOD: usize = 4;
const SLOTS_PER_EPOCH: usize = 8;
const MAX_PROPOSER_SLASHINGS: usize = 16;
const MAX_ATTESTER_SLASHINGS: usize = 2;
const MAX_ATTESTATIONS: usize = 128;
const MAX_DEPOSITS: usize = 16;
const MAX_VOLUNTARY_EXITS: usize = 16;
const JUSTIFICATION_BITS_LENGTH: usize = 4;
const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824;
const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;
const BYTES_PER_LOGS_BLOOM: usize = 256;
const MAX_EXTRA_DATA_BYTES: usize = 32;
const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;
const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 4;
const EXECUTION_BRANCH_LEN: usize = 4;
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const BYTES_PER_FIELD_ELEMENT: usize = 32;
const BYTES_PER_BLOB: usize = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;
const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: usize = 17;
const SYNC_COMMITTEE_SIZE: usize = 32;
const SYNC_SUBCOMMITTEE_SIZE: usize = 8;
const CURRENT_SYNC_COMMITTEE_BRANCH_LEN: usize = 5;
const NEXT_SYNC_COMMITTEE_BRANCH_LEN: usize = 5;
const FINALITY_BRANCH_LEN: usize = 6;
const ETH1_DATA_VOTES_LIMIT: usize = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH;
const PENDING_ATTESTATIONS_LIMIT: usize = MAX_ATTESTATIONS * SLOTS_PER_EPOCH;

fn check_roundtrip_root<T: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug>(
    ssz: &[u8],
    expected_root: &[u8; 32],
    case_name: &str,
) {
    let decoded =
        T::decode_ssz(ssz).unwrap_or_else(|e| panic!("{case_name}: decode failed: {e}"));
    assert_eq!(decoded.encode_ssz(), ssz, "{case_name}: roundtrip mismatch");
    assert_eq!(
        decoded.hash_tree_root(),
        *expected_root,
        "{case_name}: hash tree root mismatch"
    );
}

fn run_shared_minimal_type<T: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug>(
    type_name: &str,
) {
    run_minimal_type_for_forks::<T>(type_name, MINIMAL_FORKS);
}

fn run_minimal_type_for_forks<T: SszDecode + SszEncode + HashTreeRoot + std::fmt::Debug>(
    type_name: &str,
    forks: &[&str],
) {
    if !loader::archive_available(Archive::Minimal) {
        eprintln!("minimal spec vectors not available locally; skipping {type_name}");
        return;
    }
    let mut found_any = false;
    for fork in forks {
        let cases = loader::ssz_static_cases(Archive::Minimal, fork, type_name);
        if cases.is_empty() {
            continue;
        }
        found_any = true;
        for (case_path, case_name) in cases {
            let ssz = loader::read_ssz_snappy(&case_path.join("serialized.ssz_snappy"));
            let expected_root = loader::parse_root(&case_path.join("roots.yaml"));
            check_roundtrip_root::<T>(&ssz, &expected_root, &format!("{fork}/{type_name}/{case_name}"));
        }
    }
    assert!(found_any, "{type_name}: no test cases found in local mainnet archive");
}

#[derive(Debug, PartialEq, Eq)]
struct Fork {
    previous_version: [u8; 4],
    current_version: [u8; 4],
    epoch: u64,
}

impl SszEncode for Fork {
    fn encode_ssz(&self) -> Vec<u8> {
        let previous_version = self.previous_version.encode_ssz();
        let current_version = self.current_version.encode_ssz();
        let epoch = self.epoch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&previous_version),
            EncodedContainerField::Fixed(&current_version),
            EncodedContainerField::Fixed(&epoch),
        ])
    }
}

impl SszDecode for Fork {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(4),
                ContainerFieldKind::Fixed(4),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            previous_version: <[u8; 4]>::decode_ssz(slices[0])?,
            current_version: <[u8; 4]>::decode_ssz(slices[1])?,
            epoch: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for Fork {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.previous_version.hash_tree_root(),
            self.current_version.hash_tree_root(),
            self.epoch.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for Fork {
    fn fixed_len() -> usize {
        16
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ForkData {
    current_version: [u8; 4],
    genesis_validators_root: [u8; 32],
}

impl SszEncode for ForkData {
    fn encode_ssz(&self) -> Vec<u8> {
        let current_version = self.current_version.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&current_version),
            EncodedContainerField::Fixed(&genesis_validators_root),
        ])
    }
}

impl SszDecode for ForkData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(4), ContainerFieldKind::Fixed(32)],
        )?;
        Ok(Self {
            current_version: <[u8; 4]>::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for ForkData {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.current_version.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for ForkData {
    fn fixed_len() -> usize {
        36
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Checkpoint {
    epoch: u64,
    root: [u8; 32],
}

impl SszEncode for Checkpoint {
    fn encode_ssz(&self) -> Vec<u8> {
        let epoch = self.epoch.encode_ssz();
        let root = self.root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&epoch),
            EncodedContainerField::Fixed(&root),
        ])
    }
}

impl SszDecode for Checkpoint {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(8), ContainerFieldKind::Fixed(32)],
        )?;
        Ok(Self {
            epoch: u64::decode_ssz(slices[0])?,
            root: <[u8; 32]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for Checkpoint {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[self.epoch.hash_tree_root(), self.root.hash_tree_root()])
    }
}

impl SszFixedLen for Checkpoint {
    fn fixed_len() -> usize {
        40
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body_root: [u8; 32],
}

impl SszEncode for BeaconBlockHeader {
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

impl HashTreeRoot for BeaconBlockHeader {
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

#[derive(Debug, PartialEq, Eq)]
struct SignedBeaconBlockHeader {
    message: BeaconBlockHeader,
    signature: [u8; 96],
}

impl SszEncode for SignedBeaconBlockHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SignedBeaconBlockHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(112), ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: BeaconBlockHeader::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SignedBeaconBlockHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SigningData {
    object_root: [u8; 32],
    domain: [u8; 32],
}

impl SszEncode for SigningData {
    fn encode_ssz(&self) -> Vec<u8> {
        let object_root = self.object_root.encode_ssz();
        let domain = self.domain.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&object_root),
            EncodedContainerField::Fixed(&domain),
        ])
    }
}

impl SszDecode for SigningData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(32), ContainerFieldKind::Fixed(32)],
        )?;
        Ok(Self {
            object_root: <[u8; 32]>::decode_ssz(slices[0])?,
            domain: <[u8; 32]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SigningData {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.object_root.hash_tree_root(),
            self.domain.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SigningData {
    fn fixed_len() -> usize {
        64
    }
}

#[derive(Debug, PartialEq, Eq)]
struct VoluntaryExit {
    epoch: u64,
    validator_index: u64,
}

impl SszEncode for VoluntaryExit {
    fn encode_ssz(&self) -> Vec<u8> {
        let epoch = self.epoch.encode_ssz();
        let validator_index = self.validator_index.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&epoch),
            EncodedContainerField::Fixed(&validator_index),
        ])
    }
}

impl SszDecode for VoluntaryExit {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(8), ContainerFieldKind::Fixed(8)],
        )?;
        Ok(Self {
            epoch: u64::decode_ssz(slices[0])?,
            validator_index: u64::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for VoluntaryExit {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.epoch.hash_tree_root(),
            self.validator_index.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for VoluntaryExit {
    fn fixed_len() -> usize {
        16
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignedVoluntaryExit {
    message: VoluntaryExit,
    signature: [u8; 96],
}

impl SszEncode for SignedVoluntaryExit {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SignedVoluntaryExit {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(16), ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: VoluntaryExit::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SignedVoluntaryExit {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DepositMessage {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    amount: u64,
}

impl SszEncode for DepositMessage {
    fn encode_ssz(&self) -> Vec<u8> {
        let pubkey = self.pubkey.encode_ssz();
        let withdrawal_credentials = self.withdrawal_credentials.encode_ssz();
        let amount = self.amount.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&pubkey),
            EncodedContainerField::Fixed(&withdrawal_credentials),
            EncodedContainerField::Fixed(&amount),
        ])
    }
}

impl SszDecode for DepositMessage {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            pubkey: <[u8; 48]>::decode_ssz(slices[0])?,
            withdrawal_credentials: <[u8; 32]>::decode_ssz(slices[1])?,
            amount: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for DepositMessage {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.pubkey.hash_tree_root(),
            self.withdrawal_credentials.hash_tree_root(),
            self.amount.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DepositData {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    amount: u64,
    signature: [u8; 96],
}

impl SszEncode for DepositData {
    fn encode_ssz(&self) -> Vec<u8> {
        let pubkey = self.pubkey.encode_ssz();
        let withdrawal_credentials = self.withdrawal_credentials.encode_ssz();
        let amount = self.amount.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&pubkey),
            EncodedContainerField::Fixed(&withdrawal_credentials),
            EncodedContainerField::Fixed(&amount),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for DepositData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            pubkey: <[u8; 48]>::decode_ssz(slices[0])?,
            withdrawal_credentials: <[u8; 32]>::decode_ssz(slices[1])?,
            amount: u64::decode_ssz(slices[2])?,
            signature: <[u8; 96]>::decode_ssz(slices[3])?,
        })
    }
}

impl HashTreeRoot for DepositData {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.pubkey.hash_tree_root(),
            self.withdrawal_credentials.hash_tree_root(),
            self.amount.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Eth1Data {
    deposit_root: [u8; 32],
    deposit_count: u64,
    block_hash: [u8; 32],
}

impl SszEncode for Eth1Data {
    fn encode_ssz(&self) -> Vec<u8> {
        let deposit_root = self.deposit_root.encode_ssz();
        let deposit_count = self.deposit_count.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&deposit_root),
            EncodedContainerField::Fixed(&deposit_count),
            EncodedContainerField::Fixed(&block_hash),
        ])
    }
}

impl SszDecode for Eth1Data {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
            ],
        )?;
        Ok(Self {
            deposit_root: <[u8; 32]>::decode_ssz(slices[0])?,
            deposit_count: u64::decode_ssz(slices[1])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for Eth1Data {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.deposit_root.hash_tree_root(),
            self.deposit_count.hash_tree_root(),
            self.block_hash.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Eth1Block {
    timestamp: u64,
    deposit_root: [u8; 32],
    deposit_count: u64,
}

impl SszEncode for Eth1Block {
    fn encode_ssz(&self) -> Vec<u8> {
        let timestamp = self.timestamp.encode_ssz();
        let deposit_root = self.deposit_root.encode_ssz();
        let deposit_count = self.deposit_count.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Fixed(&deposit_root),
            EncodedContainerField::Fixed(&deposit_count),
        ])
    }
}

impl SszDecode for Eth1Block {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            timestamp: u64::decode_ssz(slices[0])?,
            deposit_root: <[u8; 32]>::decode_ssz(slices[1])?,
            deposit_count: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for Eth1Block {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.timestamp.hash_tree_root(),
            self.deposit_root.hash_tree_root(),
            self.deposit_count.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Validator {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
}

impl SszEncode for Validator {
    fn encode_ssz(&self) -> Vec<u8> {
        let pubkey = self.pubkey.encode_ssz();
        let withdrawal_credentials = self.withdrawal_credentials.encode_ssz();
        let effective_balance = self.effective_balance.encode_ssz();
        let slashed = self.slashed.encode_ssz();
        let activation_eligibility_epoch = self.activation_eligibility_epoch.encode_ssz();
        let activation_epoch = self.activation_epoch.encode_ssz();
        let exit_epoch = self.exit_epoch.encode_ssz();
        let withdrawable_epoch = self.withdrawable_epoch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&pubkey),
            EncodedContainerField::Fixed(&withdrawal_credentials),
            EncodedContainerField::Fixed(&effective_balance),
            EncodedContainerField::Fixed(&slashed),
            EncodedContainerField::Fixed(&activation_eligibility_epoch),
            EncodedContainerField::Fixed(&activation_epoch),
            EncodedContainerField::Fixed(&exit_epoch),
            EncodedContainerField::Fixed(&withdrawable_epoch),
        ])
    }
}

impl SszDecode for Validator {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            pubkey: <[u8; 48]>::decode_ssz(slices[0])?,
            withdrawal_credentials: <[u8; 32]>::decode_ssz(slices[1])?,
            effective_balance: u64::decode_ssz(slices[2])?,
            slashed: bool::decode_ssz(slices[3])?,
            activation_eligibility_epoch: u64::decode_ssz(slices[4])?,
            activation_epoch: u64::decode_ssz(slices[5])?,
            exit_epoch: u64::decode_ssz(slices[6])?,
            withdrawable_epoch: u64::decode_ssz(slices[7])?,
        })
    }
}

impl HashTreeRoot for Validator {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.pubkey.hash_tree_root(),
            self.withdrawal_credentials.hash_tree_root(),
            self.effective_balance.hash_tree_root(),
            self.slashed.hash_tree_root(),
            self.activation_eligibility_epoch.hash_tree_root(),
            self.activation_epoch.hash_tree_root(),
            self.exit_epoch.hash_tree_root(),
            self.withdrawable_epoch.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for Validator {
    fn fixed_len() -> usize {
        121
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AttestationData {
    slot: u64,
    index: u64,
    beacon_block_root: [u8; 32],
    source: Checkpoint,
    target: Checkpoint,
}

impl SszEncode for AttestationData {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let index = self.index.encode_ssz();
        let beacon_block_root = self.beacon_block_root.encode_ssz();
        let source = self.source.encode_ssz();
        let target = self.target.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&index),
            EncodedContainerField::Fixed(&beacon_block_root),
            EncodedContainerField::Fixed(&source),
            EncodedContainerField::Fixed(&target),
        ])
    }
}

impl SszDecode for AttestationData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            index: u64::decode_ssz(slices[1])?,
            beacon_block_root: <[u8; 32]>::decode_ssz(slices[2])?,
            source: Checkpoint::decode_ssz(slices[3])?,
            target: Checkpoint::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for AttestationData {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.index.hash_tree_root(),
            self.beacon_block_root.hash_tree_root(),
            self.source.hash_tree_root(),
            self.target.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for AttestationData {
    fn fixed_len() -> usize {
        128
    }
}

#[derive(Debug, PartialEq, Eq)]
struct IndexedAttestation {
    attesting_indices: SszList<u64, MAX_VALIDATORS_PER_COMMITTEE>,
    data: AttestationData,
    signature: [u8; 96],
}

impl SszEncode for IndexedAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let attesting_indices = self.attesting_indices.encode_ssz();
        let data = self.data.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attesting_indices),
            EncodedContainerField::Fixed(&data),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for IndexedAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(128),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            attesting_indices: SszList::<u64, MAX_VALIDATORS_PER_COMMITTEE>::decode_ssz_checked(
                slices[0],
            )?,
            data: AttestationData::decode_ssz(slices[1])?,
            signature: <[u8; 96]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for IndexedAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attesting_indices.hash_tree_root(),
            self.data.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PendingAttestation {
    aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    data: AttestationData,
    inclusion_delay: u64,
    proposer_index: u64,
}

impl SszEncode for PendingAttestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let aggregation_bits = self.aggregation_bits.encode_ssz();
        let data = self.data.encode_ssz();
        let inclusion_delay = self.inclusion_delay.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&aggregation_bits),
            EncodedContainerField::Fixed(&data),
            EncodedContainerField::Fixed(&inclusion_delay),
            EncodedContainerField::Fixed(&proposer_index),
        ])
    }
}

impl SszDecode for PendingAttestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(128),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            aggregation_bits: BitList::<MAX_VALIDATORS_PER_COMMITTEE>::decode_ssz_checked(
                slices[0],
            )?,
            data: AttestationData::decode_ssz(slices[1])?,
            inclusion_delay: u64::decode_ssz(slices[2])?,
            proposer_index: u64::decode_ssz(slices[3])?,
        })
    }
}

impl HashTreeRoot for PendingAttestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.aggregation_bits.hash_tree_root(),
            self.data.hash_tree_root(),
            self.inclusion_delay.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Attestation {
    aggregation_bits: BitList<MAX_VALIDATORS_PER_COMMITTEE>,
    data: AttestationData,
    signature: [u8; 96],
}

impl SszEncode for Attestation {
    fn encode_ssz(&self) -> Vec<u8> {
        let aggregation_bits = self.aggregation_bits.encode_ssz();
        let data = self.data.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&aggregation_bits),
            EncodedContainerField::Fixed(&data),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for Attestation {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(128),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            aggregation_bits: BitList::<MAX_VALIDATORS_PER_COMMITTEE>::decode_ssz_checked(
                slices[0],
            )?,
            data: AttestationData::decode_ssz(slices[1])?,
            signature: <[u8; 96]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for Attestation {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.aggregation_bits.hash_tree_root(),
            self.data.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
}

impl SszEncode for ProposerSlashing {
    fn encode_ssz(&self) -> Vec<u8> {
        let signed_header_1 = self.signed_header_1.encode_ssz();
        let signed_header_2 = self.signed_header_2.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&signed_header_1),
            EncodedContainerField::Fixed(&signed_header_2),
        ])
    }
}

impl SszDecode for ProposerSlashing {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(208), ContainerFieldKind::Fixed(208)],
        )?;
        Ok(Self {
            signed_header_1: SignedBeaconBlockHeader::decode_ssz(slices[0])?,
            signed_header_2: SignedBeaconBlockHeader::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for ProposerSlashing {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.signed_header_1.hash_tree_root(),
            self.signed_header_2.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AttesterSlashing {
    attestation_1: IndexedAttestation,
    attestation_2: IndexedAttestation,
}

impl SszEncode for AttesterSlashing {
    fn encode_ssz(&self) -> Vec<u8> {
        let attestation_1 = self.attestation_1.encode_ssz();
        let attestation_2 = self.attestation_2.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attestation_1),
            EncodedContainerField::Variable(&attestation_2),
        ])
    }
}

impl SszDecode for AttesterSlashing {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Variable],
        )?;
        Ok(Self {
            attestation_1: IndexedAttestation::decode_ssz(slices[0])?,
            attestation_2: IndexedAttestation::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for AttesterSlashing {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attestation_1.hash_tree_root(),
            self.attestation_2.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AggregateAndProof {
    aggregator_index: u64,
    aggregate: Attestation,
    selection_proof: [u8; 96],
}

impl SszEncode for AggregateAndProof {
    fn encode_ssz(&self) -> Vec<u8> {
        let aggregator_index = self.aggregator_index.encode_ssz();
        let aggregate = self.aggregate.encode_ssz();
        let selection_proof = self.selection_proof.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&aggregator_index),
            EncodedContainerField::Variable(&aggregate),
            EncodedContainerField::Fixed(&selection_proof),
        ])
    }
}

impl SszDecode for AggregateAndProof {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            aggregator_index: u64::decode_ssz(slices[0])?,
            aggregate: Attestation::decode_ssz(slices[1])?,
            selection_proof: <[u8; 96]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for AggregateAndProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.aggregator_index.hash_tree_root(),
            self.aggregate.hash_tree_root(),
            self.selection_proof.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignedAggregateAndProof {
    message: AggregateAndProof,
    signature: [u8; 96],
}

impl SszEncode for SignedAggregateAndProof {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SignedAggregateAndProof {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices =
            decode_field_slices(bytes, &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)])?;
        Ok(Self {
            message: AggregateAndProof::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SignedAggregateAndProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Deposit {
    proof: SszVector<[u8; 32], DEPOSIT_PROOF_LEN>,
    data: DepositData,
}

impl SszEncode for Deposit {
    fn encode_ssz(&self) -> Vec<u8> {
        let proof = self.proof.encode_ssz();
        let data = self.data.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&proof),
            EncodedContainerField::Fixed(&data),
        ])
    }
}

impl SszDecode for Deposit {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(32 * 33), ContainerFieldKind::Fixed(184)],
        )?;
        Ok(Self {
            proof: SszVector::<[u8; 32], DEPOSIT_PROOF_LEN>::decode_ssz_checked(slices[0])?,
            data: DepositData::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for Deposit {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[self.proof.hash_tree_root(), self.data.hash_tree_root()])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HistoricalBatch {
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
}

impl SszEncode for HistoricalBatch {
    fn encode_ssz(&self) -> Vec<u8> {
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
        ])
    }
}

impl SszDecode for HistoricalBatch {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let roots_len = 32 * SLOTS_PER_HISTORICAL_ROOT;
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(roots_len), ContainerFieldKind::Fixed(roots_len)],
        )?;
        Ok(Self {
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(
                slices[0],
            )?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(
                slices[1],
            )?,
        })
    }
}

impl HashTreeRoot for HistoricalBatch {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SyncAggregate {
    sync_committee_bits: BitVector<SYNC_COMMITTEE_SIZE>,
    sync_committee_signature: [u8; 96],
}

impl SszEncode for SyncAggregate {
    fn encode_ssz(&self) -> Vec<u8> {
        let sync_committee_bits = self.sync_committee_bits.encode_ssz();
        let sync_committee_signature = self.sync_committee_signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&sync_committee_bits),
            EncodedContainerField::Fixed(&sync_committee_signature),
        ])
    }
}

impl SszDecode for SyncAggregate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(64), ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            sync_committee_bits: BitVector::<SYNC_COMMITTEE_SIZE>::decode_ssz_checked(slices[0])?,
            sync_committee_signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SyncAggregate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.sync_committee_bits.hash_tree_root(),
            self.sync_committee_signature.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SyncAggregate {
    fn fixed_len() -> usize {
        160
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SyncCommittee {
    pubkeys: SszVector<[u8; 48], SYNC_COMMITTEE_SIZE>,
    aggregate_pubkey: [u8; 48],
}

impl SszEncode for SyncCommittee {
    fn encode_ssz(&self) -> Vec<u8> {
        let pubkeys = self.pubkeys.encode_ssz();
        let aggregate_pubkey = self.aggregate_pubkey.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&pubkeys),
            EncodedContainerField::Fixed(&aggregate_pubkey),
        ])
    }
}

impl SszDecode for SyncCommittee {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let pubkeys_len = 48 * SYNC_COMMITTEE_SIZE;
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(pubkeys_len), ContainerFieldKind::Fixed(48)],
        )?;
        Ok(Self {
            pubkeys: SszVector::<[u8; 48], SYNC_COMMITTEE_SIZE>::decode_ssz_checked(slices[0])?,
            aggregate_pubkey: <[u8; 48]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SyncCommittee {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.pubkeys.hash_tree_root(),
            self.aggregate_pubkey.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SyncCommittee {
    fn fixed_len() -> usize {
        (48 * SYNC_COMMITTEE_SIZE) + 48
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SyncCommitteeMessage {
    slot: u64,
    beacon_block_root: [u8; 32],
    validator_index: u64,
    signature: [u8; 96],
}

impl SszEncode for SyncCommitteeMessage {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let beacon_block_root = self.beacon_block_root.encode_ssz();
        let validator_index = self.validator_index.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&beacon_block_root),
            EncodedContainerField::Fixed(&validator_index),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SyncCommitteeMessage {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            beacon_block_root: <[u8; 32]>::decode_ssz(slices[1])?,
            validator_index: u64::decode_ssz(slices[2])?,
            signature: <[u8; 96]>::decode_ssz(slices[3])?,
        })
    }
}

impl HashTreeRoot for SyncCommitteeMessage {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.beacon_block_root.hash_tree_root(),
            self.validator_index.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SyncCommitteeContribution {
    slot: u64,
    beacon_block_root: [u8; 32],
    subcommittee_index: u64,
    aggregation_bits: BitVector<SYNC_SUBCOMMITTEE_SIZE>,
    signature: [u8; 96],
}

impl SszEncode for SyncCommitteeContribution {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let beacon_block_root = self.beacon_block_root.encode_ssz();
        let subcommittee_index = self.subcommittee_index.encode_ssz();
        let aggregation_bits = self.aggregation_bits.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&beacon_block_root),
            EncodedContainerField::Fixed(&subcommittee_index),
            EncodedContainerField::Fixed(&aggregation_bits),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SyncCommitteeContribution {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            beacon_block_root: <[u8; 32]>::decode_ssz(slices[1])?,
            subcommittee_index: u64::decode_ssz(slices[2])?,
            aggregation_bits: BitVector::<SYNC_SUBCOMMITTEE_SIZE>::decode_ssz_checked(slices[3])?,
            signature: <[u8; 96]>::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for SyncCommitteeContribution {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.beacon_block_root.hash_tree_root(),
            self.subcommittee_index.hash_tree_root(),
            self.aggregation_bits.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SyncCommitteeContribution {
    fn fixed_len() -> usize {
        160
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ContributionAndProof {
    aggregator_index: u64,
    contribution: SyncCommitteeContribution,
    selection_proof: [u8; 96],
}

impl SszEncode for ContributionAndProof {
    fn encode_ssz(&self) -> Vec<u8> {
        let aggregator_index = self.aggregator_index.encode_ssz();
        let contribution = self.contribution.encode_ssz();
        let selection_proof = self.selection_proof.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&aggregator_index),
            EncodedContainerField::Fixed(&contribution),
            EncodedContainerField::Fixed(&selection_proof),
        ])
    }
}

impl SszDecode for ContributionAndProof {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(96),
            ],
        )?;
        Ok(Self {
            aggregator_index: u64::decode_ssz(slices[0])?,
            contribution: SyncCommitteeContribution::decode_ssz(slices[1])?,
            selection_proof: <[u8; 96]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for ContributionAndProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.aggregator_index.hash_tree_root(),
            self.contribution.hash_tree_root(),
            self.selection_proof.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for ContributionAndProof {
    fn fixed_len() -> usize {
        264
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignedContributionAndProof {
    message: ContributionAndProof,
    signature: [u8; 96],
}

impl SszEncode for SignedContributionAndProof {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SignedContributionAndProof {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(264), ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: ContributionAndProof::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SignedContributionAndProof {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SignedContributionAndProof {
    fn fixed_len() -> usize {
        360
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SyncAggregatorSelectionData {
    slot: u64,
    subcommittee_index: u64,
}

impl SszEncode for SyncAggregatorSelectionData {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let subcommittee_index = self.subcommittee_index.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&subcommittee_index),
        ])
    }
}

impl SszDecode for SyncAggregatorSelectionData {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(8), ContainerFieldKind::Fixed(8)],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            subcommittee_index: u64::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SyncAggregatorSelectionData {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.subcommittee_index.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for SyncAggregatorSelectionData {
    fn fixed_len() -> usize {
        16
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LightClientHeader {
    beacon: BeaconBlockHeader,
}

impl SszEncode for LightClientHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let beacon = self.beacon.encode_ssz();
        encode_fields(&[EncodedContainerField::Fixed(&beacon)])
    }
}

impl SszDecode for LightClientHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(bytes, &[ContainerFieldKind::Fixed(112)])?;
        Ok(Self {
            beacon: BeaconBlockHeader::decode_ssz(slices[0])?,
        })
    }
}

impl HashTreeRoot for LightClientHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[self.beacon.hash_tree_root()])
    }
}

impl SszFixedLen for LightClientHeader {
    fn fixed_len() -> usize {
        112
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LightClientBootstrap {
    header: LightClientHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: SszVector<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>,
}

impl SszEncode for LightClientBootstrap {
    fn encode_ssz(&self) -> Vec<u8> {
        let header = self.header.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let current_sync_committee_branch = self.current_sync_committee_branch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&header),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&current_sync_committee_branch),
        ])
    }
}

impl SszDecode for LightClientBootstrap {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let branch_len = 32 * CURRENT_SYNC_COMMITTEE_BRANCH_LEN;
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(branch_len),
            ],
        )?;
        Ok(Self {
            header: LightClientHeader::decode_ssz(slices[0])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            current_sync_committee_branch:
                SszVector::<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(
                    slices[2],
                )?,
        })
    }
}

impl HashTreeRoot for LightClientBootstrap {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.header.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.current_sync_committee_branch.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LightClientUpdate {
    attested_header: LightClientHeader,
    next_sync_committee: SyncCommittee,
    next_sync_committee_branch: SszVector<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>,
    finalized_header: LightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for LightClientUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let next_sync_committee_branch = self.next_sync_committee_branch.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&attested_header),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee_branch),
            EncodedContainerField::Fixed(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for LightClientUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let next_branch_len = 32 * NEXT_SYNC_COMMITTEE_BRANCH_LEN;
        let finality_branch_len = 32 * FINALITY_BRANCH_LEN;
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(next_branch_len),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(finality_branch_len),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: LightClientHeader::decode_ssz(slices[0])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            next_sync_committee_branch:
                SszVector::<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(
                    slices[2],
                )?,
            finalized_header: LightClientHeader::decode_ssz(slices[3])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(
                slices[4],
            )?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[5])?,
            signature_slot: u64::decode_ssz(slices[6])?,
        })
    }
}

impl HashTreeRoot for LightClientUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.next_sync_committee_branch.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LightClientFinalityUpdate {
    attested_header: LightClientHeader,
    finalized_header: LightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for LightClientFinalityUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&attested_header),
            EncodedContainerField::Fixed(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for LightClientFinalityUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let finality_branch_len = 32 * FINALITY_BRANCH_LEN;
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(finality_branch_len),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: LightClientHeader::decode_ssz(slices[0])?,
            finalized_header: LightClientHeader::decode_ssz(slices[1])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(
                slices[2],
            )?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[3])?,
            signature_slot: u64::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for LightClientFinalityUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LightClientOptimisticUpdate {
    attested_header: LightClientHeader,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for LightClientOptimisticUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&attested_header),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for LightClientOptimisticUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: LightClientHeader::decode_ssz(slices[0])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[1])?,
            signature_slot: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for LightClientOptimisticUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Phase0BeaconBlockBody {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    deposits: SszList<Deposit, MAX_DEPOSITS>,
    voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

impl SszEncode for Phase0BeaconBlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let randao_reveal = self.randao_reveal.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let graffiti = self.graffiti.encode_ssz();
        let proposer_slashings = self.proposer_slashings.encode_ssz();
        let attester_slashings = self.attester_slashings.encode_ssz();
        let attestations = self.attestations.encode_ssz();
        let deposits = self.deposits.encode_ssz();
        let voluntary_exits = self.voluntary_exits.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&randao_reveal),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Fixed(&graffiti),
            EncodedContainerField::Variable(&proposer_slashings),
            EncodedContainerField::Variable(&attester_slashings),
            EncodedContainerField::Variable(&attestations),
            EncodedContainerField::Variable(&deposits),
            EncodedContainerField::Variable(&voluntary_exits),
        ])
    }
}

impl SszDecode for Phase0BeaconBlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(96),
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            randao_reveal: <[u8; 96]>::decode_ssz(slices[0])?,
            eth1_data: Eth1Data::decode_ssz(slices[1])?,
            graffiti: <[u8; 32]>::decode_ssz(slices[2])?,
            proposer_slashings: SszList::<ProposerSlashing, MAX_PROPOSER_SLASHINGS>::decode_ssz_checked(slices[3])?,
            attester_slashings: SszList::<AttesterSlashing, MAX_ATTESTER_SLASHINGS>::decode_ssz_checked(slices[4])?,
            attestations: SszList::<Attestation, MAX_ATTESTATIONS>::decode_ssz_checked(slices[5])?,
            deposits: SszList::<Deposit, MAX_DEPOSITS>::decode_ssz_checked(slices[6])?,
            voluntary_exits: SszList::<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>::decode_ssz_checked(slices[7])?,
        })
    }
}

impl HashTreeRoot for Phase0BeaconBlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.randao_reveal.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.graffiti.hash_tree_root(),
            self.proposer_slashings.hash_tree_root(),
            self.attester_slashings.hash_tree_root(),
            self.attestations.hash_tree_root(),
            self.deposits.hash_tree_root(),
            self.voluntary_exits.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Phase0BeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: Phase0BeaconBlockBody,
}

impl SszEncode for Phase0BeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body = self.body.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Variable(&body),
        ])
    }
}

impl SszDecode for Phase0BeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body: Phase0BeaconBlockBody::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for Phase0BeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Phase0SignedBeaconBlock {
    message: Phase0BeaconBlock,
    signature: [u8; 96],
}

impl SszEncode for Phase0SignedBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for Phase0SignedBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: Phase0BeaconBlock::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for Phase0SignedBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AltairBeaconBlockBody {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    deposits: SszList<Deposit, MAX_DEPOSITS>,
    voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    sync_aggregate: SyncAggregate,
}

impl SszEncode for AltairBeaconBlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let randao_reveal = self.randao_reveal.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let graffiti = self.graffiti.encode_ssz();
        let proposer_slashings = self.proposer_slashings.encode_ssz();
        let attester_slashings = self.attester_slashings.encode_ssz();
        let attestations = self.attestations.encode_ssz();
        let deposits = self.deposits.encode_ssz();
        let voluntary_exits = self.voluntary_exits.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&randao_reveal),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Fixed(&graffiti),
            EncodedContainerField::Variable(&proposer_slashings),
            EncodedContainerField::Variable(&attester_slashings),
            EncodedContainerField::Variable(&attestations),
            EncodedContainerField::Variable(&deposits),
            EncodedContainerField::Variable(&voluntary_exits),
            EncodedContainerField::Fixed(&sync_aggregate),
        ])
    }
}

impl SszDecode for AltairBeaconBlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(96),
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
            ],
        )?;
        Ok(Self {
            randao_reveal: <[u8; 96]>::decode_ssz(slices[0])?,
            eth1_data: Eth1Data::decode_ssz(slices[1])?,
            graffiti: <[u8; 32]>::decode_ssz(slices[2])?,
            proposer_slashings: SszList::<ProposerSlashing, MAX_PROPOSER_SLASHINGS>::decode_ssz_checked(slices[3])?,
            attester_slashings: SszList::<AttesterSlashing, MAX_ATTESTER_SLASHINGS>::decode_ssz_checked(slices[4])?,
            attestations: SszList::<Attestation, MAX_ATTESTATIONS>::decode_ssz_checked(slices[5])?,
            deposits: SszList::<Deposit, MAX_DEPOSITS>::decode_ssz_checked(slices[6])?,
            voluntary_exits: SszList::<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>::decode_ssz_checked(slices[7])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[8])?,
        })
    }
}

impl HashTreeRoot for AltairBeaconBlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.randao_reveal.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.graffiti.hash_tree_root(),
            self.proposer_slashings.hash_tree_root(),
            self.attester_slashings.hash_tree_root(),
            self.attestations.hash_tree_root(),
            self.deposits.hash_tree_root(),
            self.voluntary_exits.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AltairBeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: AltairBeaconBlockBody,
}

impl SszEncode for AltairBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body = self.body.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Variable(&body),
        ])
    }
}

impl SszDecode for AltairBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body: AltairBeaconBlockBody::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for AltairBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AltairSignedBeaconBlock {
    message: AltairBeaconBlock,
    signature: [u8; 96],
}

impl SszEncode for AltairSignedBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for AltairSignedBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: AltairBeaconBlock::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for AltairSignedBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Phase0BeaconState {
    genesis_time: u64,
    genesis_validators_root: [u8; 32],
    slot: u64,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    historical_roots: SszList<[u8; 32], HISTORICAL_ROOTS_LIMIT>,
    eth1_data: Eth1Data,
    eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    eth1_deposit_index: u64,
    validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    balances: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    randao_mixes: SszVector<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>,
    slashings: SszVector<u64, EPOCHS_PER_SLASHINGS_VECTOR>,
    previous_epoch_attestations: SszList<PendingAttestation, PENDING_ATTESTATIONS_LIMIT>,
    current_epoch_attestations: SszList<PendingAttestation, PENDING_ATTESTATIONS_LIMIT>,
    justification_bits: BitVector<JUSTIFICATION_BITS_LENGTH>,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
}

impl SszEncode for Phase0BeaconState {
    fn encode_ssz(&self) -> Vec<u8> {
        let genesis_time = self.genesis_time.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        let slot = self.slot.encode_ssz();
        let fork = self.fork.encode_ssz();
        let latest_block_header = self.latest_block_header.encode_ssz();
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        let historical_roots = self.historical_roots.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let eth1_data_votes = self.eth1_data_votes.encode_ssz();
        let eth1_deposit_index = self.eth1_deposit_index.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let randao_mixes = self.randao_mixes.encode_ssz();
        let slashings = self.slashings.encode_ssz();
        let previous_epoch_attestations = self.previous_epoch_attestations.encode_ssz();
        let current_epoch_attestations = self.current_epoch_attestations.encode_ssz();
        let justification_bits = self.justification_bits.encode_ssz();
        let previous_justified_checkpoint = self.previous_justified_checkpoint.encode_ssz();
        let current_justified_checkpoint = self.current_justified_checkpoint.encode_ssz();
        let finalized_checkpoint = self.finalized_checkpoint.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&genesis_time),
            EncodedContainerField::Fixed(&genesis_validators_root),
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&fork),
            EncodedContainerField::Fixed(&latest_block_header),
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
            EncodedContainerField::Variable(&historical_roots),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Variable(&eth1_data_votes),
            EncodedContainerField::Fixed(&eth1_deposit_index),
            EncodedContainerField::Variable(&validators),
            EncodedContainerField::Variable(&balances),
            EncodedContainerField::Fixed(&randao_mixes),
            EncodedContainerField::Fixed(&slashings),
            EncodedContainerField::Variable(&previous_epoch_attestations),
            EncodedContainerField::Variable(&current_epoch_attestations),
            EncodedContainerField::Fixed(&justification_bits),
            EncodedContainerField::Fixed(&previous_justified_checkpoint),
            EncodedContainerField::Fixed(&current_justified_checkpoint),
            EncodedContainerField::Fixed(&finalized_checkpoint),
        ])
    }
}

impl SszDecode for Phase0BeaconState {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EPOCHS_PER_HISTORICAL_VECTOR),
                ContainerFieldKind::Fixed(8 * EPOCHS_PER_SLASHINGS_VECTOR),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
            ],
        )?;
        Ok(Self {
            genesis_time: u64::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
            slot: u64::decode_ssz(slices[2])?,
            fork: Fork::decode_ssz(slices[3])?,
            latest_block_header: BeaconBlockHeader::decode_ssz(slices[4])?,
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[5])?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[6])?,
            historical_roots: SszList::<[u8; 32], HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[7])?,
            eth1_data: Eth1Data::decode_ssz(slices[8])?,
            eth1_data_votes: SszList::<Eth1Data, ETH1_DATA_VOTES_LIMIT>::decode_ssz_checked(slices[9])?,
            eth1_deposit_index: u64::decode_ssz(slices[10])?,
            validators: SszList::<Validator, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[11])?,
            balances: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[12])?,
            randao_mixes: SszVector::<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>::decode_ssz_checked(slices[13])?,
            slashings: SszVector::<u64, EPOCHS_PER_SLASHINGS_VECTOR>::decode_ssz_checked(slices[14])?,
            previous_epoch_attestations: SszList::<PendingAttestation, PENDING_ATTESTATIONS_LIMIT>::decode_ssz_checked(slices[15])?,
            current_epoch_attestations: SszList::<PendingAttestation, PENDING_ATTESTATIONS_LIMIT>::decode_ssz_checked(slices[16])?,
            justification_bits: BitVector::<JUSTIFICATION_BITS_LENGTH>::decode_ssz_checked(slices[17])?,
            previous_justified_checkpoint: Checkpoint::decode_ssz(slices[18])?,
            current_justified_checkpoint: Checkpoint::decode_ssz(slices[19])?,
            finalized_checkpoint: Checkpoint::decode_ssz(slices[20])?,
        })
    }
}

impl HashTreeRoot for Phase0BeaconState {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.genesis_time.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
            self.slot.hash_tree_root(),
            self.fork.hash_tree_root(),
            self.latest_block_header.hash_tree_root(),
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
            self.historical_roots.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.eth1_data_votes.hash_tree_root(),
            self.eth1_deposit_index.hash_tree_root(),
            self.validators.hash_tree_root(),
            self.balances.hash_tree_root(),
            self.randao_mixes.hash_tree_root(),
            self.slashings.hash_tree_root(),
            self.previous_epoch_attestations.hash_tree_root(),
            self.current_epoch_attestations.hash_tree_root(),
            self.justification_bits.hash_tree_root(),
            self.previous_justified_checkpoint.hash_tree_root(),
            self.current_justified_checkpoint.hash_tree_root(),
            self.finalized_checkpoint.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AltairBeaconState {
    genesis_time: u64,
    genesis_validators_root: [u8; 32],
    slot: u64,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    historical_roots: SszList<[u8; 32], HISTORICAL_ROOTS_LIMIT>,
    eth1_data: Eth1Data,
    eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    eth1_deposit_index: u64,
    validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    balances: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    randao_mixes: SszVector<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>,
    slashings: SszVector<u64, EPOCHS_PER_SLASHINGS_VECTOR>,
    previous_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    current_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    justification_bits: BitVector<JUSTIFICATION_BITS_LENGTH>,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
}

impl SszEncode for AltairBeaconState {
    fn encode_ssz(&self) -> Vec<u8> {
        let genesis_time = self.genesis_time.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        let slot = self.slot.encode_ssz();
        let fork = self.fork.encode_ssz();
        let latest_block_header = self.latest_block_header.encode_ssz();
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        let historical_roots = self.historical_roots.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let eth1_data_votes = self.eth1_data_votes.encode_ssz();
        let eth1_deposit_index = self.eth1_deposit_index.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let randao_mixes = self.randao_mixes.encode_ssz();
        let slashings = self.slashings.encode_ssz();
        let previous_epoch_participation = self.previous_epoch_participation.encode_ssz();
        let current_epoch_participation = self.current_epoch_participation.encode_ssz();
        let justification_bits = self.justification_bits.encode_ssz();
        let previous_justified_checkpoint = self.previous_justified_checkpoint.encode_ssz();
        let current_justified_checkpoint = self.current_justified_checkpoint.encode_ssz();
        let finalized_checkpoint = self.finalized_checkpoint.encode_ssz();
        let inactivity_scores = self.inactivity_scores.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&genesis_time),
            EncodedContainerField::Fixed(&genesis_validators_root),
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&fork),
            EncodedContainerField::Fixed(&latest_block_header),
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
            EncodedContainerField::Variable(&historical_roots),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Variable(&eth1_data_votes),
            EncodedContainerField::Fixed(&eth1_deposit_index),
            EncodedContainerField::Variable(&validators),
            EncodedContainerField::Variable(&balances),
            EncodedContainerField::Fixed(&randao_mixes),
            EncodedContainerField::Fixed(&slashings),
            EncodedContainerField::Variable(&previous_epoch_participation),
            EncodedContainerField::Variable(&current_epoch_participation),
            EncodedContainerField::Fixed(&justification_bits),
            EncodedContainerField::Fixed(&previous_justified_checkpoint),
            EncodedContainerField::Fixed(&current_justified_checkpoint),
            EncodedContainerField::Fixed(&finalized_checkpoint),
            EncodedContainerField::Variable(&inactivity_scores),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee),
        ])
    }
}

impl SszDecode for AltairBeaconState {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EPOCHS_PER_HISTORICAL_VECTOR),
                ContainerFieldKind::Fixed(8 * EPOCHS_PER_SLASHINGS_VECTOR),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(committee_len),
            ],
        )?;
        Ok(Self {
            genesis_time: u64::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
            slot: u64::decode_ssz(slices[2])?,
            fork: Fork::decode_ssz(slices[3])?,
            latest_block_header: BeaconBlockHeader::decode_ssz(slices[4])?,
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[5])?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[6])?,
            historical_roots: SszList::<[u8; 32], HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[7])?,
            eth1_data: Eth1Data::decode_ssz(slices[8])?,
            eth1_data_votes: SszList::<Eth1Data, ETH1_DATA_VOTES_LIMIT>::decode_ssz_checked(slices[9])?,
            eth1_deposit_index: u64::decode_ssz(slices[10])?,
            validators: SszList::<Validator, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[11])?,
            balances: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[12])?,
            randao_mixes: SszVector::<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>::decode_ssz_checked(slices[13])?,
            slashings: SszVector::<u64, EPOCHS_PER_SLASHINGS_VECTOR>::decode_ssz_checked(slices[14])?,
            previous_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[15])?,
            current_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[16])?,
            justification_bits: BitVector::<JUSTIFICATION_BITS_LENGTH>::decode_ssz_checked(slices[17])?,
            previous_justified_checkpoint: Checkpoint::decode_ssz(slices[18])?,
            current_justified_checkpoint: Checkpoint::decode_ssz(slices[19])?,
            finalized_checkpoint: Checkpoint::decode_ssz(slices[20])?,
            inactivity_scores: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[21])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[22])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[23])?,
        })
    }
}

impl HashTreeRoot for AltairBeaconState {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.genesis_time.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
            self.slot.hash_tree_root(),
            self.fork.hash_tree_root(),
            self.latest_block_header.hash_tree_root(),
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
            self.historical_roots.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.eth1_data_votes.hash_tree_root(),
            self.eth1_deposit_index.hash_tree_root(),
            self.validators.hash_tree_root(),
            self.balances.hash_tree_root(),
            self.randao_mixes.hash_tree_root(),
            self.slashings.hash_tree_root(),
            self.previous_epoch_participation.hash_tree_root(),
            self.current_epoch_participation.hash_tree_root(),
            self.justification_bits.hash_tree_root(),
            self.previous_justified_checkpoint.hash_tree_root(),
            self.current_justified_checkpoint.hash_tree_root(),
            self.finalized_checkpoint.hash_tree_root(),
            self.inactivity_scores.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExecutionPayload {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: SszList<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
}

impl SszEncode for ExecutionPayload {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions = self.transactions.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Variable(&transactions),
        ])
    }
}

impl SszDecode for ExecutionPayload {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions: SszList::<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>::decode_ssz_checked(slices[13])?,
        })
    }
}

impl HashTreeRoot for ExecutionPayload {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ExecutionPayloadHeader {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions_root: [u8; 32],
}

impl SszEncode for ExecutionPayloadHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions_root = self.transactions_root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Fixed(&transactions_root),
        ])
    }
}

impl SszDecode for ExecutionPayloadHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions_root: <[u8; 32]>::decode_ssz(slices[13])?,
        })
    }
}

impl HashTreeRoot for ExecutionPayloadHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions_root.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PowBlock {
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    total_difficulty: [u8; 32],
}

impl SszEncode for PowBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let block_hash = self.block_hash.encode_ssz();
        let parent_hash = self.parent_hash.encode_ssz();
        let total_difficulty = self.total_difficulty.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&total_difficulty),
        ])
    }
}

impl SszDecode for PowBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
            ],
        )?;
        Ok(Self {
            block_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            parent_hash: <[u8; 32]>::decode_ssz(slices[1])?,
            total_difficulty: <[u8; 32]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for PowBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.block_hash.hash_tree_root(),
            self.parent_hash.hash_tree_root(),
            self.total_difficulty.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BellatrixBeaconBlockBody {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    deposits: SszList<Deposit, MAX_DEPOSITS>,
    voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    sync_aggregate: SyncAggregate,
    execution_payload: ExecutionPayload,
}

impl SszEncode for BellatrixBeaconBlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let randao_reveal = self.randao_reveal.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let graffiti = self.graffiti.encode_ssz();
        let proposer_slashings = self.proposer_slashings.encode_ssz();
        let attester_slashings = self.attester_slashings.encode_ssz();
        let attestations = self.attestations.encode_ssz();
        let deposits = self.deposits.encode_ssz();
        let voluntary_exits = self.voluntary_exits.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let execution_payload = self.execution_payload.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&randao_reveal),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Fixed(&graffiti),
            EncodedContainerField::Variable(&proposer_slashings),
            EncodedContainerField::Variable(&attester_slashings),
            EncodedContainerField::Variable(&attestations),
            EncodedContainerField::Variable(&deposits),
            EncodedContainerField::Variable(&voluntary_exits),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Variable(&execution_payload),
        ])
    }
}

impl SszDecode for BellatrixBeaconBlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(96),
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            randao_reveal: <[u8; 96]>::decode_ssz(slices[0])?,
            eth1_data: Eth1Data::decode_ssz(slices[1])?,
            graffiti: <[u8; 32]>::decode_ssz(slices[2])?,
            proposer_slashings: SszList::<ProposerSlashing, MAX_PROPOSER_SLASHINGS>::decode_ssz_checked(slices[3])?,
            attester_slashings: SszList::<AttesterSlashing, MAX_ATTESTER_SLASHINGS>::decode_ssz_checked(slices[4])?,
            attestations: SszList::<Attestation, MAX_ATTESTATIONS>::decode_ssz_checked(slices[5])?,
            deposits: SszList::<Deposit, MAX_DEPOSITS>::decode_ssz_checked(slices[6])?,
            voluntary_exits: SszList::<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>::decode_ssz_checked(slices[7])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[8])?,
            execution_payload: ExecutionPayload::decode_ssz(slices[9])?,
        })
    }
}

impl HashTreeRoot for BellatrixBeaconBlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.randao_reveal.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.graffiti.hash_tree_root(),
            self.proposer_slashings.hash_tree_root(),
            self.attester_slashings.hash_tree_root(),
            self.attestations.hash_tree_root(),
            self.deposits.hash_tree_root(),
            self.voluntary_exits.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.execution_payload.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BellatrixBeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: BellatrixBeaconBlockBody,
}

impl SszEncode for BellatrixBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body = self.body.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Variable(&body),
        ])
    }
}

impl SszDecode for BellatrixBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body: BellatrixBeaconBlockBody::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for BellatrixBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BellatrixSignedBeaconBlock {
    message: BellatrixBeaconBlock,
    signature: [u8; 96],
}

impl SszEncode for BellatrixSignedBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for BellatrixSignedBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: BellatrixBeaconBlock::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for BellatrixSignedBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BellatrixBeaconState {
    genesis_time: u64,
    genesis_validators_root: [u8; 32],
    slot: u64,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    historical_roots: SszList<[u8; 32], HISTORICAL_ROOTS_LIMIT>,
    eth1_data: Eth1Data,
    eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    eth1_deposit_index: u64,
    validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    balances: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    randao_mixes: SszVector<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>,
    slashings: SszVector<u64, EPOCHS_PER_SLASHINGS_VECTOR>,
    previous_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    current_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    justification_bits: BitVector<JUSTIFICATION_BITS_LENGTH>,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    latest_execution_payload_header: ExecutionPayloadHeader,
}

impl SszEncode for BellatrixBeaconState {
    fn encode_ssz(&self) -> Vec<u8> {
        let genesis_time = self.genesis_time.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        let slot = self.slot.encode_ssz();
        let fork = self.fork.encode_ssz();
        let latest_block_header = self.latest_block_header.encode_ssz();
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        let historical_roots = self.historical_roots.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let eth1_data_votes = self.eth1_data_votes.encode_ssz();
        let eth1_deposit_index = self.eth1_deposit_index.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let randao_mixes = self.randao_mixes.encode_ssz();
        let slashings = self.slashings.encode_ssz();
        let previous_epoch_participation = self.previous_epoch_participation.encode_ssz();
        let current_epoch_participation = self.current_epoch_participation.encode_ssz();
        let justification_bits = self.justification_bits.encode_ssz();
        let previous_justified_checkpoint = self.previous_justified_checkpoint.encode_ssz();
        let current_justified_checkpoint = self.current_justified_checkpoint.encode_ssz();
        let finalized_checkpoint = self.finalized_checkpoint.encode_ssz();
        let inactivity_scores = self.inactivity_scores.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let latest_execution_payload_header = self.latest_execution_payload_header.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&genesis_time),
            EncodedContainerField::Fixed(&genesis_validators_root),
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&fork),
            EncodedContainerField::Fixed(&latest_block_header),
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
            EncodedContainerField::Variable(&historical_roots),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Variable(&eth1_data_votes),
            EncodedContainerField::Fixed(&eth1_deposit_index),
            EncodedContainerField::Variable(&validators),
            EncodedContainerField::Variable(&balances),
            EncodedContainerField::Fixed(&randao_mixes),
            EncodedContainerField::Fixed(&slashings),
            EncodedContainerField::Variable(&previous_epoch_participation),
            EncodedContainerField::Variable(&current_epoch_participation),
            EncodedContainerField::Fixed(&justification_bits),
            EncodedContainerField::Fixed(&previous_justified_checkpoint),
            EncodedContainerField::Fixed(&current_justified_checkpoint),
            EncodedContainerField::Fixed(&finalized_checkpoint),
            EncodedContainerField::Variable(&inactivity_scores),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Variable(&latest_execution_payload_header),
        ])
    }
}

impl SszDecode for BellatrixBeaconState {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EPOCHS_PER_HISTORICAL_VECTOR),
                ContainerFieldKind::Fixed(8 * EPOCHS_PER_SLASHINGS_VECTOR),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            genesis_time: u64::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
            slot: u64::decode_ssz(slices[2])?,
            fork: Fork::decode_ssz(slices[3])?,
            latest_block_header: BeaconBlockHeader::decode_ssz(slices[4])?,
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[5])?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[6])?,
            historical_roots: SszList::<[u8; 32], HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[7])?,
            eth1_data: Eth1Data::decode_ssz(slices[8])?,
            eth1_data_votes: SszList::<Eth1Data, ETH1_DATA_VOTES_LIMIT>::decode_ssz_checked(slices[9])?,
            eth1_deposit_index: u64::decode_ssz(slices[10])?,
            validators: SszList::<Validator, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[11])?,
            balances: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[12])?,
            randao_mixes: SszVector::<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>::decode_ssz_checked(slices[13])?,
            slashings: SszVector::<u64, EPOCHS_PER_SLASHINGS_VECTOR>::decode_ssz_checked(slices[14])?,
            previous_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[15])?,
            current_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[16])?,
            justification_bits: BitVector::<JUSTIFICATION_BITS_LENGTH>::decode_ssz_checked(slices[17])?,
            previous_justified_checkpoint: Checkpoint::decode_ssz(slices[18])?,
            current_justified_checkpoint: Checkpoint::decode_ssz(slices[19])?,
            finalized_checkpoint: Checkpoint::decode_ssz(slices[20])?,
            inactivity_scores: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[21])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[22])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[23])?,
            latest_execution_payload_header: ExecutionPayloadHeader::decode_ssz(slices[24])?,
        })
    }
}

impl HashTreeRoot for BellatrixBeaconState {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.genesis_time.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
            self.slot.hash_tree_root(),
            self.fork.hash_tree_root(),
            self.latest_block_header.hash_tree_root(),
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
            self.historical_roots.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.eth1_data_votes.hash_tree_root(),
            self.eth1_deposit_index.hash_tree_root(),
            self.validators.hash_tree_root(),
            self.balances.hash_tree_root(),
            self.randao_mixes.hash_tree_root(),
            self.slashings.hash_tree_root(),
            self.previous_epoch_participation.hash_tree_root(),
            self.current_epoch_participation.hash_tree_root(),
            self.justification_bits.hash_tree_root(),
            self.previous_justified_checkpoint.hash_tree_root(),
            self.current_justified_checkpoint.hash_tree_root(),
            self.finalized_checkpoint.hash_tree_root(),
            self.inactivity_scores.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.latest_execution_payload_header.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Withdrawal {
    index: u64,
    validator_index: u64,
    address: [u8; 20],
    amount: u64,
}

impl SszEncode for Withdrawal {
    fn encode_ssz(&self) -> Vec<u8> {
        let index = self.index.encode_ssz();
        let validator_index = self.validator_index.encode_ssz();
        let address = self.address.encode_ssz();
        let amount = self.amount.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&index),
            EncodedContainerField::Fixed(&validator_index),
            EncodedContainerField::Fixed(&address),
            EncodedContainerField::Fixed(&amount),
        ])
    }
}

impl SszDecode for Withdrawal {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            index: u64::decode_ssz(slices[0])?,
            validator_index: u64::decode_ssz(slices[1])?,
            address: <[u8; 20]>::decode_ssz(slices[2])?,
            amount: u64::decode_ssz(slices[3])?,
        })
    }
}

impl HashTreeRoot for Withdrawal {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.index.hash_tree_root(),
            self.validator_index.hash_tree_root(),
            self.address.hash_tree_root(),
            self.amount.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BLSToExecutionChange {
    validator_index: u64,
    from_bls_pubkey: [u8; 48],
    to_execution_address: [u8; 20],
}

impl SszEncode for BLSToExecutionChange {
    fn encode_ssz(&self) -> Vec<u8> {
        let validator_index = self.validator_index.encode_ssz();
        let from_bls_pubkey = self.from_bls_pubkey.encode_ssz();
        let to_execution_address = self.to_execution_address.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&validator_index),
            EncodedContainerField::Fixed(&from_bls_pubkey),
            EncodedContainerField::Fixed(&to_execution_address),
        ])
    }
}

impl SszDecode for BLSToExecutionChange {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(20),
            ],
        )?;
        Ok(Self {
            validator_index: u64::decode_ssz(slices[0])?,
            from_bls_pubkey: <[u8; 48]>::decode_ssz(slices[1])?,
            to_execution_address: <[u8; 20]>::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for BLSToExecutionChange {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.validator_index.hash_tree_root(),
            self.from_bls_pubkey.hash_tree_root(),
            self.to_execution_address.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SignedBLSToExecutionChange {
    message: BLSToExecutionChange,
    signature: [u8; 96],
}

impl SszEncode for SignedBLSToExecutionChange {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for SignedBLSToExecutionChange {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(76), ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: BLSToExecutionChange::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for SignedBLSToExecutionChange {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HistoricalSummary {
    block_summary_root: [u8; 32],
    state_summary_root: [u8; 32],
}

impl SszEncode for HistoricalSummary {
    fn encode_ssz(&self) -> Vec<u8> {
        let block_summary_root = self.block_summary_root.encode_ssz();
        let state_summary_root = self.state_summary_root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&block_summary_root),
            EncodedContainerField::Fixed(&state_summary_root),
        ])
    }
}

impl SszDecode for HistoricalSummary {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(32), ContainerFieldKind::Fixed(32)],
        )?;
        Ok(Self {
            block_summary_root: <[u8; 32]>::decode_ssz(slices[0])?,
            state_summary_root: <[u8; 32]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for HistoricalSummary {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.block_summary_root.hash_tree_root(),
            self.state_summary_root.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaExecutionPayload {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: SszList<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    withdrawals: SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
}

impl SszEncode for CapellaExecutionPayload {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions = self.transactions.encode_ssz();
        let withdrawals = self.withdrawals.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Variable(&transactions),
            EncodedContainerField::Variable(&withdrawals),
        ])
    }
}

impl SszDecode for CapellaExecutionPayload {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions: SszList::<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>::decode_ssz_checked(slices[13])?,
            withdrawals: SszList::<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>::decode_ssz_checked(slices[14])?,
        })
    }
}

impl HashTreeRoot for CapellaExecutionPayload {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions.hash_tree_root(),
            self.withdrawals.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaExecutionPayloadHeader {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions_root: [u8; 32],
    withdrawals_root: [u8; 32],
}

impl SszEncode for CapellaExecutionPayloadHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions_root = self.transactions_root.encode_ssz();
        let withdrawals_root = self.withdrawals_root.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Fixed(&transactions_root),
            EncodedContainerField::Fixed(&withdrawals_root),
        ])
    }
}

impl SszDecode for CapellaExecutionPayloadHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions_root: <[u8; 32]>::decode_ssz(slices[13])?,
            withdrawals_root: <[u8; 32]>::decode_ssz(slices[14])?,
        })
    }
}

impl HashTreeRoot for CapellaExecutionPayloadHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions_root.hash_tree_root(),
            self.withdrawals_root.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaBeaconBlockBody {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    deposits: SszList<Deposit, MAX_DEPOSITS>,
    voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    sync_aggregate: SyncAggregate,
    execution_payload: CapellaExecutionPayload,
    bls_to_execution_changes: SszList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
}

impl SszEncode for CapellaBeaconBlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let randao_reveal = self.randao_reveal.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let graffiti = self.graffiti.encode_ssz();
        let proposer_slashings = self.proposer_slashings.encode_ssz();
        let attester_slashings = self.attester_slashings.encode_ssz();
        let attestations = self.attestations.encode_ssz();
        let deposits = self.deposits.encode_ssz();
        let voluntary_exits = self.voluntary_exits.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let execution_payload = self.execution_payload.encode_ssz();
        let bls_to_execution_changes = self.bls_to_execution_changes.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&randao_reveal),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Fixed(&graffiti),
            EncodedContainerField::Variable(&proposer_slashings),
            EncodedContainerField::Variable(&attester_slashings),
            EncodedContainerField::Variable(&attestations),
            EncodedContainerField::Variable(&deposits),
            EncodedContainerField::Variable(&voluntary_exits),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Variable(&execution_payload),
            EncodedContainerField::Variable(&bls_to_execution_changes),
        ])
    }
}

impl SszDecode for CapellaBeaconBlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(96),
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            randao_reveal: <[u8; 96]>::decode_ssz(slices[0])?,
            eth1_data: Eth1Data::decode_ssz(slices[1])?,
            graffiti: <[u8; 32]>::decode_ssz(slices[2])?,
            proposer_slashings: SszList::<ProposerSlashing, MAX_PROPOSER_SLASHINGS>::decode_ssz_checked(slices[3])?,
            attester_slashings: SszList::<AttesterSlashing, MAX_ATTESTER_SLASHINGS>::decode_ssz_checked(slices[4])?,
            attestations: SszList::<Attestation, MAX_ATTESTATIONS>::decode_ssz_checked(slices[5])?,
            deposits: SszList::<Deposit, MAX_DEPOSITS>::decode_ssz_checked(slices[6])?,
            voluntary_exits: SszList::<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>::decode_ssz_checked(slices[7])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[8])?,
            execution_payload: CapellaExecutionPayload::decode_ssz(slices[9])?,
            bls_to_execution_changes: SszList::<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>::decode_ssz_checked(slices[10])?,
        })
    }
}

impl HashTreeRoot for CapellaBeaconBlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.randao_reveal.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.graffiti.hash_tree_root(),
            self.proposer_slashings.hash_tree_root(),
            self.attester_slashings.hash_tree_root(),
            self.attestations.hash_tree_root(),
            self.deposits.hash_tree_root(),
            self.voluntary_exits.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.execution_payload.hash_tree_root(),
            self.bls_to_execution_changes.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaBeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: CapellaBeaconBlockBody,
}

impl SszEncode for CapellaBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body = self.body.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Variable(&body),
        ])
    }
}

impl SszDecode for CapellaBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body: CapellaBeaconBlockBody::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for CapellaBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaSignedBeaconBlock {
    message: CapellaBeaconBlock,
    signature: [u8; 96],
}

impl SszEncode for CapellaSignedBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for CapellaSignedBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: CapellaBeaconBlock::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for CapellaSignedBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaLightClientHeader {
    beacon: BeaconBlockHeader,
    execution: CapellaExecutionPayloadHeader,
    execution_branch: SszVector<[u8; 32], EXECUTION_BRANCH_LEN>,
}

impl SszEncode for CapellaLightClientHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let beacon = self.beacon.encode_ssz();
        let execution = self.execution.encode_ssz();
        let execution_branch = self.execution_branch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&beacon),
            EncodedContainerField::Variable(&execution),
            EncodedContainerField::Fixed(&execution_branch),
        ])
    }
}

impl SszDecode for CapellaLightClientHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EXECUTION_BRANCH_LEN),
            ],
        )?;
        Ok(Self {
            beacon: BeaconBlockHeader::decode_ssz(slices[0])?,
            execution: CapellaExecutionPayloadHeader::decode_ssz(slices[1])?,
            execution_branch: SszVector::<[u8; 32], EXECUTION_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
        })
    }
}

impl HashTreeRoot for CapellaLightClientHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.beacon.hash_tree_root(),
            self.execution.hash_tree_root(),
            self.execution_branch.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaLightClientBootstrap {
    header: CapellaLightClientHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: SszVector<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>,
}

impl SszEncode for CapellaLightClientBootstrap {
    fn encode_ssz(&self) -> Vec<u8> {
        let header = self.header.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let current_sync_committee_branch = self.current_sync_committee_branch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&header),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&current_sync_committee_branch),
        ])
    }
}

impl SszDecode for CapellaLightClientBootstrap {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(32 * CURRENT_SYNC_COMMITTEE_BRANCH_LEN),
            ],
        )?;
        Ok(Self {
            header: CapellaLightClientHeader::decode_ssz(slices[0])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            current_sync_committee_branch: SszVector::<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
        })
    }
}

impl HashTreeRoot for CapellaLightClientBootstrap {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.header.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.current_sync_committee_branch.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaLightClientUpdate {
    attested_header: CapellaLightClientHeader,
    next_sync_committee: SyncCommittee,
    next_sync_committee_branch: SszVector<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>,
    finalized_header: CapellaLightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for CapellaLightClientUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let next_sync_committee_branch = self.next_sync_committee_branch.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee_branch),
            EncodedContainerField::Variable(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for CapellaLightClientUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(32 * NEXT_SYNC_COMMITTEE_BRANCH_LEN),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * FINALITY_BRANCH_LEN),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: CapellaLightClientHeader::decode_ssz(slices[0])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            next_sync_committee_branch: SszVector::<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
            finalized_header: CapellaLightClientHeader::decode_ssz(slices[3])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(slices[4])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[5])?,
            signature_slot: u64::decode_ssz(slices[6])?,
        })
    }
}

impl HashTreeRoot for CapellaLightClientUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.next_sync_committee_branch.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaLightClientFinalityUpdate {
    attested_header: CapellaLightClientHeader,
    finalized_header: CapellaLightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for CapellaLightClientFinalityUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Variable(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for CapellaLightClientFinalityUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * FINALITY_BRANCH_LEN),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: CapellaLightClientHeader::decode_ssz(slices[0])?,
            finalized_header: CapellaLightClientHeader::decode_ssz(slices[1])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[3])?,
            signature_slot: u64::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for CapellaLightClientFinalityUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaLightClientOptimisticUpdate {
    attested_header: CapellaLightClientHeader,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for CapellaLightClientOptimisticUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for CapellaLightClientOptimisticUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: CapellaLightClientHeader::decode_ssz(slices[0])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[1])?,
            signature_slot: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for CapellaLightClientOptimisticUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CapellaBeaconState {
    genesis_time: u64,
    genesis_validators_root: [u8; 32],
    slot: u64,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    historical_roots: SszList<[u8; 32], HISTORICAL_ROOTS_LIMIT>,
    eth1_data: Eth1Data,
    eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    eth1_deposit_index: u64,
    validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    balances: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    randao_mixes: SszVector<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>,
    slashings: SszVector<u64, EPOCHS_PER_SLASHINGS_VECTOR>,
    previous_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    current_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    justification_bits: BitVector<JUSTIFICATION_BITS_LENGTH>,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    latest_execution_payload_header: CapellaExecutionPayloadHeader,
    next_withdrawal_index: u64,
    next_withdrawal_validator_index: u64,
    historical_summaries: SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
}

impl SszEncode for CapellaBeaconState {
    fn encode_ssz(&self) -> Vec<u8> {
        let genesis_time = self.genesis_time.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        let slot = self.slot.encode_ssz();
        let fork = self.fork.encode_ssz();
        let latest_block_header = self.latest_block_header.encode_ssz();
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        let historical_roots = self.historical_roots.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let eth1_data_votes = self.eth1_data_votes.encode_ssz();
        let eth1_deposit_index = self.eth1_deposit_index.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let randao_mixes = self.randao_mixes.encode_ssz();
        let slashings = self.slashings.encode_ssz();
        let previous_epoch_participation = self.previous_epoch_participation.encode_ssz();
        let current_epoch_participation = self.current_epoch_participation.encode_ssz();
        let justification_bits = self.justification_bits.encode_ssz();
        let previous_justified_checkpoint = self.previous_justified_checkpoint.encode_ssz();
        let current_justified_checkpoint = self.current_justified_checkpoint.encode_ssz();
        let finalized_checkpoint = self.finalized_checkpoint.encode_ssz();
        let inactivity_scores = self.inactivity_scores.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let latest_execution_payload_header = self.latest_execution_payload_header.encode_ssz();
        let next_withdrawal_index = self.next_withdrawal_index.encode_ssz();
        let next_withdrawal_validator_index = self.next_withdrawal_validator_index.encode_ssz();
        let historical_summaries = self.historical_summaries.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&genesis_time),
            EncodedContainerField::Fixed(&genesis_validators_root),
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&fork),
            EncodedContainerField::Fixed(&latest_block_header),
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
            EncodedContainerField::Variable(&historical_roots),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Variable(&eth1_data_votes),
            EncodedContainerField::Fixed(&eth1_deposit_index),
            EncodedContainerField::Variable(&validators),
            EncodedContainerField::Variable(&balances),
            EncodedContainerField::Fixed(&randao_mixes),
            EncodedContainerField::Fixed(&slashings),
            EncodedContainerField::Variable(&previous_epoch_participation),
            EncodedContainerField::Variable(&current_epoch_participation),
            EncodedContainerField::Fixed(&justification_bits),
            EncodedContainerField::Fixed(&previous_justified_checkpoint),
            EncodedContainerField::Fixed(&current_justified_checkpoint),
            EncodedContainerField::Fixed(&finalized_checkpoint),
            EncodedContainerField::Variable(&inactivity_scores),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Variable(&latest_execution_payload_header),
            EncodedContainerField::Fixed(&next_withdrawal_index),
            EncodedContainerField::Fixed(&next_withdrawal_validator_index),
            EncodedContainerField::Variable(&historical_summaries),
        ])
    }
}

impl SszDecode for CapellaBeaconState {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EPOCHS_PER_HISTORICAL_VECTOR),
                ContainerFieldKind::Fixed(8 * EPOCHS_PER_SLASHINGS_VECTOR),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            genesis_time: u64::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
            slot: u64::decode_ssz(slices[2])?,
            fork: Fork::decode_ssz(slices[3])?,
            latest_block_header: BeaconBlockHeader::decode_ssz(slices[4])?,
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[5])?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[6])?,
            historical_roots: SszList::<[u8; 32], HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[7])?,
            eth1_data: Eth1Data::decode_ssz(slices[8])?,
            eth1_data_votes: SszList::<Eth1Data, ETH1_DATA_VOTES_LIMIT>::decode_ssz_checked(slices[9])?,
            eth1_deposit_index: u64::decode_ssz(slices[10])?,
            validators: SszList::<Validator, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[11])?,
            balances: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[12])?,
            randao_mixes: SszVector::<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>::decode_ssz_checked(slices[13])?,
            slashings: SszVector::<u64, EPOCHS_PER_SLASHINGS_VECTOR>::decode_ssz_checked(slices[14])?,
            previous_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[15])?,
            current_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[16])?,
            justification_bits: BitVector::<JUSTIFICATION_BITS_LENGTH>::decode_ssz_checked(slices[17])?,
            previous_justified_checkpoint: Checkpoint::decode_ssz(slices[18])?,
            current_justified_checkpoint: Checkpoint::decode_ssz(slices[19])?,
            finalized_checkpoint: Checkpoint::decode_ssz(slices[20])?,
            inactivity_scores: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[21])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[22])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[23])?,
            latest_execution_payload_header: CapellaExecutionPayloadHeader::decode_ssz(slices[24])?,
            next_withdrawal_index: u64::decode_ssz(slices[25])?,
            next_withdrawal_validator_index: u64::decode_ssz(slices[26])?,
            historical_summaries: SszList::<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[27])?,
        })
    }
}

impl HashTreeRoot for CapellaBeaconState {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.genesis_time.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
            self.slot.hash_tree_root(),
            self.fork.hash_tree_root(),
            self.latest_block_header.hash_tree_root(),
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
            self.historical_roots.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.eth1_data_votes.hash_tree_root(),
            self.eth1_deposit_index.hash_tree_root(),
            self.validators.hash_tree_root(),
            self.balances.hash_tree_root(),
            self.randao_mixes.hash_tree_root(),
            self.slashings.hash_tree_root(),
            self.previous_epoch_participation.hash_tree_root(),
            self.current_epoch_participation.hash_tree_root(),
            self.justification_bits.hash_tree_root(),
            self.previous_justified_checkpoint.hash_tree_root(),
            self.current_justified_checkpoint.hash_tree_root(),
            self.finalized_checkpoint.hash_tree_root(),
            self.inactivity_scores.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.latest_execution_payload_header.hash_tree_root(),
            self.next_withdrawal_index.hash_tree_root(),
            self.next_withdrawal_validator_index.hash_tree_root(),
            self.historical_summaries.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BlobIdentifier {
    block_root: [u8; 32],
    index: u64,
}

impl SszEncode for BlobIdentifier {
    fn encode_ssz(&self) -> Vec<u8> {
        let block_root = self.block_root.encode_ssz();
        let index = self.index.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&block_root),
            EncodedContainerField::Fixed(&index),
        ])
    }
}

impl SszDecode for BlobIdentifier {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Fixed(32), ContainerFieldKind::Fixed(8)],
        )?;
        Ok(Self {
            block_root: <[u8; 32]>::decode_ssz(slices[0])?,
            index: u64::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for BlobIdentifier {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.block_root.hash_tree_root(),
            self.index.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BlobSidecar {
    index: u64,
    blob: SszVector<u8, BYTES_PER_BLOB>,
    kzg_commitment: [u8; 48],
    kzg_proof: [u8; 48],
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitment_inclusion_proof: SszVector<[u8; 32], KZG_COMMITMENT_INCLUSION_PROOF_DEPTH>,
}

impl SszEncode for BlobSidecar {
    fn encode_ssz(&self) -> Vec<u8> {
        let index = self.index.encode_ssz();
        let blob = self.blob.encode_ssz();
        let kzg_commitment = self.kzg_commitment.encode_ssz();
        let kzg_proof = self.kzg_proof.encode_ssz();
        let signed_block_header = self.signed_block_header.encode_ssz();
        let kzg_commitment_inclusion_proof = self.kzg_commitment_inclusion_proof.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&index),
            EncodedContainerField::Fixed(&blob),
            EncodedContainerField::Fixed(&kzg_commitment),
            EncodedContainerField::Fixed(&kzg_proof),
            EncodedContainerField::Fixed(&signed_block_header),
            EncodedContainerField::Fixed(&kzg_commitment_inclusion_proof),
        ])
    }
}

impl SszDecode for BlobSidecar {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(BYTES_PER_BLOB),
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(48),
                ContainerFieldKind::Fixed(208),
                ContainerFieldKind::Fixed(32 * KZG_COMMITMENT_INCLUSION_PROOF_DEPTH),
            ],
        )?;
        Ok(Self {
            index: u64::decode_ssz(slices[0])?,
            blob: SszVector::<u8, BYTES_PER_BLOB>::decode_ssz_checked(slices[1])?,
            kzg_commitment: <[u8; 48]>::decode_ssz(slices[2])?,
            kzg_proof: <[u8; 48]>::decode_ssz(slices[3])?,
            signed_block_header: SignedBeaconBlockHeader::decode_ssz(slices[4])?,
            kzg_commitment_inclusion_proof: SszVector::<
                [u8; 32],
                KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
            >::decode_ssz_checked(slices[5])?,
        })
    }
}

impl HashTreeRoot for BlobSidecar {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.index.hash_tree_root(),
            self.blob.hash_tree_root(),
            self.kzg_commitment.hash_tree_root(),
            self.kzg_proof.hash_tree_root(),
            self.signed_block_header.hash_tree_root(),
            self.kzg_commitment_inclusion_proof.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebExecutionPayload {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions: SszList<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    withdrawals: SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

impl SszEncode for DenebExecutionPayload {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions = self.transactions.encode_ssz();
        let withdrawals = self.withdrawals.encode_ssz();
        let blob_gas_used = self.blob_gas_used.encode_ssz();
        let excess_blob_gas = self.excess_blob_gas.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Variable(&transactions),
            EncodedContainerField::Variable(&withdrawals),
            EncodedContainerField::Fixed(&blob_gas_used),
            EncodedContainerField::Fixed(&excess_blob_gas),
        ])
    }
}

impl SszDecode for DenebExecutionPayload {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions: SszList::<SszList<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>::decode_ssz_checked(slices[13])?,
            withdrawals: SszList::<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>::decode_ssz_checked(slices[14])?,
            blob_gas_used: u64::decode_ssz(slices[15])?,
            excess_blob_gas: u64::decode_ssz(slices[16])?,
        })
    }
}

impl HashTreeRoot for DenebExecutionPayload {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions.hash_tree_root(),
            self.withdrawals.hash_tree_root(),
            self.blob_gas_used.hash_tree_root(),
            self.excess_blob_gas.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebExecutionPayloadHeader {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    base_fee_per_gas: [u8; 32],
    block_hash: [u8; 32],
    transactions_root: [u8; 32],
    withdrawals_root: [u8; 32],
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

impl SszEncode for DenebExecutionPayloadHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let parent_hash = self.parent_hash.encode_ssz();
        let fee_recipient = self.fee_recipient.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let receipts_root = self.receipts_root.encode_ssz();
        let logs_bloom = self.logs_bloom.encode_ssz();
        let prev_randao = self.prev_randao.encode_ssz();
        let block_number = self.block_number.encode_ssz();
        let gas_limit = self.gas_limit.encode_ssz();
        let gas_used = self.gas_used.encode_ssz();
        let timestamp = self.timestamp.encode_ssz();
        let extra_data = self.extra_data.encode_ssz();
        let base_fee_per_gas = self.base_fee_per_gas.encode_ssz();
        let block_hash = self.block_hash.encode_ssz();
        let transactions_root = self.transactions_root.encode_ssz();
        let withdrawals_root = self.withdrawals_root.encode_ssz();
        let blob_gas_used = self.blob_gas_used.encode_ssz();
        let excess_blob_gas = self.excess_blob_gas.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&parent_hash),
            EncodedContainerField::Fixed(&fee_recipient),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Fixed(&receipts_root),
            EncodedContainerField::Fixed(&logs_bloom),
            EncodedContainerField::Fixed(&prev_randao),
            EncodedContainerField::Fixed(&block_number),
            EncodedContainerField::Fixed(&gas_limit),
            EncodedContainerField::Fixed(&gas_used),
            EncodedContainerField::Fixed(&timestamp),
            EncodedContainerField::Variable(&extra_data),
            EncodedContainerField::Fixed(&base_fee_per_gas),
            EncodedContainerField::Fixed(&block_hash),
            EncodedContainerField::Fixed(&transactions_root),
            EncodedContainerField::Fixed(&withdrawals_root),
            EncodedContainerField::Fixed(&blob_gas_used),
            EncodedContainerField::Fixed(&excess_blob_gas),
        ])
    }
}

impl SszDecode for DenebExecutionPayloadHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(20),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(BYTES_PER_LOGS_BLOOM),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            parent_hash: <[u8; 32]>::decode_ssz(slices[0])?,
            fee_recipient: <[u8; 20]>::decode_ssz(slices[1])?,
            state_root: <[u8; 32]>::decode_ssz(slices[2])?,
            receipts_root: <[u8; 32]>::decode_ssz(slices[3])?,
            logs_bloom: SszVector::<u8, BYTES_PER_LOGS_BLOOM>::decode_ssz_checked(slices[4])?,
            prev_randao: <[u8; 32]>::decode_ssz(slices[5])?,
            block_number: u64::decode_ssz(slices[6])?,
            gas_limit: u64::decode_ssz(slices[7])?,
            gas_used: u64::decode_ssz(slices[8])?,
            timestamp: u64::decode_ssz(slices[9])?,
            extra_data: SszList::<u8, MAX_EXTRA_DATA_BYTES>::decode_ssz_checked(slices[10])?,
            base_fee_per_gas: <[u8; 32]>::decode_ssz(slices[11])?,
            block_hash: <[u8; 32]>::decode_ssz(slices[12])?,
            transactions_root: <[u8; 32]>::decode_ssz(slices[13])?,
            withdrawals_root: <[u8; 32]>::decode_ssz(slices[14])?,
            blob_gas_used: u64::decode_ssz(slices[15])?,
            excess_blob_gas: u64::decode_ssz(slices[16])?,
        })
    }
}

impl HashTreeRoot for DenebExecutionPayloadHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.parent_hash.hash_tree_root(),
            self.fee_recipient.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.receipts_root.hash_tree_root(),
            self.logs_bloom.hash_tree_root(),
            self.prev_randao.hash_tree_root(),
            self.block_number.hash_tree_root(),
            self.gas_limit.hash_tree_root(),
            self.gas_used.hash_tree_root(),
            self.timestamp.hash_tree_root(),
            self.extra_data.hash_tree_root(),
            self.base_fee_per_gas.hash_tree_root(),
            self.block_hash.hash_tree_root(),
            self.transactions_root.hash_tree_root(),
            self.withdrawals_root.hash_tree_root(),
            self.blob_gas_used.hash_tree_root(),
            self.excess_blob_gas.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebBeaconBlockBody {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    attester_slashings: SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    attestations: SszList<Attestation, MAX_ATTESTATIONS>,
    deposits: SszList<Deposit, MAX_DEPOSITS>,
    voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    sync_aggregate: SyncAggregate,
    execution_payload: DenebExecutionPayload,
    bls_to_execution_changes: SszList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
    blob_kzg_commitments: SszList<[u8; 48], MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

impl SszEncode for DenebBeaconBlockBody {
    fn encode_ssz(&self) -> Vec<u8> {
        let randao_reveal = self.randao_reveal.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let graffiti = self.graffiti.encode_ssz();
        let proposer_slashings = self.proposer_slashings.encode_ssz();
        let attester_slashings = self.attester_slashings.encode_ssz();
        let attestations = self.attestations.encode_ssz();
        let deposits = self.deposits.encode_ssz();
        let voluntary_exits = self.voluntary_exits.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let execution_payload = self.execution_payload.encode_ssz();
        let bls_to_execution_changes = self.bls_to_execution_changes.encode_ssz();
        let blob_kzg_commitments = self.blob_kzg_commitments.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&randao_reveal),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Fixed(&graffiti),
            EncodedContainerField::Variable(&proposer_slashings),
            EncodedContainerField::Variable(&attester_slashings),
            EncodedContainerField::Variable(&attestations),
            EncodedContainerField::Variable(&deposits),
            EncodedContainerField::Variable(&voluntary_exits),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Variable(&execution_payload),
            EncodedContainerField::Variable(&bls_to_execution_changes),
            EncodedContainerField::Variable(&blob_kzg_commitments),
        ])
    }
}

impl SszDecode for DenebBeaconBlockBody {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(96),
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            randao_reveal: <[u8; 96]>::decode_ssz(slices[0])?,
            eth1_data: Eth1Data::decode_ssz(slices[1])?,
            graffiti: <[u8; 32]>::decode_ssz(slices[2])?,
            proposer_slashings: SszList::<ProposerSlashing, MAX_PROPOSER_SLASHINGS>::decode_ssz_checked(slices[3])?,
            attester_slashings: SszList::<AttesterSlashing, MAX_ATTESTER_SLASHINGS>::decode_ssz_checked(slices[4])?,
            attestations: SszList::<Attestation, MAX_ATTESTATIONS>::decode_ssz_checked(slices[5])?,
            deposits: SszList::<Deposit, MAX_DEPOSITS>::decode_ssz_checked(slices[6])?,
            voluntary_exits: SszList::<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>::decode_ssz_checked(slices[7])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[8])?,
            execution_payload: DenebExecutionPayload::decode_ssz(slices[9])?,
            bls_to_execution_changes: SszList::<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>::decode_ssz_checked(slices[10])?,
            blob_kzg_commitments: SszList::<[u8; 48], MAX_BLOB_COMMITMENTS_PER_BLOCK>::decode_ssz_checked(slices[11])?,
        })
    }
}

impl HashTreeRoot for DenebBeaconBlockBody {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.randao_reveal.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.graffiti.hash_tree_root(),
            self.proposer_slashings.hash_tree_root(),
            self.attester_slashings.hash_tree_root(),
            self.attestations.hash_tree_root(),
            self.deposits.hash_tree_root(),
            self.voluntary_exits.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.execution_payload.hash_tree_root(),
            self.bls_to_execution_changes.hash_tree_root(),
            self.blob_kzg_commitments.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebBeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body: DenebBeaconBlockBody,
}

impl SszEncode for DenebBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let slot = self.slot.encode_ssz();
        let proposer_index = self.proposer_index.encode_ssz();
        let parent_root = self.parent_root.encode_ssz();
        let state_root = self.state_root.encode_ssz();
        let body = self.body.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&proposer_index),
            EncodedContainerField::Fixed(&parent_root),
            EncodedContainerField::Fixed(&state_root),
            EncodedContainerField::Variable(&body),
        ])
    }
}

impl SszDecode for DenebBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            slot: u64::decode_ssz(slices[0])?,
            proposer_index: u64::decode_ssz(slices[1])?,
            parent_root: <[u8; 32]>::decode_ssz(slices[2])?,
            state_root: <[u8; 32]>::decode_ssz(slices[3])?,
            body: DenebBeaconBlockBody::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for DenebBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebSignedBeaconBlock {
    message: DenebBeaconBlock,
    signature: [u8; 96],
}

impl SszEncode for DenebSignedBeaconBlock {
    fn encode_ssz(&self) -> Vec<u8> {
        let message = self.message.encode_ssz();
        let signature = self.signature.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&message),
            EncodedContainerField::Fixed(&signature),
        ])
    }
}

impl SszDecode for DenebSignedBeaconBlock {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[ContainerFieldKind::Variable, ContainerFieldKind::Fixed(96)],
        )?;
        Ok(Self {
            message: DenebBeaconBlock::decode_ssz(slices[0])?,
            signature: <[u8; 96]>::decode_ssz(slices[1])?,
        })
    }
}

impl HashTreeRoot for DenebSignedBeaconBlock {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.message.hash_tree_root(),
            self.signature.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebLightClientHeader {
    beacon: BeaconBlockHeader,
    execution: DenebExecutionPayloadHeader,
    execution_branch: SszVector<[u8; 32], EXECUTION_BRANCH_LEN>,
}

impl SszEncode for DenebLightClientHeader {
    fn encode_ssz(&self) -> Vec<u8> {
        let beacon = self.beacon.encode_ssz();
        let execution = self.execution.encode_ssz();
        let execution_branch = self.execution_branch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&beacon),
            EncodedContainerField::Variable(&execution),
            EncodedContainerField::Fixed(&execution_branch),
        ])
    }
}

impl SszDecode for DenebLightClientHeader {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EXECUTION_BRANCH_LEN),
            ],
        )?;
        Ok(Self {
            beacon: BeaconBlockHeader::decode_ssz(slices[0])?,
            execution: DenebExecutionPayloadHeader::decode_ssz(slices[1])?,
            execution_branch: SszVector::<[u8; 32], EXECUTION_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
        })
    }
}

impl HashTreeRoot for DenebLightClientHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.beacon.hash_tree_root(),
            self.execution.hash_tree_root(),
            self.execution_branch.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebLightClientBootstrap {
    header: DenebLightClientHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: SszVector<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>,
}

impl SszEncode for DenebLightClientBootstrap {
    fn encode_ssz(&self) -> Vec<u8> {
        let header = self.header.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let current_sync_committee_branch = self.current_sync_committee_branch.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&header),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&current_sync_committee_branch),
        ])
    }
}

impl SszDecode for DenebLightClientBootstrap {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(32 * CURRENT_SYNC_COMMITTEE_BRANCH_LEN),
            ],
        )?;
        Ok(Self {
            header: DenebLightClientHeader::decode_ssz(slices[0])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            current_sync_committee_branch: SszVector::<[u8; 32], CURRENT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
        })
    }
}

impl HashTreeRoot for DenebLightClientBootstrap {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.header.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.current_sync_committee_branch.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebLightClientUpdate {
    attested_header: DenebLightClientHeader,
    next_sync_committee: SyncCommittee,
    next_sync_committee_branch: SszVector<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>,
    finalized_header: DenebLightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for DenebLightClientUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let next_sync_committee_branch = self.next_sync_committee_branch.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee_branch),
            EncodedContainerField::Variable(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for DenebLightClientUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(32 * NEXT_SYNC_COMMITTEE_BRANCH_LEN),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * FINALITY_BRANCH_LEN),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: DenebLightClientHeader::decode_ssz(slices[0])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[1])?,
            next_sync_committee_branch: SszVector::<[u8; 32], NEXT_SYNC_COMMITTEE_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
            finalized_header: DenebLightClientHeader::decode_ssz(slices[3])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(slices[4])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[5])?,
            signature_slot: u64::decode_ssz(slices[6])?,
        })
    }
}

impl HashTreeRoot for DenebLightClientUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.next_sync_committee_branch.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebLightClientFinalityUpdate {
    attested_header: DenebLightClientHeader,
    finalized_header: DenebLightClientHeader,
    finality_branch: SszVector<[u8; 32], FINALITY_BRANCH_LEN>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for DenebLightClientFinalityUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let finalized_header = self.finalized_header.encode_ssz();
        let finality_branch = self.finality_branch.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Variable(&finalized_header),
            EncodedContainerField::Fixed(&finality_branch),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for DenebLightClientFinalityUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * FINALITY_BRANCH_LEN),
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: DenebLightClientHeader::decode_ssz(slices[0])?,
            finalized_header: DenebLightClientHeader::decode_ssz(slices[1])?,
            finality_branch: SszVector::<[u8; 32], FINALITY_BRANCH_LEN>::decode_ssz_checked(slices[2])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[3])?,
            signature_slot: u64::decode_ssz(slices[4])?,
        })
    }
}

impl HashTreeRoot for DenebLightClientFinalityUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.finalized_header.hash_tree_root(),
            self.finality_branch.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebLightClientOptimisticUpdate {
    attested_header: DenebLightClientHeader,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl SszEncode for DenebLightClientOptimisticUpdate {
    fn encode_ssz(&self) -> Vec<u8> {
        let attested_header = self.attested_header.encode_ssz();
        let sync_aggregate = self.sync_aggregate.encode_ssz();
        let signature_slot = self.signature_slot.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Variable(&attested_header),
            EncodedContainerField::Fixed(&sync_aggregate),
            EncodedContainerField::Fixed(&signature_slot),
        ])
    }
}

impl SszDecode for DenebLightClientOptimisticUpdate {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(160),
                ContainerFieldKind::Fixed(8),
            ],
        )?;
        Ok(Self {
            attested_header: DenebLightClientHeader::decode_ssz(slices[0])?,
            sync_aggregate: SyncAggregate::decode_ssz(slices[1])?,
            signature_slot: u64::decode_ssz(slices[2])?,
        })
    }
}

impl HashTreeRoot for DenebLightClientOptimisticUpdate {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.attested_header.hash_tree_root(),
            self.sync_aggregate.hash_tree_root(),
            self.signature_slot.hash_tree_root(),
        ])
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DenebBeaconState {
    genesis_time: u64,
    genesis_validators_root: [u8; 32],
    slot: u64,
    fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    state_roots: SszVector<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>,
    historical_roots: SszList<[u8; 32], HISTORICAL_ROOTS_LIMIT>,
    eth1_data: Eth1Data,
    eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    eth1_deposit_index: u64,
    validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    balances: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    randao_mixes: SszVector<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>,
    slashings: SszVector<u64, EPOCHS_PER_SLASHINGS_VECTOR>,
    previous_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    current_epoch_participation: SszList<u8, VALIDATOR_REGISTRY_LIMIT>,
    justification_bits: BitVector<JUSTIFICATION_BITS_LENGTH>,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    current_sync_committee: SyncCommittee,
    next_sync_committee: SyncCommittee,
    latest_execution_payload_header: DenebExecutionPayloadHeader,
    next_withdrawal_index: u64,
    next_withdrawal_validator_index: u64,
    historical_summaries: SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
}

impl SszEncode for DenebBeaconState {
    fn encode_ssz(&self) -> Vec<u8> {
        let genesis_time = self.genesis_time.encode_ssz();
        let genesis_validators_root = self.genesis_validators_root.encode_ssz();
        let slot = self.slot.encode_ssz();
        let fork = self.fork.encode_ssz();
        let latest_block_header = self.latest_block_header.encode_ssz();
        let block_roots = self.block_roots.encode_ssz();
        let state_roots = self.state_roots.encode_ssz();
        let historical_roots = self.historical_roots.encode_ssz();
        let eth1_data = self.eth1_data.encode_ssz();
        let eth1_data_votes = self.eth1_data_votes.encode_ssz();
        let eth1_deposit_index = self.eth1_deposit_index.encode_ssz();
        let validators = self.validators.encode_ssz();
        let balances = self.balances.encode_ssz();
        let randao_mixes = self.randao_mixes.encode_ssz();
        let slashings = self.slashings.encode_ssz();
        let previous_epoch_participation = self.previous_epoch_participation.encode_ssz();
        let current_epoch_participation = self.current_epoch_participation.encode_ssz();
        let justification_bits = self.justification_bits.encode_ssz();
        let previous_justified_checkpoint = self.previous_justified_checkpoint.encode_ssz();
        let current_justified_checkpoint = self.current_justified_checkpoint.encode_ssz();
        let finalized_checkpoint = self.finalized_checkpoint.encode_ssz();
        let inactivity_scores = self.inactivity_scores.encode_ssz();
        let current_sync_committee = self.current_sync_committee.encode_ssz();
        let next_sync_committee = self.next_sync_committee.encode_ssz();
        let latest_execution_payload_header = self.latest_execution_payload_header.encode_ssz();
        let next_withdrawal_index = self.next_withdrawal_index.encode_ssz();
        let next_withdrawal_validator_index = self.next_withdrawal_validator_index.encode_ssz();
        let historical_summaries = self.historical_summaries.encode_ssz();
        encode_fields(&[
            EncodedContainerField::Fixed(&genesis_time),
            EncodedContainerField::Fixed(&genesis_validators_root),
            EncodedContainerField::Fixed(&slot),
            EncodedContainerField::Fixed(&fork),
            EncodedContainerField::Fixed(&latest_block_header),
            EncodedContainerField::Fixed(&block_roots),
            EncodedContainerField::Fixed(&state_roots),
            EncodedContainerField::Variable(&historical_roots),
            EncodedContainerField::Fixed(&eth1_data),
            EncodedContainerField::Variable(&eth1_data_votes),
            EncodedContainerField::Fixed(&eth1_deposit_index),
            EncodedContainerField::Variable(&validators),
            EncodedContainerField::Variable(&balances),
            EncodedContainerField::Fixed(&randao_mixes),
            EncodedContainerField::Fixed(&slashings),
            EncodedContainerField::Variable(&previous_epoch_participation),
            EncodedContainerField::Variable(&current_epoch_participation),
            EncodedContainerField::Fixed(&justification_bits),
            EncodedContainerField::Fixed(&previous_justified_checkpoint),
            EncodedContainerField::Fixed(&current_justified_checkpoint),
            EncodedContainerField::Fixed(&finalized_checkpoint),
            EncodedContainerField::Variable(&inactivity_scores),
            EncodedContainerField::Fixed(&current_sync_committee),
            EncodedContainerField::Fixed(&next_sync_committee),
            EncodedContainerField::Variable(&latest_execution_payload_header),
            EncodedContainerField::Fixed(&next_withdrawal_index),
            EncodedContainerField::Fixed(&next_withdrawal_validator_index),
            EncodedContainerField::Variable(&historical_summaries),
        ])
    }
}

impl SszDecode for DenebBeaconState {
    fn decode_ssz(bytes: &[u8]) -> Result<Self, String> {
        let committee_len = SyncCommittee::fixed_len();
        let slices = decode_field_slices(
            bytes,
            &[
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(32),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(16),
                ContainerFieldKind::Fixed(112),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Fixed(32 * SLOTS_PER_HISTORICAL_ROOT),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(72),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(32 * EPOCHS_PER_HISTORICAL_VECTOR),
                ContainerFieldKind::Fixed(8 * EPOCHS_PER_SLASHINGS_VECTOR),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(1),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Fixed(40),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Fixed(committee_len),
                ContainerFieldKind::Variable,
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Fixed(8),
                ContainerFieldKind::Variable,
            ],
        )?;
        Ok(Self {
            genesis_time: u64::decode_ssz(slices[0])?,
            genesis_validators_root: <[u8; 32]>::decode_ssz(slices[1])?,
            slot: u64::decode_ssz(slices[2])?,
            fork: Fork::decode_ssz(slices[3])?,
            latest_block_header: BeaconBlockHeader::decode_ssz(slices[4])?,
            block_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[5])?,
            state_roots: SszVector::<[u8; 32], SLOTS_PER_HISTORICAL_ROOT>::decode_ssz_checked(slices[6])?,
            historical_roots: SszList::<[u8; 32], HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[7])?,
            eth1_data: Eth1Data::decode_ssz(slices[8])?,
            eth1_data_votes: SszList::<Eth1Data, ETH1_DATA_VOTES_LIMIT>::decode_ssz_checked(slices[9])?,
            eth1_deposit_index: u64::decode_ssz(slices[10])?,
            validators: SszList::<Validator, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[11])?,
            balances: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[12])?,
            randao_mixes: SszVector::<[u8; 32], EPOCHS_PER_HISTORICAL_VECTOR>::decode_ssz_checked(slices[13])?,
            slashings: SszVector::<u64, EPOCHS_PER_SLASHINGS_VECTOR>::decode_ssz_checked(slices[14])?,
            previous_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[15])?,
            current_epoch_participation: SszList::<u8, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[16])?,
            justification_bits: BitVector::<JUSTIFICATION_BITS_LENGTH>::decode_ssz_checked(slices[17])?,
            previous_justified_checkpoint: Checkpoint::decode_ssz(slices[18])?,
            current_justified_checkpoint: Checkpoint::decode_ssz(slices[19])?,
            finalized_checkpoint: Checkpoint::decode_ssz(slices[20])?,
            inactivity_scores: SszList::<u64, VALIDATOR_REGISTRY_LIMIT>::decode_ssz_checked(slices[21])?,
            current_sync_committee: SyncCommittee::decode_ssz(slices[22])?,
            next_sync_committee: SyncCommittee::decode_ssz(slices[23])?,
            latest_execution_payload_header: DenebExecutionPayloadHeader::decode_ssz(slices[24])?,
            next_withdrawal_index: u64::decode_ssz(slices[25])?,
            next_withdrawal_validator_index: u64::decode_ssz(slices[26])?,
            historical_summaries: SszList::<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>::decode_ssz_checked(slices[27])?,
        })
    }
}

impl HashTreeRoot for DenebBeaconState {
    fn hash_tree_root(&self) -> [u8; 32] {
        hash_tree_root_from_field_roots(&[
            self.genesis_time.hash_tree_root(),
            self.genesis_validators_root.hash_tree_root(),
            self.slot.hash_tree_root(),
            self.fork.hash_tree_root(),
            self.latest_block_header.hash_tree_root(),
            self.block_roots.hash_tree_root(),
            self.state_roots.hash_tree_root(),
            self.historical_roots.hash_tree_root(),
            self.eth1_data.hash_tree_root(),
            self.eth1_data_votes.hash_tree_root(),
            self.eth1_deposit_index.hash_tree_root(),
            self.validators.hash_tree_root(),
            self.balances.hash_tree_root(),
            self.randao_mixes.hash_tree_root(),
            self.slashings.hash_tree_root(),
            self.previous_epoch_participation.hash_tree_root(),
            self.current_epoch_participation.hash_tree_root(),
            self.justification_bits.hash_tree_root(),
            self.previous_justified_checkpoint.hash_tree_root(),
            self.current_justified_checkpoint.hash_tree_root(),
            self.finalized_checkpoint.hash_tree_root(),
            self.inactivity_scores.hash_tree_root(),
            self.current_sync_committee.hash_tree_root(),
            self.next_sync_committee.hash_tree_root(),
            self.latest_execution_payload_header.hash_tree_root(),
            self.next_withdrawal_index.hash_tree_root(),
            self.next_withdrawal_validator_index.hash_tree_root(),
            self.historical_summaries.hash_tree_root(),
        ])
    }
}

impl SszFixedLen for Eth1Data {
    fn fixed_len() -> usize {
        72
    }
}

impl SszFixedLen for DepositMessage {
    fn fixed_len() -> usize {
        88
    }
}

impl SszFixedLen for DepositData {
    fn fixed_len() -> usize {
        184
    }
}

impl SszFixedLen for SignedVoluntaryExit {
    fn fixed_len() -> usize {
        112
    }
}

impl SszFixedLen for ProposerSlashing {
    fn fixed_len() -> usize {
        416
    }
}

impl SszFixedLen for Deposit {
    fn fixed_len() -> usize {
        (32 * DEPOSIT_PROOF_LEN) + 184
    }
}

impl SszFixedLen for PowBlock {
    fn fixed_len() -> usize {
        96
    }
}

impl SszFixedLen for Withdrawal {
    fn fixed_len() -> usize {
        44
    }
}

impl SszFixedLen for BLSToExecutionChange {
    fn fixed_len() -> usize {
        76
    }
}

impl SszFixedLen for SignedBLSToExecutionChange {
    fn fixed_len() -> usize {
        172
    }
}

impl SszFixedLen for HistoricalSummary {
    fn fixed_len() -> usize {
        64
    }
}

impl SszFixedLen for BlobIdentifier {
    fn fixed_len() -> usize {
        40
    }
}

impl SszFixedLen for BlobSidecar {
    fn fixed_len() -> usize {
        8 + BYTES_PER_BLOB + 48 + 48 + 208 + (32 * KZG_COMMITMENT_INCLUSION_PROOF_DEPTH)
    }
}

impl SszElement for PendingAttestation {}
impl SszElement for Attestation {}
impl SszElement for AttesterSlashing {}

#[test]
fn minimal_shared_fork() {
    run_shared_minimal_type::<Fork>("Fork");
}

#[test]
fn minimal_shared_fork_data() {
    run_shared_minimal_type::<ForkData>("ForkData");
}

#[test]
fn minimal_shared_checkpoint() {
    run_shared_minimal_type::<Checkpoint>("Checkpoint");
}

#[test]
fn minimal_shared_beacon_block_header() {
    run_shared_minimal_type::<BeaconBlockHeader>("BeaconBlockHeader");
}

#[test]
fn minimal_shared_signed_beacon_block_header() {
    run_shared_minimal_type::<SignedBeaconBlockHeader>("SignedBeaconBlockHeader");
}

#[test]
fn minimal_shared_signing_data() {
    run_shared_minimal_type::<SigningData>("SigningData");
}

#[test]
fn minimal_shared_voluntary_exit() {
    run_shared_minimal_type::<VoluntaryExit>("VoluntaryExit");
}

#[test]
fn minimal_shared_signed_voluntary_exit() {
    run_shared_minimal_type::<SignedVoluntaryExit>("SignedVoluntaryExit");
}

#[test]
fn minimal_shared_deposit_message() {
    run_shared_minimal_type::<DepositMessage>("DepositMessage");
}

#[test]
fn minimal_shared_deposit_data() {
    run_shared_minimal_type::<DepositData>("DepositData");
}

#[test]
fn minimal_shared_eth1_data() {
    run_shared_minimal_type::<Eth1Data>("Eth1Data");
}

#[test]
fn minimal_shared_eth1_block() {
    run_shared_minimal_type::<Eth1Block>("Eth1Block");
}

#[test]
fn minimal_shared_validator() {
    run_shared_minimal_type::<Validator>("Validator");
}

#[test]
fn minimal_shared_attestation_data() {
    run_shared_minimal_type::<AttestationData>("AttestationData");
}

#[test]
fn minimal_shared_indexed_attestation() {
    run_minimal_type_for_forks::<IndexedAttestation>(
        "IndexedAttestation",
        LEGACY_ATTESTATION_FORKS,
    );
}

#[test]
fn minimal_shared_pending_attestation() {
    run_shared_minimal_type::<PendingAttestation>("PendingAttestation");
}

#[test]
fn minimal_shared_attestation() {
    run_minimal_type_for_forks::<Attestation>("Attestation", LEGACY_ATTESTATION_FORKS);
}

#[test]
fn minimal_shared_proposer_slashing() {
    run_shared_minimal_type::<ProposerSlashing>("ProposerSlashing");
}

#[test]
fn minimal_shared_attester_slashing() {
    run_minimal_type_for_forks::<AttesterSlashing>("AttesterSlashing", LEGACY_ATTESTATION_FORKS);
}

#[test]
fn minimal_shared_aggregate_and_proof() {
    run_minimal_type_for_forks::<AggregateAndProof>(
        "AggregateAndProof",
        LEGACY_ATTESTATION_FORKS,
    );
}

#[test]
fn minimal_shared_signed_aggregate_and_proof() {
    run_minimal_type_for_forks::<SignedAggregateAndProof>(
        "SignedAggregateAndProof",
        LEGACY_ATTESTATION_FORKS,
    );
}

#[test]
fn minimal_shared_deposit() {
    run_shared_minimal_type::<Deposit>("Deposit");
}

#[test]
fn minimal_shared_historical_batch() {
    run_shared_minimal_type::<HistoricalBatch>("HistoricalBatch");
}

#[test]
fn minimal_phase0_beacon_block_body() {
    run_minimal_type_for_forks::<Phase0BeaconBlockBody>("BeaconBlockBody", &["phase0"]);
}

#[test]
fn minimal_phase0_beacon_block() {
    run_minimal_type_for_forks::<Phase0BeaconBlock>("BeaconBlock", &["phase0"]);
}

#[test]
fn minimal_phase0_signed_beacon_block() {
    run_minimal_type_for_forks::<Phase0SignedBeaconBlock>("SignedBeaconBlock", &["phase0"]);
}

#[test]
fn minimal_phase0_beacon_state() {
    run_minimal_type_for_forks::<Phase0BeaconState>("BeaconState", &["phase0"]);
}

#[test]
fn minimal_altair_beacon_block_body() {
    run_minimal_type_for_forks::<AltairBeaconBlockBody>("BeaconBlockBody", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_beacon_block() {
    run_minimal_type_for_forks::<AltairBeaconBlock>("BeaconBlock", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_signed_beacon_block() {
    run_minimal_type_for_forks::<AltairSignedBeaconBlock>("SignedBeaconBlock", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_beacon_state() {
    run_minimal_type_for_forks::<AltairBeaconState>("BeaconState", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_bellatrix_pow_block() {
    run_minimal_type_for_forks::<PowBlock>("PowBlock", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_execution_payload() {
    run_minimal_type_for_forks::<ExecutionPayload>("ExecutionPayload", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_execution_payload_header() {
    run_minimal_type_for_forks::<ExecutionPayloadHeader>("ExecutionPayloadHeader", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_beacon_block_body() {
    run_minimal_type_for_forks::<BellatrixBeaconBlockBody>("BeaconBlockBody", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_beacon_block() {
    run_minimal_type_for_forks::<BellatrixBeaconBlock>("BeaconBlock", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_signed_beacon_block() {
    run_minimal_type_for_forks::<BellatrixSignedBeaconBlock>("SignedBeaconBlock", &["bellatrix"]);
}

#[test]
fn minimal_bellatrix_beacon_state() {
    run_minimal_type_for_forks::<BellatrixBeaconState>("BeaconState", &["bellatrix"]);
}

#[test]
fn minimal_capella_withdrawal() {
    run_minimal_type_for_forks::<Withdrawal>("Withdrawal", &["capella"]);
}

#[test]
fn minimal_capella_bls_to_execution_change() {
    run_minimal_type_for_forks::<BLSToExecutionChange>("BLSToExecutionChange", &["capella"]);
}

#[test]
fn minimal_capella_signed_bls_to_execution_change() {
    run_minimal_type_for_forks::<SignedBLSToExecutionChange>(
        "SignedBLSToExecutionChange",
        &["capella"],
    );
}

#[test]
fn minimal_capella_historical_summary() {
    run_minimal_type_for_forks::<HistoricalSummary>("HistoricalSummary", &["capella"]);
}

#[test]
fn minimal_capella_execution_payload() {
    run_minimal_type_for_forks::<CapellaExecutionPayload>("ExecutionPayload", &["capella"]);
}

#[test]
fn minimal_capella_execution_payload_header() {
    run_minimal_type_for_forks::<CapellaExecutionPayloadHeader>(
        "ExecutionPayloadHeader",
        &["capella"],
    );
}

#[test]
fn minimal_capella_beacon_block_body() {
    run_minimal_type_for_forks::<CapellaBeaconBlockBody>("BeaconBlockBody", &["capella"]);
}

#[test]
fn minimal_capella_beacon_block() {
    run_minimal_type_for_forks::<CapellaBeaconBlock>("BeaconBlock", &["capella"]);
}

#[test]
fn minimal_capella_signed_beacon_block() {
    run_minimal_type_for_forks::<CapellaSignedBeaconBlock>("SignedBeaconBlock", &["capella"]);
}

#[test]
fn minimal_capella_light_client_header() {
    run_minimal_type_for_forks::<CapellaLightClientHeader>("LightClientHeader", &["capella"]);
}

#[test]
fn minimal_capella_light_client_bootstrap() {
    run_minimal_type_for_forks::<CapellaLightClientBootstrap>(
        "LightClientBootstrap",
        &["capella"],
    );
}

#[test]
fn minimal_capella_light_client_update() {
    run_minimal_type_for_forks::<CapellaLightClientUpdate>("LightClientUpdate", &["capella"]);
}

#[test]
fn minimal_capella_light_client_finality_update() {
    run_minimal_type_for_forks::<CapellaLightClientFinalityUpdate>(
        "LightClientFinalityUpdate",
        &["capella"],
    );
}

#[test]
fn minimal_capella_light_client_optimistic_update() {
    run_minimal_type_for_forks::<CapellaLightClientOptimisticUpdate>(
        "LightClientOptimisticUpdate",
        &["capella"],
    );
}

#[test]
fn minimal_capella_beacon_state() {
    run_minimal_type_for_forks::<CapellaBeaconState>("BeaconState", &["capella"]);
}

#[test]
fn minimal_deneb_blob_identifier() {
    run_minimal_type_for_forks::<BlobIdentifier>("BlobIdentifier", &["deneb"]);
}

#[test]
fn minimal_deneb_blob_sidecar() {
    run_minimal_type_for_forks::<BlobSidecar>("BlobSidecar", &["deneb"]);
}

#[test]
fn minimal_deneb_execution_payload() {
    run_minimal_type_for_forks::<DenebExecutionPayload>("ExecutionPayload", &["deneb"]);
}

#[test]
fn minimal_deneb_execution_payload_header() {
    run_minimal_type_for_forks::<DenebExecutionPayloadHeader>(
        "ExecutionPayloadHeader",
        &["deneb"],
    );
}

#[test]
fn minimal_deneb_beacon_block_body() {
    run_minimal_type_for_forks::<DenebBeaconBlockBody>("BeaconBlockBody", &["deneb"]);
}

#[test]
fn minimal_deneb_beacon_block() {
    run_minimal_type_for_forks::<DenebBeaconBlock>("BeaconBlock", &["deneb"]);
}

#[test]
fn minimal_deneb_signed_beacon_block() {
    run_minimal_type_for_forks::<DenebSignedBeaconBlock>("SignedBeaconBlock", &["deneb"]);
}

#[test]
fn minimal_deneb_light_client_header() {
    run_minimal_type_for_forks::<DenebLightClientHeader>("LightClientHeader", &["deneb"]);
}

#[test]
fn minimal_deneb_light_client_bootstrap() {
    run_minimal_type_for_forks::<DenebLightClientBootstrap>("LightClientBootstrap", &["deneb"]);
}

#[test]
fn minimal_deneb_light_client_update() {
    run_minimal_type_for_forks::<DenebLightClientUpdate>("LightClientUpdate", &["deneb"]);
}

#[test]
fn minimal_deneb_light_client_finality_update() {
    run_minimal_type_for_forks::<DenebLightClientFinalityUpdate>(
        "LightClientFinalityUpdate",
        &["deneb"],
    );
}

#[test]
fn minimal_deneb_light_client_optimistic_update() {
    run_minimal_type_for_forks::<DenebLightClientOptimisticUpdate>(
        "LightClientOptimisticUpdate",
        &["deneb"],
    );
}

#[test]
fn minimal_deneb_beacon_state() {
    run_minimal_type_for_forks::<DenebBeaconState>("BeaconState", &["deneb"]);
}

#[test]
fn minimal_altair_plus_sync_aggregate() {
    run_minimal_type_for_forks::<SyncAggregate>("SyncAggregate", ALTAIR_PLUS_FORKS);
}

#[test]
fn minimal_altair_plus_sync_committee() {
    run_minimal_type_for_forks::<SyncCommittee>("SyncCommittee", ALTAIR_PLUS_FORKS);
}

#[test]
fn minimal_altair_plus_sync_committee_message() {
    run_minimal_type_for_forks::<SyncCommitteeMessage>("SyncCommitteeMessage", ALTAIR_PLUS_FORKS);
}

#[test]
fn minimal_altair_plus_sync_committee_contribution() {
    run_minimal_type_for_forks::<SyncCommitteeContribution>(
        "SyncCommitteeContribution",
        ALTAIR_PLUS_FORKS,
    );
}

#[test]
fn minimal_altair_plus_contribution_and_proof() {
    run_minimal_type_for_forks::<ContributionAndProof>(
        "ContributionAndProof",
        ALTAIR_PLUS_FORKS,
    );
}

#[test]
fn minimal_altair_plus_signed_contribution_and_proof() {
    run_minimal_type_for_forks::<SignedContributionAndProof>(
        "SignedContributionAndProof",
        ALTAIR_PLUS_FORKS,
    );
}

#[test]
fn minimal_altair_plus_sync_aggregator_selection_data() {
    run_minimal_type_for_forks::<SyncAggregatorSelectionData>(
        "SyncAggregatorSelectionData",
        ALTAIR_PLUS_FORKS,
    );
}

#[test]
fn minimal_altair_light_client_header() {
    run_minimal_type_for_forks::<LightClientHeader>("LightClientHeader", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_light_client_bootstrap() {
    run_minimal_type_for_forks::<LightClientBootstrap>("LightClientBootstrap", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_light_client_update() {
    run_minimal_type_for_forks::<LightClientUpdate>("LightClientUpdate", ALTAIR_ONLY_FORKS);
}

#[test]
fn minimal_altair_light_client_finality_update() {
    run_minimal_type_for_forks::<LightClientFinalityUpdate>(
        "LightClientFinalityUpdate",
        ALTAIR_ONLY_FORKS,
    );
}

#[test]
fn minimal_altair_light_client_optimistic_update() {
    run_minimal_type_for_forks::<LightClientOptimisticUpdate>(
        "LightClientOptimisticUpdate",
        ALTAIR_ONLY_FORKS,
    );
}
