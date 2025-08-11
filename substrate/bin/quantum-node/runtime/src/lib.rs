#![cfg_attr(not(feature = "std"), no_std)]

use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{Block as BlockT, IdentifyAccount, Verify},
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult,
};
use codec::Encode;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, H256};
use sp_std::prelude::*;
use sp_version::RuntimeVersion;
use sp_runtime::traits::Hash as HashT;
use scale_info::TypeInfo;

use frame_support::{
    construct_runtime, parameter_types,
    traits::{ConstU128, ConstU32, ConstU64, ConstU8},
    weights::{constants::WEIGHT_REF_TIME_PER_SECOND, Weight},
};
use frame_system::EnsureRoot;

pub use sp_runtime::{Perbill, Permill};
pub use frame_support::{
    StorageValue,
    weights::{constants::RocksDbWeight, IdentityFee},
};
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

// TODO: Enable quantum hasher when fully integrated
// use sp_core::QuantumHasher;

/// Opaque types
pub mod opaque {
    use super::*;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
    pub type Header = generic::Header<BlockNumber, Hashing>;
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    pub type BlockId = generic::BlockId<Block>;
}

impl_opaque_keys! {
    pub struct SessionKeys {}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("quantum"),
    impl_name: create_runtime_str!("quantum-node"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: sp_version::create_apis_vec!([]),
    transaction_version: 1,
    system_version: 1,
};

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Use standard signature for now until quantum signatures are fully integrated
pub type Signature = sp_runtime::MultiSignature;
pub type AccountPublic = <Signature as Verify>::Signer;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type Index = u32;
pub type BlockNumber = u32;
pub type Hash = H256;
pub type Hashing = sp_runtime::traits::BlakeTwo256; // TODO: Replace with QuantumHasher when ready
pub type Header = generic::Header<BlockNumber, Hashing>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<AccountId, RuntimeCall, Signature, SignedExtra>;
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;
    pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Runtime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = RocksDbWeight;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = Index;
    type Hash = Hash;
    type Hashing = Hashing;
    type AccountId = AccountId;
    type Lookup = sp_runtime::traits::IdentityLookup<AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = Version;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type RuntimeTask = ();
    type ExtensionsWeightInfo = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: u128 = 1;
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
    type DoneSlashHandler = ();
}

parameter_types! {
    pub const TransactionByteFee: Balance = 1;
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
    type OperationalFeeMultiplier = ConstU8<5>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ();
    type WeightInfo = ();
}

// Define quantum crypto parameter types with required traits
#[derive(Clone, Eq, PartialEq, Debug, scale_info::TypeInfo)]
pub struct MaxEntropyPoolSize;
impl frame_support::traits::Get<u32> for MaxEntropyPoolSize {
    fn get() -> u32 { 10_000 }
}

parameter_types! {
    pub const MinSecureQber: u32 = 1100; // 11%
    pub const MaxMeasurementsPerProof: u32 = 100;
    pub const MaxProofSize: u32 = 65536; // 64KB
    pub const MaxCertificateSize: u32 = 4096; // 4KB
}

// Implement a simple randomness source for quantum crypto
pub struct TimestampRandomness;
impl frame_support::traits::Randomness<Hash, BlockNumber> for TimestampRandomness {
    fn random(subject: &[u8]) -> (Hash, BlockNumber) {
        let block_number = frame_system::Pallet::<Runtime>::block_number();
        let seed = (
            subject,
            pallet_timestamp::Pallet::<Runtime>::get(),
            block_number,
        ).using_encoded(|b| Hashing::hash(b));
        (seed.into(), block_number)
    }
}

impl pallet_quantum_crypto::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MyRandomness = TimestampRandomness;
    type MaxEntropyPoolSize = MaxEntropyPoolSize;
    type QkdEndpoint = ();
    type MinSecureQber = MinSecureQber;
    type MaxMeasurementsPerProof = MaxMeasurementsPerProof;
    type MaxProofSize = MaxProofSize;
    type MaxCertificateSize = MaxCertificateSize;
}

// Quantum Accounts Config
parameter_types! {
    pub const MaxQuantumSignatureSize: u32 = 50_000; // 50KB for SPHINCS+
    pub const AllowFalconForTransactions: bool = true;
}

parameter_types! {
    pub const ClassicalSignatureSunsetBlock: BlockNumber = 1_000_000; // Block when classical signatures are disabled
}

impl pallet_quantum_accounts::Config for Runtime {
    type MaxQuantumSignatureSize = MaxQuantumSignatureSize;
    type AllowFalconForTransactions = AllowFalconForTransactions;
    type ClassicalSignatureSunsetBlock = ClassicalSignatureSunsetBlock;
}

// Proof of Coherence Config
parameter_types! {
    pub const MinimumCoherenceScore: u32 = 50;
    pub const MaxValidators: u32 = 100;
    pub const CoherencePeriod: BlockNumber = 100;
    pub const CoherenceReward: Balance = 1_000_000;
    pub const CoherenceSlash: Balance = 500_000;
}

impl pallet_proof_of_coherence::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MinimumCoherenceScore = MinimumCoherenceScore;
    type MaxValidators = MaxValidators;
    type CoherencePeriod = CoherencePeriod;
    type CoherenceReward = CoherenceReward;
    type CoherenceSlash = CoherenceSlash;
}

// Quantum Aura Config
parameter_types! {
    pub const MaxAuthorities: u32 = 100;
    pub const MaxSignatureSize: u32 = 50_000; // 50KB for SPHINCS+
}

impl pallet_quantum_aura::Config for Runtime {
    type MaxSignatureSize = MaxSignatureSize;
}

// Quantum Verification Config
// TODO: Fix compilation errors and re-enable
// impl pallet_quantum_verification::Config for Runtime {
//     type RuntimeEvent = RuntimeEvent;
// }

// Encrypted Payload Config
#[derive(Clone, Eq, PartialEq, Debug, scale_info::TypeInfo)]
pub struct MaxPayloadSize;
impl frame_support::traits::Get<u32> for MaxPayloadSize {
    fn get() -> u32 { 1_000_000 } // 1MB max encrypted payload
}

parameter_types! {
    pub const MaxMessagesPerAccount: u32 = 100;
}

impl pallet_encrypted_payload::Config for Runtime {
    type MaxPayloadSize = MaxPayloadSize;
    type MaxMessagesPerAccount = MaxMessagesPerAccount;
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,
        QuantumCrypto: pallet_quantum_crypto,
        QuantumAccounts: pallet_quantum_accounts,
        ProofOfCoherence: pallet_proof_of_coherence,
        QuantumAura: pallet_quantum_aura,
        // QuantumVerification: pallet_quantum_verification, // TODO: Fix compilation errors
        EncryptedPayload: pallet_encrypted_payload,
    }
);

// Runtime APIs implementation
sp_api::impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }
        
        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }
        
        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime
    where
        Block: BlockT,
    {
        fn account_nonce(account: AccountId) -> Index {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        
        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
        
        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }
        
        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }
}

