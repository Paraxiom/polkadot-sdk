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
    spec_name: create_runtime_str!("quantum-minimal"),
    impl_name: create_runtime_str!("quantum-minimal"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: sp_version::create_apis_vec!([]),
    transaction_version: 1,
    system_version: 1,
};

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

pub type Signature = sp_runtime::MultiSignature;
pub type AccountPublic = <Signature as Verify>::Signer;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type Index = u32;
pub type BlockNumber = u32;
pub type Hash = H256;
pub type Hashing = sp_runtime::traits::BlakeTwo256;
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
    type AccountData = ();
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

// Quantum crypto parameters
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

// Simple randomness source
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

// Minimal runtime with just core quantum functionality
construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Timestamp: pallet_timestamp,
        QuantumCrypto: pallet_quantum_crypto,
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
}