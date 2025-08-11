//! Mock runtime for testing

use crate as pallet_quantum_crypto;
use frame_support::{parameter_types, traits::ConstU32};
use sp_runtime::{traits::{BlakeTwo256, IdentityLookup}, BuildStorage};
use scale_info::TypeInfo;

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        QuantumCrypto: pallet_quantum_crypto,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const SS58Prefix: u8 = 42;
}

#[derive(Clone, Debug, Eq, PartialEq, TypeInfo)]
pub struct MaxEntropyPoolSize;
impl frame_support::traits::Get<u32> for MaxEntropyPoolSize {
    fn get() -> u32 {
        1024
    }
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = sp_core::H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type RuntimeTask = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
    type ExtensionsWeightInfo = ();
}

// Implement CreateBare for Test runtime
use frame_system::offchain::{CreateBare, CreateTransactionBase};
use crate::Call as QuantumCryptoCall;

// Mock extrinsic type
type MockExtrinsic = sp_runtime::testing::TestXt<RuntimeCall, ()>;

impl CreateTransactionBase<QuantumCryptoCall<Test>> for Test {
    type RuntimeCall = RuntimeCall;
    type Extrinsic = MockExtrinsic;
}

impl CreateBare<QuantumCryptoCall<Test>> for Test {
    fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
        MockExtrinsic::new_bare(call)
    }
}

impl pallet_quantum_crypto::Config for Test {
    type MaxEntropyPoolSize = MaxEntropyPoolSize;
    type QkdEndpoint = ();
    type MinSecureQber = ConstU32<1100>; // 11%
    type MaxMeasurementsPerProof = ConstU32<10000>;
    type MaxProofSize = ConstU32<65536>;
    type MaxCertificateSize = ConstU32<4096>;
}

// Build genesis storage
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = RuntimeGenesisConfig {
        system: Default::default(),
    }
    .build_storage()
    .unwrap();
    
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}