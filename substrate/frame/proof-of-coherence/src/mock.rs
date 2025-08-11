//! Mock runtime for testing Proof of Coherence

use crate as pallet_proof_of_coherence;
use frame_support::{
    parameter_types,
    traits::{ConstU16, ConstU32, ConstU64, ConstU128},
};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        QuantumCrypto: pallet_quantum_crypto,
        ProofOfCoherence: pallet_proof_of_coherence,
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u128>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type RuntimeTask = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

impl pallet_balances::Config for Test {
    type Balance = u128;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
    type DoneSlashHandler = ();
}

impl pallet_quantum_crypto::Config for Test {
    type MaxEntropyPoolSize = ConstU32<1024>;
    type QkdEndpoint = ();
    type MinSecureQber = ConstU32<1100>;
    type MaxMeasurementsPerProof = ConstU32<10000>;
    type MaxProofSize = ConstU32<65536>;
    type MaxCertificateSize = ConstU32<4096>;
}

parameter_types! {
    pub const MinimumCoherenceScore: u32 = 5000;  // 50%
    pub const MaxValidators: u32 = 100;
    pub const CoherencePeriod: u64 = 100;  // blocks
    pub const CoherenceReward: u128 = 10;
    pub const CoherenceSlash: u128 = 5;
}

impl pallet_proof_of_coherence::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MinimumCoherenceScore = MinimumCoherenceScore;
    type MaxValidators = MaxValidators;
    type CoherencePeriod = CoherencePeriod;
    type CoherenceReward = CoherenceReward;
    type CoherenceSlash = CoherenceSlash;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
        
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (1, 1000),
            (2, 1000),
            (3, 1000),
            (4, 1000),
        ],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    t.into()
}