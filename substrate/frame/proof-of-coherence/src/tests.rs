// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Tests for Proof of Coherence pallet.

use crate::{self as pallet_proof_of_coherence, *};
use frame_support::{
	assert_ok, assert_noop,
	traits::{ConstU32, ConstU64},
	parameter_types,
};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		QuantumCrypto: pallet_quantum_crypto,
		ProofOfCoherence: pallet_proof_of_coherence,
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

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
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
	type Balance = u64;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type RuntimeHoldReason = ();
	type FreezeIdentifier = ();
	type MaxHolds = ();
	type MaxFreezes = ();
}

parameter_types! {
	pub const MaxEntropyPoolSize: u32 = 1000;
	pub const QkdEndpoint: Vec<u8> = b"localhost:8001".to_vec();
}

impl pallet_quantum_crypto::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxEntropyPoolSize = MaxEntropyPoolSize;
	type QkdEndpoint = QkdEndpoint;
}

parameter_types! {
	pub const MinimumCoherenceScore: u32 = 50;
	pub const MaxValidators: u32 = 10;
	pub const CoherencePeriod: u64 = 10;
	pub const CoherenceReward: u64 = 100;
	pub const CoherenceSlash: u64 = 50;
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type MinimumCoherenceScore = MinimumCoherenceScore;
	type MaxValidators = MaxValidators;
	type CoherencePeriod = CoherencePeriod;
	type CoherenceReward = CoherenceReward;
	type CoherenceSlash = CoherenceSlash;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(1, 10000), (2, 10000), (3, 10000)],
	}
	.assimilate_storage(&mut t)
	.unwrap();
	
	// Add quantum entropy for testing
	pallet_quantum_crypto::GenesisConfig::<Test> {
		_config: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();
	
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		System::set_block_number(1);
		// Add some entropy for tests
		pallet_quantum_crypto::EntropyPool::<Test>::put(vec![42u8; 100]);
	});
	ext
}

#[test]
fn register_validator_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		assert!(Validators::<Test>::get().contains(&1));
		assert!(TonnetzPositions::<Test>::contains_key(&1));
		assert_eq!(CoherenceScores::<Test>::get(&1), 100);
	});
}

#[test]
fn cannot_register_twice() {
	new_test_ext().execute_with(|| {
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		assert_noop!(
			ProofOfCoherence::register_validator(RuntimeOrigin::signed(1), 440, 0),
			Error::<Test>::AlreadyValidator
		);
	});
}

#[test]
fn submit_coherence_proof_works() {
	new_test_ext().execute_with(|| {
		// Register first
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		// Submit proof
		assert_ok!(ProofOfCoherence::submit_coherence_proof(
			RuntimeOrigin::signed(1),
			440,
			10,
			90,
			85
		));
		
		assert!(CoherenceProofs::<Test>::contains_key(&1));
	});
}

#[test]
fn harmonic_transform_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		let initial_pos = TonnetzPositions::<Test>::get(&1).unwrap();
		
		assert_ok!(ProofOfCoherence::harmonic_transform(
			RuntimeOrigin::signed(1),
			TonnetzTransform::Parallel
		));
		
		let new_pos = TonnetzPositions::<Test>::get(&1).unwrap();
		assert_ne!(initial_pos, new_pos);
		assert_eq!(new_pos.pitch_class, 3); // Parallel adds minor third
	});
}

#[test]
fn network_harmonics_update_works() {
	new_test_ext().execute_with(|| {
		// Register validators
		for i in 1..=3 {
			assert_ok!(ProofOfCoherence::register_validator(
				RuntimeOrigin::signed(i),
				440,
				0
			));
			
			// Submit proofs
			assert_ok!(ProofOfCoherence::submit_coherence_proof(
				RuntimeOrigin::signed(i),
				440,
				i as u32 * 10,
				90,
				85
			));
		}
		
		// Fast forward
		System::set_block_number(11);
		
		assert_ok!(ProofOfCoherence::update_network_harmonics(RuntimeOrigin::root()));
		
		let state = NetworkHarmonicState::<Test>::get();
		assert!(state.coherence_level > 0);
		assert_eq!(state.resonance_nodes, 3);
	});
}

#[test]
fn coherence_rewards_work() {
	new_test_ext().execute_with(|| {
		let initial_balance = Balances::free_balance(&1);
		
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		assert_ok!(ProofOfCoherence::submit_coherence_proof(
			RuntimeOrigin::signed(1),
			440,
			0,
			90,
			90
		));
		
		System::set_block_number(11);
		assert_ok!(ProofOfCoherence::update_network_harmonics(RuntimeOrigin::root()));
		
		// Should have received reward
		assert!(Balances::free_balance(&1) > initial_balance);
	});
}

#[test]
fn low_coherence_removes_validator() {
	new_test_ext().execute_with(|| {
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		// Set very low coherence score
		CoherenceScores::<Test>::insert(&1, 5);
		
		System::set_block_number(11);
		assert_ok!(ProofOfCoherence::update_network_harmonics(RuntimeOrigin::root()));
		
		// Validator should be removed
		assert!(!Validators::<Test>::get().contains(&1));
	});
}

#[test]
fn tonnetz_transformations_cycle() {
	new_test_ext().execute_with(|| {
		assert_ok!(ProofOfCoherence::register_validator(
			RuntimeOrigin::signed(1),
			440,
			0
		));
		
		let initial_pos = TonnetzPositions::<Test>::get(&1).unwrap();
		
		// Apply PLR cycle (should return to original)
		assert_ok!(ProofOfCoherence::harmonic_transform(
			RuntimeOrigin::signed(1),
			TonnetzTransform::Parallel
		));
		assert_ok!(ProofOfCoherence::harmonic_transform(
			RuntimeOrigin::signed(1),
			TonnetzTransform::LeadingTone
		));
		assert_ok!(ProofOfCoherence::harmonic_transform(
			RuntimeOrigin::signed(1),
			TonnetzTransform::Relative
		));
		
		// Should have moved through the lattice
		let final_pos = TonnetzPositions::<Test>::get(&1).unwrap();
		assert_ne!(initial_pos, final_pos);
	});
}