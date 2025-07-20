// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarking for Proof of Coherence pallet.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::{benchmarks, whitelisted_caller, account};
use frame_system::RawOrigin;
use sp_std::vec;

benchmarks! {
	register_validator {
		let caller: T::AccountId = whitelisted_caller();
		let initial_frequency = 440u32; // A440 Hz
		let phase = 0u32;
		
		// Ensure we have quantum entropy
		pallet_quantum_crypto::EntropyPool::<T>::put(vec![42u8; 100]);
		
	}: _(RawOrigin::Signed(caller.clone()), initial_frequency, phase)
	verify {
		assert!(Validators::<T>::get().contains(&caller));
	}
	
	submit_coherence_proof {
		let caller: T::AccountId = whitelisted_caller();
		
		// Register first
		let _ = Pallet::<T>::register_validator(
			RawOrigin::Signed(caller.clone()).into(),
			440u32,
			0u32,
		);
		
		let frequency_measurement = 440u32;
		let phase_measurement = 15u32;
		let spectral_purity = 95u8;
		let quantum_fidelity = 90u8;
		
	}: _(RawOrigin::Signed(caller.clone()), frequency_measurement, phase_measurement, spectral_purity, quantum_fidelity)
	verify {
		assert!(CoherenceProofs::<T>::contains_key(&caller));
	}
	
	harmonic_transform {
		let caller: T::AccountId = whitelisted_caller();
		
		// Register first
		let _ = Pallet::<T>::register_validator(
			RawOrigin::Signed(caller.clone()).into(),
			440u32,
			0u32,
		);
		
		let transform_type = TonnetzTransform::Parallel;
		
	}: _(RawOrigin::Signed(caller.clone()), transform_type)
	verify {
		// Position should have changed
		let position = TonnetzPositions::<T>::get(&caller).unwrap();
		assert_eq!(position.pitch_class, 3); // Parallel transform adds minor third
	}
	
	update_network_harmonics {
		// Setup validators
		let validator_count = T::MaxValidators::get() / 2;
		for i in 0..validator_count {
			let validator: T::AccountId = account("validator", i, 0);
			let _ = Pallet::<T>::register_validator(
				RawOrigin::Signed(validator.clone()).into(),
				440u32 + i,
				i * 10,
			);
			
			// Submit coherence proof
			let _ = Pallet::<T>::submit_coherence_proof(
				RawOrigin::Signed(validator).into(),
				440u32 + i,
				i * 10,
				90u8,
				85u8,
			);
		}
		
		// Ensure enough blocks have passed
		LastCoherenceCheck::<T>::put(0u32.into());
		frame_system::Pallet::<T>::set_block_number(T::CoherencePeriod::get() + 1u32.into());
		
	}: _(RawOrigin::Root)
	verify {
		// Network state should be updated
		let state = NetworkHarmonicState::<T>::get();
		assert!(state.coherence_level > 0);
	}
	
	emergency_phase_reset {
		// Setup some validators
		for i in 0..5 {
			let validator: T::AccountId = account("validator", i, 0);
			let _ = Pallet::<T>::register_validator(
				RawOrigin::Signed(validator.clone()).into(),
				440u32,
				0u32,
			);
		}
		
	}: _(RawOrigin::Root)
	verify {
		// Network state should be reset
		let state = NetworkHarmonicState::<T>::get();
		assert_eq!(state, HarmonicState::default());
	}
	
	impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}