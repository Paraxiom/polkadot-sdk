// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Consensus trait implementations for Proof of Coherence.

use crate::{Config, Pallet, Validators, CoherenceScores, NetworkHarmonicState};
// use sp_consensus::{BlockOrigin, Environment, Proposer, SelectChain};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_std::vec::Vec;
use codec::{Decode, Encode};

/// Proof of Coherence consensus data included in blocks
#[derive(Clone, Encode, Decode)]
pub struct CoherenceConsensusData {
	/// Validator who maintained highest coherence
	pub primary_validator: Vec<u8>,
	/// Network harmonic state at block creation
	pub harmonic_state: crate::types::HarmonicState,
	/// Coherence score of block producer
	pub coherence_score: u32,
}

/// Select the validator with highest coherence score
pub fn select_primary_validator<T: Config>() -> Option<T::AccountId> {
	let validators = Validators::<T>::get();
	
	validators
		.into_iter()
		.max_by_key(|v| CoherenceScores::<T>::get(v))
}

/// Check if a validator is eligible to produce blocks
pub fn is_validator_eligible<T: Config>(validator: &T::AccountId) -> bool {
	let score = CoherenceScores::<T>::get(validator);
	let min_score = T::MinimumCoherenceScore::get();
	
	score >= min_score
}

/// Calculate block weight based on coherence
pub fn calculate_block_weight<T: Config>(validator: &T::AccountId) -> u32 {
	let score = CoherenceScores::<T>::get(validator);
	let network_state = NetworkHarmonicState::<T>::get();
	
	// Weight = coherence score * network coherence level
	score.saturating_mul(network_state.coherence_level as u32) / 100
}

/// Verify consensus data in a block
pub fn verify_consensus_data<T: Config>(
	data: &CoherenceConsensusData,
	expected_validator: &T::AccountId,
) -> bool {
	// Decode validator account
	if let Ok(validator) = T::AccountId::decode(&mut &data.primary_validator[..]) {
		// Check if it matches expected
		if &validator != expected_validator {
			return false;
		}
		
		// Check coherence score
		let actual_score = CoherenceScores::<T>::get(&validator);
		if actual_score != data.coherence_score {
			return false;
		}
		
		// Verify harmonic state matches
		let network_state = NetworkHarmonicState::<T>::get();
		if network_state != data.harmonic_state {
			return false;
		}
		
		true
	} else {
		false
	}
}

/// Consensus hooks for Proof of Coherence
pub trait CoherenceConsensusHooks<T: Config> {
	/// Called when a validator achieves resonance
	fn on_resonance_achieved(validator: &T::AccountId, level: u8);
	
	/// Called when network phase transition occurs
	fn on_phase_transition(old_state: &crate::types::HarmonicState, new_state: &crate::types::HarmonicState);
	
	/// Called when coherence is lost
	fn on_coherence_lost(validator: &T::AccountId);
}

/// Default implementation of consensus hooks
pub struct DefaultCoherenceHooks;

impl<T: Config> CoherenceConsensusHooks<T> for DefaultCoherenceHooks {
	fn on_resonance_achieved(_validator: &T::AccountId, _level: u8) {
		// Default: no action
	}
	
	fn on_phase_transition(_old_state: &crate::types::HarmonicState, _new_state: &crate::types::HarmonicState) {
		// Default: no action
	}
	
	fn on_coherence_lost(_validator: &T::AccountId) {
		// Default: no action
	}
}