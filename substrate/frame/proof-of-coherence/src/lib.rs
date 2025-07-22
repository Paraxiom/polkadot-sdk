// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Proof of Coherence Pallet
//!
//! ## Overview
//!
//! The Proof of Coherence (PoC) pallet implements a novel quantum consensus mechanism
//! based on harmonic resonance and quantum coherence. Validators prove their ability
//! to maintain quantum coherence in harmonic systems, creating an energy-efficient
//! and naturally decentralized consensus algorithm.
//!
//! ## Consensus Mechanism
//!
//! Validators must demonstrate:
//! 1. Quantum coherence maintenance over time
//! 2. Harmonic resonance at specific frequencies
//! 3. Spectral purity above threshold levels
//! 4. Phase coherence with network oscillations
//!
//! The consensus uses the Tonnetz lattice mathematical framework to model
//! quantum states as musical harmonies, enabling efficient verification of coherence.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod coherence;
pub mod tonnetz;
pub mod types;
pub mod consensus;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

#[cfg(test)]
mod tests;

pub use coherence::CoherenceVerifier;
pub use tonnetz::TonnetzLattice;
pub use types::*;
pub use consensus::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use frame_support::traits::Currency;
	use sp_runtime::traits::{Zero, Saturating};
	use sp_std::{vec::Vec, collections::btree_map::BTreeMap};
	use sp_core::{H256, quantum_randomness::QuantumRandomness};
	
	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);
	
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_quantum_crypto::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		
		/// The staking balance type
		type Currency: frame_support::traits::Currency<Self::AccountId>;
		
		/// Minimum coherence score required for validation
		#[pallet::constant]
		type MinimumCoherenceScore: Get<u32>;
		
		/// Maximum validators in the active set
		#[pallet::constant]
		type MaxValidators: Get<u32>;
		
		/// Coherence measurement period in blocks
		#[pallet::constant]
		type CoherencePeriod: Get<BlockNumberFor<Self>>;
		
		/// Reward amount for maintaining coherence
		#[pallet::constant]
		type CoherenceReward: Get<BalanceOf<Self>>;
		
		/// Slash amount for losing coherence
		#[pallet::constant]
		type CoherenceSlash: Get<BalanceOf<Self>>;
	}
	
	pub type BalanceOf<T> = <<T as Config>::Currency as frame_support::traits::Currency<<T as frame_system::Config>::AccountId>>::Balance;
	
	/// Active validators maintaining coherence
	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;
	
	/// Coherence proofs submitted by validators
	#[pallet::storage]
	pub type CoherenceProofs<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		CoherenceProof<BlockNumberFor<T>>,
		OptionQuery,
	>;
	
	/// Harmonic state of the network
	#[pallet::storage]
	#[pallet::getter(fn network_harmonic_state)]
	pub type NetworkHarmonicState<T> = StorageValue<_, HarmonicState, ValueQuery>;
	
	/// Tonnetz lattice positions for validators
	#[pallet::storage]
	#[pallet::getter(fn tonnetz_positions)]
	pub type TonnetzPositions<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		TonnetzPosition,
		OptionQuery,
	>;
	
	/// Coherence scores for validators
	#[pallet::storage]
	#[pallet::getter(fn coherence_scores)]
	pub type CoherenceScores<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		u32,
		ValueQuery,
	>;
	
	/// Last coherence check block
	#[pallet::storage]
	#[pallet::getter(fn last_coherence_check)]
	pub type LastCoherenceCheck<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;
	
	/// Phase synchronization data
	#[pallet::storage]
	#[pallet::getter(fn phase_sync_data)]
	pub type PhaseSyncData<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		PhaseData<BlockNumberFor<T>>,
		OptionQuery,
	>;
	
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Validator registered for coherence consensus
		ValidatorRegistered {
			who: T::AccountId,
			tonnetz_x: i8,
			tonnetz_y: i8,
			tonnetz_z: i8,
			pitch_class: u8,
		},
		
		/// Coherence proof submitted
		CoherenceProofSubmitted {
			validator: T::AccountId,
			score: u32,
			frequency: u32,
		},
		
		/// Validator achieved harmonic resonance
		HarmonicResonanceAchieved {
			validator: T::AccountId,
			harmonic_level: u8,
		},
		
		/// Network harmonic state updated
		NetworkHarmonicUpdated {
			fundamental_frequency: u32,
			phase_offset: u32,
			coherence_level: u8,
			resonance_nodes: u8,
			participating_validators: u32,
		},
		
		/// Validator lost coherence and was slashed
		CoherenceLost {
			validator: T::AccountId,
			last_score: u32,
		},
		
		/// Phase transition in network harmonics
		PhaseTransition {
			from_coherence_level: u8,
			to_coherence_level: u8,
			transition_constructive: bool,
		},
		
		/// Coherence reward distributed
		CoherenceRewardDistributed {
			validator: T::AccountId,
			amount: BalanceOf<T>,
		},
	}
	
	#[pallet::error]
	pub enum Error<T> {
		/// Already registered as validator
		AlreadyValidator,
		/// Not a registered validator
		NotValidator,
		/// Invalid coherence proof
		InvalidCoherenceProof,
		/// Coherence score too low
		InsufficientCoherence,
		/// Too many validators
		ValidatorLimitReached,
		/// Invalid Tonnetz position
		InvalidTonnetzPosition,
		/// Phase synchronization failed
		PhaseSyncFailed,
		/// Harmonic measurement failed
		HarmonicMeasurementFailed,
		/// Quantum entropy unavailable
		QuantumEntropyUnavailable,
	}
	
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register as a validator in the Proof of Coherence consensus
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(50_000, 0))]
		pub fn register_validator(
			origin: OriginFor<T>,
			initial_frequency: u32,
			phase: u32,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			
			// Check if already registered
			let mut validators = Validators::<T>::get();
			ensure!(!validators.contains(&who), Error::<T>::AlreadyValidator);
			ensure!(validators.len() < T::MaxValidators::get() as usize, Error::<T>::ValidatorLimitReached);
			
			// Generate Tonnetz position using quantum randomness
			let tonnetz_position = Self::generate_tonnetz_position(initial_frequency, phase)?;
			
			// Add to validators
			validators.try_push(who.clone())
				.map_err(|_| Error::<T>::ValidatorLimitReached)?;
			Validators::<T>::put(validators);
			
			// Initialize positions and scores
			TonnetzPositions::<T>::insert(&who, &tonnetz_position);
			CoherenceScores::<T>::insert(&who, 100); // Start with base score
			
			// Initialize phase data
			let phase_data = PhaseData {
				phase: phase % 360,
				frequency: initial_frequency,
				amplitude: 100,
				last_sync: frame_system::Pallet::<T>::block_number(),
			};
			PhaseSyncData::<T>::insert(&who, phase_data);
			
			Self::deposit_event(Event::ValidatorRegistered {
				who,
				tonnetz_x: tonnetz_position.x,
				tonnetz_y: tonnetz_position.y,
				tonnetz_z: tonnetz_position.z,
				pitch_class: tonnetz_position.pitch_class,
			});
			
			Ok(())
		}
		
		/// Submit a coherence proof
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(100_000, 0))]
		pub fn submit_coherence_proof(
			origin: OriginFor<T>,
			frequency_measurement: u32,
			phase_measurement: u32,
			spectral_purity: u8,
			quantum_fidelity: u8,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			
			// Verify validator
			let validators = Validators::<T>::get();
			ensure!(validators.contains(&who), Error::<T>::NotValidator);
			
			// Create coherence proof
			let proof = CoherenceProof {
				frequency: frequency_measurement,
				phase: phase_measurement,
				spectral_purity,
				quantum_fidelity,
				timestamp: frame_system::Pallet::<T>::block_number(),
				merkle_root: Self::calculate_proof_hash(&who, frequency_measurement, phase_measurement),
			};
			
			// Verify proof validity
			let score = Self::verify_coherence(&who, &proof)?;
			ensure!(score >= T::MinimumCoherenceScore::get(), Error::<T>::InsufficientCoherence);
			
			// Update storage
			CoherenceProofs::<T>::insert(&who, &proof);
			CoherenceScores::<T>::insert(&who, score);
			
			// Update phase sync data
			if let Some(mut phase_data) = PhaseSyncData::<T>::get(&who) {
				phase_data.phase = phase_measurement;
				phase_data.frequency = frequency_measurement;
				phase_data.last_sync = frame_system::Pallet::<T>::block_number();
				PhaseSyncData::<T>::insert(&who, phase_data);
			}
			
			Self::deposit_event(Event::CoherenceProofSubmitted {
				validator: who,
				score,
				frequency: frequency_measurement,
			});
			
			Ok(())
		}
		
		/// Perform a harmonic transformation on validator's Tonnetz position
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::from_parts(30_000, 0))]
		pub fn harmonic_transform(
			origin: OriginFor<T>,
			transform_type: u8, // 0 = Parallel, 1 = LeadingTone, 2 = Relative
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			
			// Get current position
			let mut position = TonnetzPositions::<T>::get(&who)
				.ok_or(Error::<T>::NotValidator)?;
			
			// Convert u8 to enum
			let transform = match transform_type {
				0 => TonnetzTransform::Parallel,
				1 => TonnetzTransform::LeadingTone,
				2 => TonnetzTransform::Relative,
				_ => return Err(Error::<T>::InvalidTonnetzPosition.into()),
			};
			
			// Apply transformation
			position = Self::apply_tonnetz_transform(position, transform);
			
			// Verify new position is valid
			ensure!(Self::is_valid_tonnetz_position(&position), Error::<T>::InvalidTonnetzPosition);
			
			// Update position
			TonnetzPositions::<T>::insert(&who, position.clone());
			
			// Check for harmonic resonance
			if let Some(harmonic_level) = Self::check_harmonic_resonance(&who, &position) {
				Self::deposit_event(Event::HarmonicResonanceAchieved {
					validator: who,
					harmonic_level,
				});
			}
			
			Ok(())
		}
		
		/// Update network harmonic state (called by block production)
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::from_parts(200_000, 0))]
		pub fn update_network_harmonics(origin: OriginFor<T>) -> DispatchResult {
			ensure_root(origin)?;
			
			let current_block = frame_system::Pallet::<T>::block_number();
			let last_check = LastCoherenceCheck::<T>::get();
			
			// Only update every coherence period
			if current_block.saturating_sub(last_check) < T::CoherencePeriod::get() {
				return Ok(());
			}
			
			// Calculate network harmonic state
			let validators = Validators::<T>::get();
			let mut total_coherence = 0u32;
			let mut participating = 0u32;
			let mut phase_sum = 0u32;
			let mut frequency_sum = 0u32;
			
			for validator in validators.iter() {
				if let Some(score) = CoherenceScores::<T>::get(validator).into() {
					if score > 0 {
						total_coherence = total_coherence.saturating_add(score);
						participating = participating.saturating_add(1);
						
						if let Some(phase_data) = PhaseSyncData::<T>::get(validator) {
							phase_sum = phase_sum.saturating_add(phase_data.phase);
							frequency_sum = frequency_sum.saturating_add(phase_data.frequency);
						}
					}
				}
			}
			
			// Calculate new harmonic state
			let new_state = if participating > 0 {
				HarmonicState {
					fundamental_frequency: frequency_sum / participating,
					phase_offset: phase_sum / participating,
					coherence_level: (total_coherence / participating) as u8,
					resonance_nodes: participating as u8,
				}
			} else {
				HarmonicState::default()
			};
			
			// Check for phase transition
			let old_state = NetworkHarmonicState::<T>::get();
			if Self::detect_phase_transition(&old_state, &new_state) {
				let transition_type = Self::classify_transition(&old_state, &new_state);
				Self::deposit_event(Event::PhaseTransition {
					from_coherence_level: old_state.coherence_level,
					to_coherence_level: new_state.coherence_level,
					transition_constructive: matches!(transition_type, TransitionType::Constructive),
				});
			}
			
			// Update state
			NetworkHarmonicState::<T>::put(&new_state);
			LastCoherenceCheck::<T>::put(current_block);
			
			Self::deposit_event(Event::NetworkHarmonicUpdated {
				fundamental_frequency: new_state.fundamental_frequency,
				phase_offset: new_state.phase_offset,
				coherence_level: new_state.coherence_level,
				resonance_nodes: new_state.resonance_nodes,
				participating_validators: participating,
			});
			
			// Distribute rewards/penalties
			Self::process_coherence_rewards()?;
			
			Ok(())
		}
		
		/// Emergency phase reset (governance only)
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::from_parts(100_000, 0))]
		pub fn emergency_phase_reset(origin: OriginFor<T>) -> DispatchResult {
			ensure_root(origin)?;
			
			// Reset network harmonic state
			NetworkHarmonicState::<T>::put(HarmonicState::default());
			
			// Reset all validator positions to origin
			let validators = Validators::<T>::get();
			for validator in validators.iter() {
				TonnetzPositions::<T>::insert(validator, TonnetzPosition::default());
				CoherenceScores::<T>::insert(validator, 100);
			}
			
			Ok(())
		}
	}
	
	// Helper functions
	impl<T: Config> Pallet<T> {
		/// Generate a Tonnetz position using quantum randomness
		fn generate_tonnetz_position(frequency: u32, phase: u32) -> Result<TonnetzPosition, Error<T>> {
			// Get quantum randomness for position
			let entropy = pallet_quantum_crypto::Pallet::<T>::quantum_random(12)
				.ok_or(Error::<T>::QuantumEntropyUnavailable)?;
			
			// Convert frequency and phase to Tonnetz coordinates
			let x = (frequency % 12) as i8;
			let y = (phase % 7) as i8;
			let z = (entropy[0] % 3) as i8;
			
			Ok(TonnetzPosition {
				x,
				y,
				z,
				pitch_class: (frequency % 12) as u8,
			})
		}
		
		/// Verify coherence proof and calculate score
		fn verify_coherence(
			validator: &T::AccountId,
			proof: &CoherenceProof<BlockNumberFor<T>>,
		) -> Result<u32, Error<T>> {
			// Get validator's expected position
			let position = TonnetzPositions::<T>::get(validator)
				.ok_or(Error::<T>::NotValidator)?;
			
			// Get network harmonic state
			let network_state = NetworkHarmonicState::<T>::get();
			
			// Calculate coherence score based on:
			// 1. Spectral purity (25%)
			// 2. Quantum fidelity (25%)
			// 3. Phase alignment with network (25%)
			// 4. Frequency stability (25%)
			
			let spectral_score = proof.spectral_purity as u32 * 25 / 100;
			let fidelity_score = proof.quantum_fidelity as u32 * 25 / 100;
			
			// Phase alignment score
			let phase_diff = (network_state.phase_offset as i32 - proof.phase as i32).abs() as u32;
			let phase_score = if phase_diff < 10 { 25 } else { 25_u32.saturating_sub(phase_diff / 10) };
			
			// Frequency stability score
			let freq_diff = (network_state.fundamental_frequency as i32 - proof.frequency as i32).abs() as u32;
			let freq_score = if freq_diff < 50 { 25 } else { 25_u32.saturating_sub(freq_diff / 50) };
			
			let total_score = spectral_score + fidelity_score + phase_score + freq_score;
			
			Ok(total_score)
		}
		
		/// Apply Tonnetz transformation
		fn apply_tonnetz_transform(
			position: TonnetzPosition,
			transform: TonnetzTransform,
		) -> TonnetzPosition {
			match transform {
				TonnetzTransform::Parallel => TonnetzPosition {
					x: position.x,
					y: position.y.wrapping_add(1),
					z: position.z,
					pitch_class: (position.pitch_class + 3) % 12,
				},
				TonnetzTransform::LeadingTone => TonnetzPosition {
					x: position.x.wrapping_add(1),
					y: position.y,
					z: position.z,
					pitch_class: (position.pitch_class + 1) % 12,
				},
				TonnetzTransform::Relative => TonnetzPosition {
					x: position.x,
					y: position.y,
					z: position.z.wrapping_add(1),
					pitch_class: (position.pitch_class + 4) % 12,
				},
			}
		}
		
		/// Check if Tonnetz position is valid
		fn is_valid_tonnetz_position(position: &TonnetzPosition) -> bool {
			// Ensure position is within valid bounds
			position.x.abs() <= 6 && position.y.abs() <= 4 && position.z.abs() <= 2
		}
		
		/// Check for harmonic resonance
		fn check_harmonic_resonance(
			validator: &T::AccountId,
			position: &TonnetzPosition,
		) -> Option<u8> {
			// Check if validator is at a harmonic node
			let network_state = NetworkHarmonicState::<T>::get();
			
			// Simple resonance check - real implementation would be more complex
			if position.pitch_class % 3 == 0 && network_state.coherence_level > 80 {
				Some((position.pitch_class / 3) + 1)
			} else {
				None
			}
		}
		
		/// Detect phase transitions in network state
		fn detect_phase_transition(old: &HarmonicState, new: &HarmonicState) -> bool {
			// Significant change in coherence level
			let coherence_change = (old.coherence_level as i32 - new.coherence_level as i32).abs();
			
			// Frequency shift
			let freq_change = (old.fundamental_frequency as i32 - new.fundamental_frequency as i32).abs();
			
			coherence_change > 20 || freq_change > 100
		}
		
		/// Classify the type of phase transition
		fn classify_transition(old: &HarmonicState, new: &HarmonicState) -> TransitionType {
			if new.coherence_level > old.coherence_level {
				TransitionType::Constructive
			} else if new.coherence_level < old.coherence_level {
				TransitionType::Destructive
			} else {
				TransitionType::Neutral
			}
		}
		
		/// Process coherence rewards and penalties
		fn process_coherence_rewards() -> Result<(), Error<T>> {
			let validators = Validators::<T>::get();
			let min_score = T::MinimumCoherenceScore::get();
			
			for validator in validators.iter() {
				let score = CoherenceScores::<T>::get(validator);
				
				if score >= min_score {
					// Reward for maintaining coherence
					let reward = T::CoherenceReward::get();
					let _ = T::Currency::deposit_creating(validator, reward);
					
					Self::deposit_event(Event::CoherenceRewardDistributed {
						validator: validator.clone(),
						amount: reward,
					});
				} else if score < min_score / 2 {
					// Slash for losing coherence
					let slash = T::CoherenceSlash::get();
					let _ = T::Currency::slash(validator, slash);
					
					Self::deposit_event(Event::CoherenceLost {
						validator: validator.clone(),
						last_score: score,
					});
					
					// Remove from validators if score too low
					if score < min_score / 4 {
						Validators::<T>::mutate(|v| v.retain(|x| x != validator));
						TonnetzPositions::<T>::remove(validator);
						CoherenceScores::<T>::remove(validator);
						PhaseSyncData::<T>::remove(validator);
					}
				}
			}
			
			Ok(())
		}
		
		/// Calculate proof hash for verification
		fn calculate_proof_hash(
			validator: &T::AccountId,
			frequency: u32,
			phase: u32,
		) -> H256 {
			use sp_io::hashing::blake2_256;
			
			let mut data = validator.encode();
			data.extend_from_slice(&frequency.encode());
			data.extend_from_slice(&phase.encode());
			
			H256::from(blake2_256(&data))
		}
	}
	
	// Genesis config
	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::AccountId>,
		pub initial_harmonic_state: HarmonicState,
		#[serde(skip)]
		pub _config: sp_std::marker::PhantomData<T>,
	}
	
	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			// Initialize validators
			let bounded_validators: BoundedVec<_, _> = self.initial_validators
				.clone()
				.try_into()
				.expect("Too many initial validators");
			Validators::<T>::put(bounded_validators);
			
			// Set initial harmonic state
			NetworkHarmonicState::<T>::put(&self.initial_harmonic_state);
			
			// Initialize validator data
			for (i, validator) in self.initial_validators.iter().enumerate() {
				let position = TonnetzPosition {
					x: (i % 12) as i8,
					y: (i % 7) as i8,
					z: 0,
					pitch_class: (i % 12) as u8,
				};
				TonnetzPositions::<T>::insert(validator, position);
				CoherenceScores::<T>::insert(validator, 100);
			}
		}
	}
}