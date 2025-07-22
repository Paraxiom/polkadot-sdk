// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Types for the Proof of Coherence consensus mechanism.

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_core::H256;
use serde::{Serialize, Deserialize};

/// A proof of quantum coherence submitted by a validator
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub struct CoherenceProof<BlockNumber> {
	/// Measured frequency in Hz
	pub frequency: u32,
	/// Phase measurement in degrees (0-359)
	pub phase: u32,
	/// Spectral purity percentage (0-100)
	pub spectral_purity: u8,
	/// Quantum fidelity percentage (0-100)
	pub quantum_fidelity: u8,
	/// Block number when measured
	pub timestamp: BlockNumber,
	/// Merkle root of measurement data
	pub merkle_root: H256,
}

/// Harmonic state of the network
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, Default, MaxEncodedLen, Serialize, Deserialize)]
pub struct HarmonicState {
	/// Fundamental frequency of network oscillation
	pub fundamental_frequency: u32,
	/// Phase offset from reference
	pub phase_offset: u32,
	/// Overall coherence level (0-100)
	pub coherence_level: u8,
	/// Number of resonance nodes active
	pub resonance_nodes: u8,
}

/// Position in the Tonnetz lattice
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, Default, MaxEncodedLen)]
pub struct TonnetzPosition {
	/// X coordinate (pitch axis)
	pub x: i8,
	/// Y coordinate (fifth axis)
	pub y: i8,
	/// Z coordinate (major third axis)
	pub z: i8,
	/// Pitch class (0-11)
	pub pitch_class: u8,
}

/// Phase synchronization data
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, MaxEncodedLen)]
pub struct PhaseData<BlockNumber> {
	/// Current phase in degrees
	pub phase: u32,
	/// Operating frequency
	pub frequency: u32,
	/// Signal amplitude (0-100)
	pub amplitude: u8,
	/// Last synchronization block
	pub last_sync: BlockNumber,
}

/// Tonnetz transformation types (PLR operations)
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, MaxEncodedLen)]
pub enum TonnetzTransform {
	/// Parallel transformation (minor to major)
	Parallel,
	/// Leading-tone transformation
	LeadingTone,
	/// Relative transformation (major to relative minor)
	Relative,
}

/// Phase transition types
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, MaxEncodedLen)]
pub enum TransitionType {
	/// Constructive interference
	Constructive,
	/// Destructive interference
	Destructive,
	/// Neutral transition
	Neutral,
}

/// Validator coherence status
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub enum CoherenceStatus {
	/// Maintaining strong coherence
	Coherent,
	/// Coherence degrading
	Degrading,
	/// Lost coherence
	Decoherent,
	/// In superposition (special state)
	Superposition,
}

/// Harmonic resonance level
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub struct ResonanceLevel {
	/// Harmonic number (1st, 2nd, 3rd, etc.)
	pub harmonic: u8,
	/// Resonance strength (0-100)
	pub strength: u8,
	/// Phase coupling factor
	pub coupling: u8,
}

/// Quantum measurement result
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub struct QuantumMeasurement {
	/// Observable type
	pub observable: Observable,
	/// Measurement value
	pub value: i32,
	/// Measurement uncertainty
	pub uncertainty: u32,
	/// Quantum state fidelity
	pub fidelity: u8,
}

/// Quantum observables that can be measured
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub enum Observable {
	/// Position observable
	Position,
	/// Momentum observable
	Momentum,
	/// Energy observable
	Energy,
	/// Spin observable
	Spin,
	/// Custom harmonic observable
	Harmonic(u8),
}

/// Network consensus mode
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq)]
pub enum ConsensusMode {
	/// Normal coherence-based consensus
	Coherence,
	/// Emergency classical consensus
	Classical,
	/// Hybrid quantum-classical
	Hybrid,
	/// Experimental superposition consensus
	Superposition,
}

/// Validator performance metrics
#[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, Default)]
pub struct ValidatorMetrics {
	/// Total coherence maintained (cumulative)
	pub total_coherence: u64,
	/// Number of successful measurements
	pub successful_measurements: u32,
	/// Number of failed measurements
	pub failed_measurements: u32,
	/// Longest coherence streak
	pub longest_streak: u32,
	/// Current streak
	pub current_streak: u32,
}