// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Coherence verification logic for the Proof of Coherence consensus.
//!
//! This module implements the quantum coherence verification algorithms
//! that validators must pass to participate in consensus.

use crate::types::{CoherenceProof, HarmonicState, PhaseData, QuantumMeasurement, Observable};
use sp_std::{vec::Vec, cmp::min};
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use num_complex::Complex32;

/// Coherence verifier for quantum measurements
#[derive(Clone, Encode, Decode, TypeInfo, Debug)]
pub struct CoherenceVerifier {
	/// Minimum coherence threshold
	pub min_coherence: u8,
	/// Maximum phase deviation allowed
	pub max_phase_deviation: u32,
	/// Frequency tolerance in Hz
	pub frequency_tolerance: u32,
}

impl Default for CoherenceVerifier {
	fn default() -> Self {
		Self {
			min_coherence: 80,
			max_phase_deviation: 30,
			frequency_tolerance: 50,
		}
	}
}

impl CoherenceVerifier {
	/// Verify a coherence proof against expected parameters
	pub fn verify_proof<BlockNumber>(
		&self,
		proof: &CoherenceProof<BlockNumber>,
		expected_state: &HarmonicState,
	) -> Result<u32, &'static str> {
		// Check spectral purity
		if proof.spectral_purity < self.min_coherence {
			return Err("Spectral purity below threshold");
		}
		
		// Check quantum fidelity
		if proof.quantum_fidelity < self.min_coherence {
			return Err("Quantum fidelity below threshold");
		}
		
		// Check frequency deviation
		let freq_diff = (proof.frequency as i32 - expected_state.fundamental_frequency as i32).abs() as u32;
		if freq_diff > self.frequency_tolerance {
			return Err("Frequency deviation too high");
		}
		
		// Check phase alignment
		let phase_diff = Self::phase_difference(proof.phase, expected_state.phase_offset);
		if phase_diff > self.max_phase_deviation {
			return Err("Phase deviation too high");
		}
		
		// Calculate overall coherence score
		let score = self.calculate_coherence_score(proof, expected_state, phase_diff, freq_diff);
		
		Ok(score)
	}
	
	/// Calculate phase difference accounting for wrap-around
	fn phase_difference(phase1: u32, phase2: u32) -> u32 {
		let diff = (phase1 as i32 - phase2 as i32).abs() as u32;
		min(diff, 360 - diff)
	}
	
	/// Calculate coherence score from measurements
	fn calculate_coherence_score<BlockNumber>(
		&self,
		proof: &CoherenceProof<BlockNumber>,
		expected_state: &HarmonicState,
		phase_diff: u32,
		freq_diff: u32,
	) -> u32 {
		// Weight factors for different components
		const SPECTRAL_WEIGHT: u32 = 30;
		const FIDELITY_WEIGHT: u32 = 30;
		const PHASE_WEIGHT: u32 = 20;
		const FREQUENCY_WEIGHT: u32 = 20;
		
		// Calculate component scores
		let spectral_score = (proof.spectral_purity as u32 * SPECTRAL_WEIGHT) / 100;
		let fidelity_score = (proof.quantum_fidelity as u32 * FIDELITY_WEIGHT) / 100;
		
		// Phase score (inverse of deviation)
		let phase_score = if phase_diff == 0 {
			PHASE_WEIGHT
		} else {
			PHASE_WEIGHT.saturating_sub(phase_diff * PHASE_WEIGHT / self.max_phase_deviation)
		};
		
		// Frequency score (inverse of deviation)
		let freq_score = if freq_diff == 0 {
			FREQUENCY_WEIGHT
		} else {
			FREQUENCY_WEIGHT.saturating_sub(freq_diff * FREQUENCY_WEIGHT / self.frequency_tolerance)
		};
		
		spectral_score + fidelity_score + phase_score + freq_score
	}
	
	/// Verify phase synchronization between validators
	pub fn verify_phase_sync(
		&self,
		phase_data: &[PhaseData],
		network_state: &HarmonicState,
	) -> bool {
		if phase_data.is_empty() {
			return false;
		}
		
		// Calculate average phase
		let mut phase_sum = 0u32;
		let mut freq_sum = 0u32;
		
		for data in phase_data {
			phase_sum += data.phase;
			freq_sum += data.frequency;
		}
		
		let avg_phase = phase_sum / phase_data.len() as u32;
		let avg_freq = freq_sum / phase_data.len() as u32;
		
		// Check if average is close to network state
		let phase_diff = Self::phase_difference(avg_phase, network_state.phase_offset);
		let freq_diff = (avg_freq as i32 - network_state.fundamental_frequency as i32).abs() as u32;
		
		phase_diff <= self.max_phase_deviation && freq_diff <= self.frequency_tolerance
	}
	
	/// Calculate quantum state fidelity
	pub fn calculate_fidelity(measured: &QuantumMeasurement, expected: &QuantumMeasurement) -> u8 {
		// Simple fidelity calculation
		let value_diff = (measured.value - expected.value).abs() as u32;
		let total_uncertainty = measured.uncertainty + expected.uncertainty;
		
		if total_uncertainty == 0 {
			if value_diff == 0 { 100 } else { 0 }
		} else {
			let fidelity = 100u32.saturating_sub(value_diff * 100 / total_uncertainty);
			fidelity.min(100) as u8
		}
	}
	
	/// Verify quantum measurement validity
	pub fn verify_measurement(measurement: &QuantumMeasurement) -> bool {
		// Check uncertainty principle compliance
		match measurement.observable {
			Observable::Position | Observable::Momentum => {
				// Heisenberg uncertainty principle check
				measurement.uncertainty > 0
			},
			Observable::Energy => {
				// Energy measurements should have reasonable bounds
				measurement.value >= 0 && measurement.value < 1_000_000
			},
			Observable::Spin => {
				// Spin should be quantized
				measurement.value == -1 || measurement.value == 0 || measurement.value == 1
			},
			Observable::Harmonic(n) => {
				// Harmonic measurements should be positive
				measurement.value >= 0 && n > 0 && n <= 12
			},
		}
	}
	
	/// Calculate interference pattern between validators
	pub fn calculate_interference(
		phase1: u32,
		phase2: u32,
		amplitude1: u8,
		amplitude2: u8,
	) -> (u8, bool) {
		// Convert to radians
		let phi1 = (phase1 as f32) * core::f32::consts::PI / 180.0;
		let phi2 = (phase2 as f32) * core::f32::consts::PI / 180.0;
		
		// Calculate complex amplitudes using from_polar
		let a1 = Complex32::from_polar(amplitude1 as f32, phi1);
		let a2 = Complex32::from_polar(amplitude2 as f32, phi2);
		
		// Superposition
		let result = a1 + a2;
		let magnitude = result.norm();
		
		// Determine if constructive or destructive
		let constructive = magnitude > (amplitude1 as f32 + amplitude2 as f32) / 2.0;
		
		(magnitude.min(100.0) as u8, constructive)
	}
	
	/// Check if validators are in quantum entanglement
	pub fn check_entanglement(
		measurements1: &[QuantumMeasurement],
		measurements2: &[QuantumMeasurement],
	) -> bool {
		if measurements1.len() != measurements2.len() {
			return false;
		}
		
		// Check correlation between measurements
		let mut correlations = 0;
		for (m1, m2) in measurements1.iter().zip(measurements2.iter()) {
			if m1.observable == m2.observable {
				// Anti-correlation for entangled states
				if m1.value == -m2.value {
					correlations += 1;
				}
			}
		}
		
		// Strong correlation indicates entanglement
		correlations > measurements1.len() / 2
	}
	
	/// Calculate decoherence rate from historical data
	pub fn calculate_decoherence_rate(
		coherence_history: &[u8],
		time_intervals: &[u32],
	) -> u32 {
		if coherence_history.len() < 2 || time_intervals.is_empty() {
			return 0;
		}
		
		let mut total_rate = 0u32;
		for i in 1..coherence_history.len().min(time_intervals.len() + 1) {
			let coherence_drop = coherence_history[i-1].saturating_sub(coherence_history[i]) as u32;
			let time_interval = time_intervals.get(i-1).copied().unwrap_or(1);
			
			// Rate = coherence drop per time unit
			let rate = coherence_drop * 1000 / time_interval.max(1);
			total_rate += rate;
		}
		
		// Average rate
		total_rate / (coherence_history.len() - 1) as u32
	}
}

/// Helper functions for wave function calculations
pub mod wave_functions {
	use super::*;
	
	/// Calculate wave function collapse probability
	pub fn collapse_probability(coherence: u8, measurement_strength: u8) -> u8 {
		// Stronger measurement = higher collapse probability
		// Higher coherence = lower collapse probability
		let base_probability = measurement_strength.saturating_sub(coherence / 2);
		base_probability.min(100)
	}
	
	/// Calculate superposition state amplitude
	pub fn superposition_amplitude(states: &[(u8, u32)]) -> u8 {
		if states.is_empty() {
			return 0;
		}
		
		let mut total_amplitude = 0f32;
		for (amplitude, phase) in states {
			let phi = (*phase as f32) * core::f32::consts::PI / 180.0;
			let complex = Complex32::from_polar(*amplitude as f32, phi);
			total_amplitude += complex.norm();
		}
		
		(total_amplitude / states.len() as f32).min(100.0) as u8
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_phase_difference() {
		assert_eq!(CoherenceVerifier::phase_difference(10, 20), 10);
		assert_eq!(CoherenceVerifier::phase_difference(350, 10), 20);
		assert_eq!(CoherenceVerifier::phase_difference(180, 0), 180);
	}
	
	#[test]
	fn test_interference_calculation() {
		let verifier = CoherenceVerifier::default();
		
		// Constructive interference (same phase)
		let (magnitude, constructive) = verifier.calculate_interference(0, 0, 50, 50);
		assert!(constructive);
		assert_eq!(magnitude, 100);
		
		// Destructive interference (opposite phase)
		let (magnitude, constructive) = verifier.calculate_interference(0, 180, 50, 50);
		assert!(!constructive);
		assert_eq!(magnitude, 0);
	}
}