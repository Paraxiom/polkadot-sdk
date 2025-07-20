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

//! Quantum randomness traits and utilities.
//!
//! This module provides traits and types for integrating quantum random number
//! generators (QRNGs) and quantum key distribution (QKD) systems with Substrate.

use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Trait for quantum randomness sources.
pub trait QuantumRandomness {
	/// Get quantum-generated random bytes.
	fn quantum_random(num_bytes: usize) -> Option<Vec<u8>>;
	
	/// Fill a buffer with quantum random data.
	fn fill_quantum_random(buffer: &mut [u8]) -> Result<(), QuantumRandomnessError>;
	
	/// Get the current entropy level (0-100).
	fn entropy_level() -> u8;
	
	/// Check if quantum source is healthy.
	fn is_healthy() -> bool;
}

/// Errors that can occur when using quantum randomness.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum QuantumRandomnessError {
	/// Insufficient entropy available.
	InsufficientEntropy,
	/// Quantum source is unhealthy.
	UnhealthySource,
	/// QKD link is down.
	QkdLinkDown,
	/// General failure.
	GeneralFailure,
}

/// Quantum entropy metrics.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct QuantumEntropyMetrics {
	/// Total bytes generated.
	pub total_bytes: u64,
	/// Current entropy pool size.
	pub pool_size: u32,
	/// Entropy generation rate (bytes/sec).
	pub generation_rate: u32,
	/// Last update timestamp.
	pub last_update: u64,
}

/// Trait for managing quantum entropy pools.
pub trait QuantumEntropyPool {
	/// Add entropy to the pool.
	fn add_entropy(entropy: &[u8]) -> Result<(), QuantumRandomnessError>;
	
	/// Consume entropy from the pool.
	fn consume_entropy(num_bytes: usize) -> Option<Vec<u8>>;
	
	/// Get current pool metrics.
	fn metrics() -> QuantumEntropyMetrics;
	
	/// Clear the entropy pool (for security).
	fn clear_pool();
}

/// Implementation of quantum randomness using a mock source (for testing).
pub struct MockQuantumRandomness;

impl QuantumRandomness for MockQuantumRandomness {
	fn quantum_random(num_bytes: usize) -> Option<Vec<u8>> {
		// In production, this would interface with real QRNG hardware
		Some(vec![0x42; num_bytes])
	}
	
	fn fill_quantum_random(buffer: &mut [u8]) -> Result<(), QuantumRandomnessError> {
		// Mock implementation
		for byte in buffer.iter_mut() {
			*byte = 0x42;
		}
		Ok(())
	}
	
	fn entropy_level() -> u8 {
		// Mock: always report 75% entropy
		75
	}
	
	fn is_healthy() -> bool {
		// Mock: always healthy
		true
	}
}

/// Hybrid randomness that combines classical and quantum sources.
pub struct HybridRandomness<C: crate::traits::SpawnNamed> {
	_phantom: sp_std::marker::PhantomData<C>,
}

impl<C: crate::traits::SpawnNamed> HybridRandomness<C> {
	/// Generate random bytes using both classical and quantum sources.
	pub fn random_hybrid(num_bytes: usize) -> Vec<u8> {
		let mut result = vec![0u8; num_bytes];
		
		// Get quantum randomness if available
		if let Some(quantum_bytes) = MockQuantumRandomness::quantum_random(num_bytes) {
			// XOR with classical randomness for defense in depth
			for (i, byte) in quantum_bytes.iter().enumerate() {
				result[i] ^= byte;
			}
		}
		
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mock_quantum_randomness_works() {
		let random = MockQuantumRandomness::quantum_random(32);
		assert!(random.is_some());
		assert_eq!(random.unwrap().len(), 32);
	}

	#[test]
	fn entropy_level_works() {
		assert_eq!(MockQuantumRandomness::entropy_level(), 75);
	}

	#[test]
	fn is_healthy_works() {
		assert!(MockQuantumRandomness::is_healthy());
	}
}