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

//! Post-quantum cryptography algorithm selection for different use cases.
//!
//! This module provides a unified interface for selecting between different
//! post-quantum algorithms based on operational requirements, particularly
//! for satellite communications where bandwidth constraints are critical.

use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Post-quantum algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum PostQuantumAlgorithm {
	/// Falcon-512: Lattice-based, small signatures (690 bytes)
	/// Best for bandwidth-constrained environments like satellites
	Falcon512,
	/// SPHINCS+: Hash-based, large signatures (17-49 KB)
	/// Most conservative security, best for critical operations
	SphincsPlus,
}

/// Operation type to guide algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum OperationType {
	/// Regular operations (message signing, authentication)
	Regular,
	/// Critical operations (root certificates, firmware updates)
	Critical,
	/// Emergency operations (key revocation, security incidents)
	Emergency,
	/// Bandwidth-constrained operations (satellite, IoT)
	BandwidthConstrained,
}

/// Configuration for post-quantum crypto selection
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct PostQuantumConfig {
	/// Default algorithm for regular operations
	pub default_algorithm: PostQuantumAlgorithm,
	/// Whether to allow automatic algorithm selection
	pub auto_select: bool,
	/// Maximum acceptable signature size in bytes
	pub max_signature_size: Option<u32>,
	/// Minimum security level required (in bits)
	pub min_security_level: u32,
}

impl Default for PostQuantumConfig {
	fn default() -> Self {
		Self {
			default_algorithm: PostQuantumAlgorithm::Falcon512,
			auto_select: true,
			max_signature_size: Some(1024), // 1KB default for satellite comms
			min_security_level: 128,
		}
	}
}

impl PostQuantumConfig {
	/// Create a configuration optimized for satellite communications
	pub fn satellite() -> Self {
		Self {
			default_algorithm: PostQuantumAlgorithm::Falcon512,
			auto_select: true,
			max_signature_size: Some(750), // Slightly above Falcon-512 size
			min_security_level: 128,
		}
	}

	/// Create a configuration for maximum security
	pub fn max_security() -> Self {
		Self {
			default_algorithm: PostQuantumAlgorithm::SphincsPlus,
			auto_select: false,
			max_signature_size: None,
			min_security_level: 256,
		}
	}

	/// Select the appropriate algorithm based on operation type
	pub fn select_algorithm(&self, operation: OperationType) -> PostQuantumAlgorithm {
		if !self.auto_select {
			return self.default_algorithm;
		}

		match operation {
			OperationType::Regular | OperationType::BandwidthConstrained => {
				// For regular and bandwidth-constrained ops, prefer Falcon-512
				if let Some(max_size) = self.max_signature_size {
					if max_size < 17000 {
						// SPHINCS+ won't fit
						PostQuantumAlgorithm::Falcon512
					} else {
						self.default_algorithm
					}
				} else {
					self.default_algorithm
				}
			},
			OperationType::Critical | OperationType::Emergency => {
				// For critical operations, prefer SPHINCS+ unless bandwidth-constrained
				if let Some(max_size) = self.max_signature_size {
					if max_size < 17000 {
						// Can't use SPHINCS+, fall back to Falcon
						PostQuantumAlgorithm::Falcon512
					} else {
						PostQuantumAlgorithm::SphincsPlus
					}
				} else {
					PostQuantumAlgorithm::SphincsPlus
				}
			},
		}
	}
}

/// Trait for post-quantum signatures
pub trait PostQuantumSignature {
	/// The algorithm used
	fn algorithm(&self) -> PostQuantumAlgorithm;
	
	/// Size of the signature in bytes
	fn size(&self) -> usize;
	
	/// Estimated transmission time at given bandwidth (bits per second)
	fn transmission_time_ms(&self, bandwidth_bps: u32) -> u32 {
		let bits = self.size() as u32 * 8;
		(bits * 1000) / bandwidth_bps
	}
}

/// Algorithm characteristics for decision making
pub struct AlgorithmInfo {
	pub algorithm: PostQuantumAlgorithm,
	pub signature_size: usize,
	pub public_key_size: usize,
	pub private_key_size: usize,
	pub security_level: u32,
	pub signing_ops_per_sec: u32,
	pub verification_ops_per_sec: u32,
}

impl PostQuantumAlgorithm {
	/// Get algorithm characteristics
	pub fn info(&self) -> AlgorithmInfo {
		match self {
			PostQuantumAlgorithm::Falcon512 => AlgorithmInfo {
				algorithm: *self,
				signature_size: 690,
				public_key_size: 897,
				private_key_size: 1281,
				security_level: 128,
				signing_ops_per_sec: 3125,
				verification_ops_per_sec: 15625,
			},
			PostQuantumAlgorithm::SphincsPlus => AlgorithmInfo {
				algorithm: *self,
				signature_size: 49856, // SPHINCS+-256f
				public_key_size: 64,
				private_key_size: 128,
				security_level: 256,
				signing_ops_per_sec: 50,
				verification_ops_per_sec: 500,
			},
		}
	}

	/// Check if suitable for given bandwidth constraint
	pub fn suitable_for_bandwidth(&self, bandwidth_bps: u32, max_latency_ms: u32) -> bool {
		let info = self.info();
		let transmission_time_ms = (info.signature_size as u32 * 8 * 1000) / bandwidth_bps;
		transmission_time_ms <= max_latency_ms
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_satellite_config() {
		let config = PostQuantumConfig::satellite();
		assert_eq!(config.default_algorithm, PostQuantumAlgorithm::Falcon512);
		assert_eq!(config.max_signature_size, Some(750));
	}

	#[test]
	fn test_algorithm_selection() {
		let config = PostQuantumConfig::satellite();
		
		// Regular ops should use Falcon-512
		assert_eq!(
			config.select_algorithm(OperationType::Regular),
			PostQuantumAlgorithm::Falcon512
		);
		
		// Critical ops with satellite config should still use Falcon due to bandwidth
		assert_eq!(
			config.select_algorithm(OperationType::Critical),
			PostQuantumAlgorithm::Falcon512
		);
	}

	#[test]
	fn test_bandwidth_suitability() {
		// 9.6 kbps satellite link
		let bandwidth = 9600;
		let max_latency = 1000; // 1 second
		
		assert!(PostQuantumAlgorithm::Falcon512.suitable_for_bandwidth(bandwidth, max_latency));
		assert!(!PostQuantumAlgorithm::SphincsPlus.suitable_for_bandwidth(bandwidth, max_latency));
	}
}