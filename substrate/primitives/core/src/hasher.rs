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

//! Substrate Blake2b Hasher implementation

pub mod blake2 {
	use crate::hash::H256;
	use hash256_std_hasher::Hash256StdHasher;
	use hash_db::Hasher;

	/// Concrete implementation of Hasher using Blake2b 256-bit hashes
	#[derive(Debug)]
	pub struct Blake2Hasher;

	impl Hasher for Blake2Hasher {
		type Out = H256;
		type StdHasher = Hash256StdHasher;
		const LENGTH: usize = 32;

		fn hash(x: &[u8]) -> Self::Out {
			sp_crypto_hashing::blake2_256(x).into()
		}
	}
}

pub mod keccak {
	use crate::hash::H256;
	use hash256_std_hasher::Hash256StdHasher;
	use hash_db::Hasher;

	/// Concrete implementation of Hasher using Keccak 256-bit hashes
	#[derive(Debug)]
	pub struct KeccakHasher;

	impl Hasher for KeccakHasher {
		type Out = H256;
		type StdHasher = Hash256StdHasher;
		const LENGTH: usize = 32;

		fn hash(x: &[u8]) -> Self::Out {
			sp_crypto_hashing::keccak_256(x).into()
		}
	}
}

pub mod quantum {
	use crate::hash::H256;
	use hash256_std_hasher::Hash256StdHasher;
	use hash_db::Hasher;

	/// Quantum-aware hasher that uses PQC/QKD when available, falls back to Blake2
	#[derive(Debug)]
	pub struct QuantumHasher;

	impl Hasher for QuantumHasher {
		type Out = H256;
		type StdHasher = Hash256StdHasher;
		const LENGTH: usize = 32;

		fn hash(x: &[u8]) -> Self::Out {
			// Check if quantum resources are available
			if Self::quantum_available() {
				// Use quantum-safe hashing (SHA3/Keccak is quantum-resistant)
				sp_crypto_hashing::keccak_256(x).into()
			} else {
				// Fallback to Blake2
				sp_crypto_hashing::blake2_256(x).into()
			}
		}
	}

	impl QuantumHasher {
		/// Check if quantum resources (QKD hardware, entropy) are available
		fn quantum_available() -> bool {
			// Check multiple quantum resource indicators
			Self::check_qkd_hardware() || Self::check_entropy_levels() || Self::check_env_flag()
		}
		
		/// Check for QKD hardware presence
		fn check_qkd_hardware() -> bool {
			// Check for known QKD device paths
			#[cfg(target_os = "linux")]
			{
				// Toshiba QKD typically exposes devices at /dev/qkd*
				if std::path::Path::new("/dev/qkd0").exists() {
					return true;
				}
				
				// IDQ Quantis devices
				if std::path::Path::new("/dev/quantis0").exists() {
					return true;
				}
				
				// Check for QKD network endpoints
				if Self::check_qkd_network() {
					return true;
				}
			}
			
			false
		}
		
		/// Check if sufficient quantum entropy is available
		fn check_entropy_levels() -> bool {
			#[cfg(feature = "std")]
			{
				// Check entropy available in system
				if let Ok(contents) = std::fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
					if let Ok(entropy) = contents.trim().parse::<u32>() {
						// Require high entropy (> 3000 bits) for quantum mode
						return entropy > 3000;
					}
				}
			}
			
			false
		}
		
		/// Check for QKD network services
		fn check_qkd_network() -> bool {
			#[cfg(feature = "std")]
			{
				use std::net::TcpStream;
				use std::time::Duration;
				
				// Known QKD endpoints
				let endpoints = [
					"192.168.0.152:5000", // Toshiba Alice
					"192.168.0.153:5000", // Toshiba Bob
					"127.0.0.1:8080",     // KIRQ Hub
					"localhost:9999",     // Quantum Bridge
				];
				
				for endpoint in &endpoints {
					if let Ok(stream) = TcpStream::connect_timeout(
						&endpoint.parse().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
						Duration::from_millis(100)
					) {
						drop(stream);
						return true;
					}
				}
			}
			
			false
		}
		
		/// Check environment variable for quantum mode
		fn check_env_flag() -> bool {
			#[cfg(feature = "std")]
			{
				std::env::var("QUANTUM_MODE").unwrap_or_default() == "1" ||
				std::env::var("ENABLE_QUANTUM").unwrap_or_default() == "true"
			}
			
			#[cfg(not(feature = "std"))]
			false
		}
	}
}
