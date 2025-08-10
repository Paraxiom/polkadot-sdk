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
			// TODO: Check for QKD hardware presence
			// TODO: Check entropy levels
			// For now, return false to use fallback
			false
		}
	}
}
