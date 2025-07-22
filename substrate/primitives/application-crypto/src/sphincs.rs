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

//! SPHINCS+ (post-quantum) cryptographic types and functionality.

use crate::{KeyTypeId, RuntimePublic};
use alloc::vec::Vec;

// TEMPORARY FIX: Stub out SPHINCS+ to avoid recursive type error
// QuantumHarmony uses Falcon-512 instead of SPHINCS+ for post-quantum signatures

/// Placeholder for SPHINCS+ public key
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Public([u8; 32]);

/// Placeholder for SPHINCS+ signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

/// Placeholder for SPHINCS+ keypair
#[cfg(feature = "full_crypto")]
#[derive(Clone)]
pub struct Pair;

impl RuntimePublic for Public {
	type Signature = Signature;

	fn all(_key_type: KeyTypeId) -> crate::Vec<Self> {
		Vec::new()
	}

	fn generate_pair(_key_type: KeyTypeId, _seed: Option<Vec<u8>>) -> Self {
		Public([0u8; 32])
	}

	fn sign<M: AsRef<[u8]>>(&self, _key_type: KeyTypeId, _msg: &M) -> Option<Self::Signature> {
		None
	}

	fn verify<M: AsRef<[u8]>>(&self, _msg: &M, _signature: &Self::Signature) -> bool {
		false
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	fn generate_proof_of_possession(&mut self, _key_type: KeyTypeId) -> Option<Self::Signature> {
		None
	}

	fn verify_proof_of_possession(&self, _pop: &Self::Signature) -> bool {
		false
	}
}

// Re-export constants from sp_core if they exist
pub use sp_core::sphincs::{
	CRYPTO_ID, PUBLIC_KEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
	SECRET_KEY_SERIALIZED_SIZE,
};

#[cfg(test)]
mod tests {
	// Tests disabled for stub implementation
}