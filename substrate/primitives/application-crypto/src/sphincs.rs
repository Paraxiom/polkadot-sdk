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

// Import specific types to avoid naming conflicts
pub use sp_core::sphincs::{
	Pair as CorePair, Public as CorePublic, Signature as CoreSignature,
	CRYPTO_ID, PUBLIC_KEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE,
	SECRET_KEY_SERIALIZED_SIZE,
};

mod app {
	crate::app_crypto!(super, sp_core::testing::SPHINCS);
}

pub use app::{Pair as AppPair, Public as AppPublic, Signature as AppSignature};

/// A SPHINCS+ keypair.
#[cfg(feature = "full_crypto")]
pub type Pair = AppPair;

/// A SPHINCS+ public key.
pub type Public = AppPublic;

/// A SPHINCS+ signature.
pub type Signature = AppSignature;

impl RuntimePublic for Public {
	type Signature = Signature;

	fn all(key_type: KeyTypeId) -> crate::Vec<Self> {
		sp_io::crypto::sphincs_public_keys(key_type)
			.into_iter()
			.map(|k| k.into())
			.collect()
	}

	fn generate_pair(key_type: KeyTypeId, seed: Option<Vec<u8>>) -> Self {
		sp_io::crypto::sphincs_generate(key_type, seed).into()
	}

	fn sign<M: AsRef<[u8]>>(&self, key_type: KeyTypeId, msg: &M) -> Option<Self::Signature> {
		let core_pub: CorePublic = self.as_ref().clone();
		sp_io::crypto::sphincs_sign(key_type, &core_pub, msg.as_ref())
			.map(|sig| sig.into())
	}

	fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
		let core_pub: CorePublic = self.as_ref().clone();
		let core_sig: CoreSignature = signature.as_ref().clone();
		sp_io::crypto::sphincs_verify(&core_sig, msg.as_ref(), &core_pub)
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.as_ref().to_vec()
	}

	fn generate_proof_of_possession(&mut self, _key_type: KeyTypeId) -> Option<Self::Signature> {
		// SPHINCS+ doesn't have a specific PoP mechanism
		// We could sign a special message as proof
		None
	}

	fn verify_proof_of_possession(&self, _pop: &Self::Signature) -> bool {
		// SPHINCS+ doesn't have a specific PoP mechanism
		false
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::Pair as TraitPair;

	#[test]
	fn generate_account_id() {
		let keypair = Pair::generate().0;
		let account_id = keypair.public().into_account();
		// SPHINCS+ will have a different account ID format
		assert!(!account_id.to_string().is_empty());
	}
}