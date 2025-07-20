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

pub use sp_core::sphincs::*;

mod app {
	use sp_core::testing::SPHINCS;

	crate::app_crypto!(super, SPHINCS);
}

/// A SPHINCS+ keypair.
#[cfg(feature = "full_crypto")]
pub type Pair = app::Pair;

/// A SPHINCS+ public key.
pub type Public = app::Public;

/// A SPHINCS+ signature.
pub type Signature = app::Signature;

impl RuntimePublic for Public {
	type Signature = Signature;

	fn all(key_type: KeyTypeId) -> crate::Vec<Self> {
		sp_io::crypto::sphincs_public_keys(key_type)
	}

	fn generate_pair(key_type: KeyTypeId, seed: Option<Vec<u8>>) -> Self {
		sp_io::crypto::sphincs_generate(key_type, seed)
	}

	fn sign<M: AsRef<[u8]>>(&self, key_type: KeyTypeId, msg: &M) -> Option<Self::Signature> {
		sp_io::crypto::sphincs_sign(key_type, self, msg.as_ref())
	}

	fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
		sp_io::crypto::sphincs_verify(signature, msg.as_ref(), self)
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.to_vec()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::Pair as TraitPair;

	#[test]
	fn generate_account_id() {
		let keypair = app::Pair::generate().0;
		let account_id = keypair.public().into_account();
		assert_eq!(account_id.to_string(), "5FKFid8YeUCQZbYTZnSZM7CJyqKYLPGPpxjnqgKWBej1Nxjy");
	}
}