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

//! SPHINCS+ crypto types using macro approach.

use crate::{KeyTypeId, RuntimePublic};
use alloc::vec::Vec;

pub use sp_core::sphincs::*;

mod app {
	crate::app_crypto!(super, sp_core::testing::SPHINCS);
}

pub use app::{Pair as AppPair, Public as AppPublic, Signature as AppSignature};

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
		let sig_bytes = sp_core::crypto::ByteArray::to_raw_vec(signature);
		sp_io::crypto::sphincs_verify(sig_bytes, msg.as_ref(), self)
	}

	fn generate_proof_of_possession(&mut self, _key_type: KeyTypeId) -> Option<Self::Signature> {
		// SPHINCS+ doesn't need proof of possession as it's deterministic
		// and quantum-safe by design
		None
	}

	fn verify_proof_of_possession(&self, _proof: &Self::Signature) -> bool {
		// SPHINCS+ doesn't need proof of possession verification
		false
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		sp_core::crypto::ByteArray::to_raw_vec(self)
	}
}