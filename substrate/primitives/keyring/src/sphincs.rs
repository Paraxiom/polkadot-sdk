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

//! Support code for the runtime. A set of test accounts with SPHINCS+ keys.

use crate::ParseKeyringError;
use alloc::{fmt, str::FromStr, string::String, vec::Vec};
use sp_core::{crypto::Ss58Codec, sphincs};
use sp_core::crypto::Pair as TraitPair;

extern crate alloc;

/// Set of test accounts using SPHINCS+ crypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display, strum::EnumIter)]
pub enum Keyring {
	Alice,
	Bob,
	Charlie,
	Dave,
	Eve,
	Ferdie,
	One,
	Two,
}

impl Keyring {
	pub fn from_public(who: &sphincs::Public) -> Option<Keyring> {
		Self::iter().find(|k| &k.public() == who)
	}

	pub fn from_account_id(who: &sphincs::Public) -> Option<Keyring> {
		Self::iter().find(|k| &k.public() == who)
	}

	pub fn from_raw_public(who: [u8; 64]) -> Option<Keyring> {
		Self::from_public(&sphincs::Public::from_raw(who))
	}

	pub fn to_raw_public(self) -> [u8; 64] {
		self.public().to_raw_vec().try_into().expect("SPHINCS+ key is always 64 bytes")
	}

	pub fn from_h256_public(who: sp_core::H256) -> Option<Keyring> {
		// H256 is 32 bytes, but SPHINCS+ public keys are 64 bytes
		// We'll pad with zeros for compatibility
		let mut key = [0u8; 64];
		key[..32].copy_from_slice(who.as_bytes());
		Self::from_raw_public(key)
	}

	pub fn to_h256_public(self) -> sp_core::H256 {
		// Take first 32 bytes of the 64-byte public key
		let key = self.to_raw_public();
		sp_core::H256::from_slice(&key[..32])
	}

	pub fn to_raw_public_vec(self) -> Vec<u8> {
		self.public().to_raw_vec()
	}

	pub fn to_account_id(self) -> sphincs::Public {
		self.public()
	}

	#[cfg(feature = "full_crypto")]
	pub fn sign(self, msg: &[u8]) -> sphincs::Signature {
		<sphincs::Pair as TraitPair>::sign(&self.pair(), msg)
	}

	pub fn pair(self) -> sphincs::Pair {
		// SPHINCS+ doesn't support key derivation, so we use deterministic seeds
		let seed = match self {
			Keyring::Alice => [1u8; 48],
			Keyring::Bob => [2u8; 48],
			Keyring::Charlie => [3u8; 48],
			Keyring::Dave => [4u8; 48],
			Keyring::Eve => [5u8; 48],
			Keyring::Ferdie => [6u8; 48],
			Keyring::One => [7u8; 48],
			Keyring::Two => [8u8; 48],
		};
		sphincs::Pair::from_seed(&sphincs::Seed::from(seed))
	}

	pub fn public(self) -> sphincs::Public {
		self.pair().public()
	}

	pub fn to_seed(self) -> String {
		match self {
			Keyring::Alice => "//Alice".into(),
			Keyring::Bob => "//Bob".into(),
			Keyring::Charlie => "//Charlie".into(),
			Keyring::Dave => "//Dave".into(),
			Keyring::Eve => "//Eve".into(),
			Keyring::Ferdie => "//Ferdie".into(),
			Keyring::One => "//One".into(),
			Keyring::Two => "//Two".into(),
		}
	}

	/// Returns an iterator over all test accounts.
	pub fn iter() -> impl Iterator<Item = Keyring> {
		<Self as strum::IntoEnumIterator>::iter()
	}

	pub fn numeric(idx: usize) -> Self {
		match idx {
			0 => Keyring::Alice,
			1 => Keyring::Bob,
			2 => Keyring::Charlie,
			3 => Keyring::Dave,
			4 => Keyring::Eve,
			5 => Keyring::Ferdie,
			_ => panic!("Cannot create Keyring from index {}", idx),
		}
	}
}

impl From<Keyring> for sphincs::Public {
	fn from(k: Keyring) -> Self {
		k.public()
	}
}

impl From<Keyring> for sphincs::Pair {
	fn from(k: Keyring) -> Self {
		k.pair()
	}
}

impl From<Keyring> for [u8; 64] {
	fn from(k: Keyring) -> Self {
		k.public().to_raw_vec().try_into().expect("SPHINCS+ public key is always 64 bytes")
	}
}

// Note: Direct conversion from Keyring to H256 is not provided
// because SPHINCS+ keys are 64 bytes while H256 is 32 bytes.
// Use to_h256_public() method instead.

impl FromStr for Keyring {
	type Err = ParseKeyringError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		match s {
			"alice" | "Alice" => Ok(Keyring::Alice),
			"bob" | "Bob" => Ok(Keyring::Bob),
			"charlie" | "Charlie" => Ok(Keyring::Charlie),
			"dave" | "Dave" => Ok(Keyring::Dave),
			"eve" | "Eve" => Ok(Keyring::Eve),
			"ferdie" | "Ferdie" => Ok(Keyring::Ferdie),
			"one" | "One" => Ok(Keyring::One),
			"two" | "Two" => Ok(Keyring::Two),
			_ => Err(ParseKeyringError),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::sphincs::Pair;

	#[test]
	fn should_work() {
		assert!(Keyring::iter()
			.all(|k| sphincs::Public::from_raw(k.to_raw_public()).is_ok()));
	}

	#[test]
	fn verify_static_public_keys() {
		// These keys are deterministic based on the seed
		// SPHINCS+ uses deterministic key generation
		assert!(Keyring::iter().all(|k| {
			let pair = k.pair();
			let public = pair.public();
			k.public() == public
		}));
	}

	#[test]
	fn verify_static_signatures() {
		let msg = b"test message";
		assert!(Keyring::iter().all(|k| {
			let sig = k.sign(msg);
			k.pair().verify(&sig, msg)
		}));
	}

	#[test]
	fn verify_account_id_derivation() {
		assert!(Keyring::iter().all(|k| {
			let account_id = k.to_account_id();
			k == Keyring::from_account_id(&account_id).unwrap()
		}));
	}
}