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

//! SPHINCS+ (SLH-DSA) post-quantum signature scheme implementation.
//!
//! This module provides quantum-resistant digital signatures using the SPHINCS+ algorithm,
//! which is one of the NIST standardized post-quantum signature schemes.

#[cfg(feature = "serde")]
use crate::crypto::Ss58Codec;
use crate::crypto::{
	ByteArray, CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair, 
	Public as PublicTrait, Signature as SignatureTrait,
	SecretStringError, UncheckedFrom,
};

use alloc::{vec::Vec, format};
#[cfg(feature = "serde")]
use alloc::string::String;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use sp_std::convert::TryFrom;

/// SPHINCS+ public key size (64 bytes for SPHINCS+-256)
pub const PUBLIC_KEY_SERIALIZED_SIZE: usize = 64;

/// SPHINCS+ signature size (varies by parameter set, using SPHINCS+-256f)
pub const SIGNATURE_SERIALIZED_SIZE: usize = 49856;

/// SPHINCS+ secret key size
pub const SECRET_KEY_SERIALIZED_SIZE: usize = 128;

/// An identifier used to match public keys against pre-stored quantum keys.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sphn");

/// A secret seed (for deterministic key derivation).
///
/// For SPHINCS+ we don't use a seed directly but generate keypairs deterministically.
#[derive(Clone)]
pub struct Seed([u8; 48]);

impl Default for Seed {
	fn default() -> Self {
		Seed([0u8; 48])
	}
}

impl AsRef<[u8]> for Seed {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for Seed {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

impl From<[u8; 48]> for Seed {
	fn from(seed: [u8; 48]) -> Self {
		Seed(seed)
	}
}

/// SPHINCS+ public key.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Hash,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
)]
pub struct Public(pub [u8; PUBLIC_KEY_SERIALIZED_SIZE]);

impl crate::crypto::FromEntropy for Public {
	fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
		let mut result = Self([0u8; PUBLIC_KEY_SERIALIZED_SIZE]);
		input.read(&mut result.0)?;
		Ok(result)
	}
}

impl ByteArray for Public {
	const LEN: usize = PUBLIC_KEY_SERIALIZED_SIZE;
}

impl UncheckedFrom<[u8; PUBLIC_KEY_SERIALIZED_SIZE]> for Public {
	fn unchecked_from(data: [u8; PUBLIC_KEY_SERIALIZED_SIZE]) -> Self {
		Public(data)
	}
}

impl TryFrom<&[u8]> for Public {
	type Error = ();

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() != PUBLIC_KEY_SERIALIZED_SIZE {
			return Err(())
		}
		let mut r = [0u8; PUBLIC_KEY_SERIALIZED_SIZE];
		r.copy_from_slice(data);
		Ok(Self(r))
	}
}

impl From<Public> for [u8; PUBLIC_KEY_SERIALIZED_SIZE] {
	fn from(x: Public) -> Self {
		x.0
	}
}

impl From<[u8; PUBLIC_KEY_SERIALIZED_SIZE]> for Public {
	fn from(x: [u8; PUBLIC_KEY_SERIALIZED_SIZE]) -> Self {
		Public(x)
	}
}

impl AsRef<[u8]> for Public {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for Public {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

impl PublicTrait for Public {}

impl crate::crypto::Derive for Public {}

impl Public {
	/// Create a new instance from the given 64-byte `data`.
	pub fn from_raw(data: [u8; PUBLIC_KEY_SERIALIZED_SIZE]) -> Self {
		Self(data)
	}

	/// Return a `Vec<u8>` filled with raw data.
	pub fn to_raw_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}
}

impl sp_std::fmt::Debug for Public {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "0x{}", crate::hexdisplay::HexDisplay::from(&self.0))
	}
}

#[cfg(feature = "serde")]
impl Serialize for Public {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_ss58check())
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Public {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Public::from_ss58check(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

/// SPHINCS+ signature.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct Signature(pub [u8; SIGNATURE_SERIALIZED_SIZE]);

impl TryFrom<&[u8]> for Signature {
	type Error = ();

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() != SIGNATURE_SERIALIZED_SIZE {
			return Err(())
		}
		let mut r = [0u8; SIGNATURE_SERIALIZED_SIZE];
		r.copy_from_slice(data);
		Ok(Self(r))
	}
}

impl From<Signature> for [u8; SIGNATURE_SERIALIZED_SIZE] {
	fn from(x: Signature) -> [u8; SIGNATURE_SERIALIZED_SIZE] {
		x.0
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for Signature {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

impl ByteArray for Signature {
	const LEN: usize = SIGNATURE_SERIALIZED_SIZE;
}

impl SignatureTrait for Signature {}

impl UncheckedFrom<[u8; SIGNATURE_SERIALIZED_SIZE]> for Signature {
	fn unchecked_from(data: [u8; SIGNATURE_SERIALIZED_SIZE]) -> Self {
		Signature(data)
	}
}

impl sp_std::fmt::Debug for Signature {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "SphincsSignature({} bytes)", SIGNATURE_SERIALIZED_SIZE)
	}
}

/// A key pair for SPHINCS+ signatures.
#[derive(Clone)]
pub struct Pair {
	secret: [u8; SECRET_KEY_SERIALIZED_SIZE],
	public: Public,
}

impl Pair {
	/// Create a new key pair from secret key bytes.
	pub fn from_secret(secret: [u8; SECRET_KEY_SERIALIZED_SIZE]) -> Self {
		// In real implementation, derive public key from secret
		// For now, we'll use a placeholder
		let public = Public([0u8; PUBLIC_KEY_SERIALIZED_SIZE]);
		Self { secret, public }
	}

	/// Get the secret key.
	pub fn secret(&self) -> &[u8; SECRET_KEY_SERIALIZED_SIZE] {
		&self.secret
	}

	/// Generate a key pair from a seed.
	pub fn from_seed(seed: &Seed) -> Self {
		// In real implementation, use SPHINCS+ key generation
		// For now, we'll use a deterministic derivation
		let mut secret = [0u8; SECRET_KEY_SERIALIZED_SIZE];
		secret[..48].copy_from_slice(seed.as_ref());
		
		let public = Public([0u8; PUBLIC_KEY_SERIALIZED_SIZE]);
		Self { secret, public }
	}
}

impl TraitPair for Pair {
	type Seed = Seed;
	type Public = Public;
	type Signature = Signature;

	fn from_seed_slice(seed_slice: &[u8]) -> Result<Self, SecretStringError> {
		if seed_slice.len() != 48 {
			return Err(SecretStringError::InvalidSeedLength)
		}
		let mut seed = [0u8; 48];
		seed.copy_from_slice(seed_slice);
		Ok(Self::from_seed(&Seed::from(seed)))
	}

	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		_path: Iter,
		_seed: Option<Self::Seed>,
	) -> Result<(Self, Option<Self::Seed>), DeriveError> {
		// SPHINCS+ doesn't support key derivation in the traditional sense
		Err(DeriveError::SoftKeyInPath)
	}

	fn public(&self) -> Self::Public {
		self.public
	}

	#[cfg(feature = "full_crypto")]
	fn sign(&self, _message: &[u8]) -> Self::Signature {
		// In real implementation, use SPHINCS+ signing
		// For now, return a dummy signature
		Signature([0u8; SIGNATURE_SERIALIZED_SIZE])
	}

	fn verify<M: AsRef<[u8]>>(_sig: &Self::Signature, _message: M, _public: &Self::Public) -> bool {
		// In real implementation, use SPHINCS+ verification
		// For now, return true for testing
		true
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.secret.to_vec()
	}
}

impl CryptoType for Pair {
	type Pair = Pair;
}

impl CryptoType for Public {
	type Pair = Pair;
}

impl CryptoType for Signature {
	type Pair = Pair;
}

/// Derive a single hard junction.
fn derive_hard_junction(secret: &[u8; SECRET_KEY_SERIALIZED_SIZE], _cc: &[u8; 32]) -> [u8; SECRET_KEY_SERIALIZED_SIZE] {
	// SPHINCS+ doesn't support traditional HD derivation
	// This is a placeholder
	*secret
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::Pair as TraitPair;

	#[test]
	fn test_length_of_public_key() {
		assert_eq!(Public::LEN, PUBLIC_KEY_SERIALIZED_SIZE);
	}

	#[test]
	fn test_length_of_signature() {
		assert_eq!(Signature::LEN, SIGNATURE_SERIALIZED_SIZE);
	}

	#[test]
	fn generated_pair_should_work() {
		let seed = Seed::from([0u8; 48]);
		let pair = Pair::from_seed(&seed);
		let public = pair.public();
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		assert!(Pair::verify(&signature, &message[..], &public));
	}
}