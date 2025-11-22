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
//!
//! SPHINCS+ provides the highest security guarantees as it relies only on hash functions,
//! but has large signatures (17-49 KB) making it unsuitable for bandwidth-constrained
//! applications. Use for critical operations only.

use alloc::{vec::Vec, string::String, format};
use core::convert::TryFrom;
#[cfg(feature = "serde")]
use crate::crypto::Ss58Codec;
use crate::crypto::{
	ByteArray, CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair,
	Public as PublicTrait, Signature as SignatureTrait,
	SecretStringError, UncheckedFrom,
};

#[cfg(feature = "std")]
use secrecy::ExposeSecret;
#[cfg(feature = "std")]
use crate::address_uri;

#[cfg(feature = "full_crypto")]
use pqcrypto_sphincsplus::sphincsshake256fsimple as sphincs_impl;
#[cfg(feature = "full_crypto")]
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, SignedMessage as _};
use codec::{Decode, Encode, MaxEncodedLen, DecodeWithMemTracking};
use scale_info::TypeInfo;

// FFI bindings to PQClean's deterministic key generation

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// SPHINCS+ public key size (64 bytes for SPHINCS+-256)
pub const PUBLIC_KEY_SERIALIZED_SIZE: usize = 64;
pub const PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_SERIALIZED_SIZE;

/// SPHINCS+ signature size (varies by parameter set, using SPHINCS+-256f)
pub const SIGNATURE_SERIALIZED_SIZE: usize = 49856;
pub const SIGNATURE_LENGTH: usize = SIGNATURE_SERIALIZED_SIZE;

/// SPHINCS+ secret key size
pub const SECRET_KEY_SERIALIZED_SIZE: usize = 128;

/// SPHINCS+ key type ID
pub const SPHINCS_CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sphn");

/// Alias for compatibility
pub const PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_SERIALIZED_SIZE;
pub const SIGNATURE_SIZE: usize = SIGNATURE_SERIALIZED_SIZE;

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
	DecodeWithMemTracking,
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
	
	/// Create from 32-byte account ID (for runtime compatibility)
	pub fn from_account_id(data: [u8; 32]) -> Self {
		// SPHINCS+ public keys are 64 bytes, so we need to pad
		let mut bytes = [0u8; PUBLIC_KEY_SERIALIZED_SIZE];
		bytes[..32].copy_from_slice(&data);
		Self(bytes)
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

#[cfg(feature = "std")]
impl std::fmt::Display for Public {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.to_ss58check())
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
#[derive(Clone, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Hash))]
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

impl Signature {
	/// Create from raw bytes array
	pub fn from_raw(data: [u8; SIGNATURE_SERIALIZED_SIZE]) -> Self {
		Signature(data)
	}
}


#[cfg(feature = "serde")]
impl Serialize for Signature {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_bytes(&self.0[..])
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let bytes = <Vec<u8>>::deserialize(deserializer)?;
		if bytes.len() != SIGNATURE_SERIALIZED_SIZE {
			return Err(serde::de::Error::custom("Invalid signature length"));
		}
		let mut arr = [0u8; SIGNATURE_SERIALIZED_SIZE];
		arr.copy_from_slice(&bytes);
		Ok(Signature(arr))
	}
}

impl SignatureTrait for Signature {}

impl Signature {
	/// Verify a signature against a message and public key
	pub fn verify<M: AsRef<[u8]>>(&self, message: M, pubkey: &Public) -> bool {
		#[cfg(feature = "full_crypto")]
		{
			// Convert our types to the format expected by pqcrypto
			let pk = match sphincs_impl::PublicKey::from_bytes(&pubkey.0) {
				Ok(pk) => pk,
				Err(_) => return false,
			};

			// CRITICAL FIX FOR SPHINCS+ VERIFICATION:
			//
			// SPHINCS+ in pqcrypto-sphincsplus uses "signed message" format where
			// the signature and message are COMBINED:
			//   sign(msg, sk) -> SignedMessage = [signature_bytes || message_bytes]
			//   open(SignedMessage, pk) -> extracts and returns original message
			//
			// However, Substrate uses "detached signature" format where signature
			// and message are stored separately. During signing, we only store the
			// first SIGNATURE_SERIALIZED_SIZE bytes, discarding the message part.
			//
			// During verification, we need to reconstruct the SignedMessage format
			// by concatenating signature + message before calling open().
			//
			// SignedMessage format: [signature (49856 bytes) || message (variable)]

			let msg_bytes = message.as_ref();
			let mut signed_message_bytes = Vec::with_capacity(SIGNATURE_SERIALIZED_SIZE + msg_bytes.len());
			signed_message_bytes.extend_from_slice(&self.0);
			signed_message_bytes.extend_from_slice(msg_bytes);

			let signed_msg = match sphincs_impl::SignedMessage::from_bytes(&signed_message_bytes) {
				Ok(sm) => sm,
				Err(_) => return false,
			};

			// Verify the signature by opening the signed message
			match sphincs_impl::open(&signed_msg, &pk) {
				Ok(opened_msg) => {
					// Check if the opened message matches our input message
					opened_msg == msg_bytes
				}
				Err(_) => false,
			}
		}

		#[cfg(not(feature = "full_crypto"))]
		{
			// Without full_crypto, we can't verify signatures
			false
		}
	}
}

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

// ============================================================================
// SHARED CACHE FOR SPHINCS+ KEYPAIRS
// ============================================================================
// This cache is shared between Pair::from_seed() and Pair::insert_hardcoded_keypair()
// to ensure consistent keypair retrieval
#[cfg(feature = "full_crypto")]
mod keypair_cache {
	use core::sync::atomic::{AtomicBool, Ordering};
	use alloc::collections::BTreeMap;
	use super::{PUBLIC_KEY_SERIALIZED_SIZE, SECRET_KEY_SERIALIZED_SIZE};

	pub static INIT: AtomicBool = AtomicBool::new(false);
	pub static mut CACHE: Option<BTreeMap<[u8; 48], ([u8; PUBLIC_KEY_SERIALIZED_SIZE], [u8; SECRET_KEY_SERIALIZED_SIZE])>> = None;

	/// Initialize the cache if not already initialized
	pub unsafe fn init_cache() {
		if !INIT.load(Ordering::Acquire) {
			CACHE = Some(BTreeMap::new());
			INIT.store(true, Ordering::Release);
		}
	}

	/// Get mutable access to the cache (must call init_cache() first)
	pub unsafe fn get_cache_mut() -> &'static mut BTreeMap<[u8; 48], ([u8; PUBLIC_KEY_SERIALIZED_SIZE], [u8; SECRET_KEY_SERIALIZED_SIZE])> {
		CACHE.as_mut().unwrap()
	}
}

impl Pair {
	/// Create a new key pair from secret key bytes.
	pub fn from_secret(secret: [u8; SECRET_KEY_SERIALIZED_SIZE]) -> Self {
		#[cfg(feature = "full_crypto")]
		{
			// Extract public key from the secret key
			let sk = match sphincs_impl::SecretKey::from_bytes(&secret) {
				Ok(sk) => sk,
				Err(_) => {
					return Self { 
						secret, 
						public: Public([0u8; PUBLIC_KEY_SERIALIZED_SIZE]) 
					}
				}
			};
			
			// Extract public key bytes from secret key (public key is embedded in secret key)
			let sk_bytes = sk.as_bytes();
			let pk_bytes = &sk_bytes[..PUBLIC_KEY_SERIALIZED_SIZE];
			
			let mut public_bytes = [0u8; PUBLIC_KEY_SERIALIZED_SIZE];
			let copy_len = pk_bytes.len().min(PUBLIC_KEY_SERIALIZED_SIZE);
			public_bytes[..copy_len].copy_from_slice(&pk_bytes[..copy_len]);
			
			Self { 
				secret, 
				public: Public(public_bytes) 
			}
		}
		
		#[cfg(not(feature = "full_crypto"))]
		{
			let public = Public([0u8; PUBLIC_KEY_SERIALIZED_SIZE]);
			Self { secret, public }
		}
	}

	/// Get the secret key.
	pub fn secret(&self) -> &[u8; SECRET_KEY_SERIALIZED_SIZE] {
		&self.secret
	}

/// Generate a key pair from a seed.
///
/// NOTE: Since pqcrypto-sphincsplus doesn't provide deterministic key generation,
/// we use a lazy static cache to ensure the same seed always returns the same keypair.
/// This is acceptable for dev/test networks.
pub fn from_seed(seed: &Seed) -> Self {
	#[cfg(feature = "full_crypto")]
	{
		let seed_bytes: [u8; 48] = {
			let mut s = [0u8; 48];
			s.copy_from_slice(&seed.as_ref()[..48]);
			s
		};

		unsafe {
			keypair_cache::init_cache();
			let cache = keypair_cache::get_cache_mut();

			if let Some((pk_bytes, sk_bytes)) = cache.get(&seed_bytes) {
				// Return cached keypair
				return Pair {
					secret: *sk_bytes,
					public: Public(*pk_bytes),
				};
			}

			// Generate new keypair using pqcrypto-sphincsplus Rust API
			let (pk, sk) = sphincs_impl::keypair();

			let mut pk_bytes = [0u8; PUBLIC_KEY_SERIALIZED_SIZE];
			let mut sk_bytes = [0u8; SECRET_KEY_SERIALIZED_SIZE];

			pk_bytes.copy_from_slice(pk.as_bytes());
			sk_bytes.copy_from_slice(sk.as_bytes());

			// Cache for future use
			cache.insert(seed_bytes, (pk_bytes, sk_bytes));

			Pair {
				secret: sk_bytes,
				public: Public(pk_bytes),
			}
		}
	}

	#[cfg(not(feature = "full_crypto"))]
	{
		let mut secret = [0u8; SECRET_KEY_SERIALIZED_SIZE];
		secret[..48].copy_from_slice(seed.as_ref());
		let public = Public([0u8; PUBLIC_KEY_SERIALIZED_SIZE]);
		Self { secret, public }
	}
}

/// Manually insert a hardcoded keypair into the SPHINCS+ cache
///
/// This function allows pre-populating the cache with specific keypairs for development mode.
///
/// WHY THIS IS NEEDED:
/// - SPHINCS+ keypair generation is non-deterministic (calls sphincs_impl::keypair())
/// - The from_seed() function generates RANDOM keypairs and caches them by seed
/// - For development networks, we need reproducible keys that match genesis config
/// - Solution: Pre-generate keypairs offline, hardcode them, and insert into cache
///
/// USAGE:
/// ```ignore
/// let seed = [0xbb, 0xe4, ...]; // 48 bytes
/// let public = [0x43, 0x53, ...]; // 64 bytes
/// let secret = [0x..., ...]; // 2592 bytes
/// insert_hardcoded_keypair(&seed, &public, &secret);
///
/// // Now from_seed_slice(&seed) will return this exact keypair
/// let pair = SphincsPair::from_seed_slice(&seed).unwrap();
/// assert_eq!(pair.public().as_ref(), &public);
/// ```
///
/// PRODUCTION QRNG INTEGRATION:
/// - This approach is for development mode only
/// - For production: Generate keypairs with QRNG → Store permanently → Never re-derive
/// - See SPHINCS_KEYSTORE_ARCHITECTURE.md for full details
pub fn insert_hardcoded_keypair(seed: &[u8; 48], public: &[u8; PUBLIC_KEY_SERIALIZED_SIZE], secret: &[u8; SECRET_KEY_SERIALIZED_SIZE]) {
	#[cfg(feature = "full_crypto")]
	{
		unsafe {
			keypair_cache::init_cache();
			let cache = keypair_cache::get_cache_mut();

			// Insert the hardcoded keypair into the SHARED cache
			// This ensures from_seed() will return this exact keypair
			cache.insert(*seed, (*public, *secret));
		}
	}
}

/// Get a cached keypair by public key (for dev mode consensus)
/// Returns None if the key is not in the cache
///
/// NOTE: This uses the SAME cache as from_seed(), so keys must be generated
/// via from_seed() first before they can be retrieved here.
pub fn get_cached_pair(public: &Public) -> Option<Pair> {
	#[cfg(feature = "full_crypto")]
	{
		// Re-use the cache from from_seed() by calling from_seed() with a dummy seed
		// and then searching through all cached values
		//
		// This is inefficient but works for dev mode with small key counts

		use crate::crypto::DeriveJunction;

		// Try common dev seeds to populate cache
		let dev_seeds = [
			"//Alice",
			"//Bob",
			"//Charlie",
			"//Dave",
			"//Eve",
			"//Ferdie",
		];

		for seed_str in &dev_seeds {
			// Generate keypair from seed to populate cache
			if let Ok(pair) = <Pair as TraitPair>::from_string(seed_str, None) {
				if &pair.public() == public {
					return Some(pair);
				}
			}
		}

		None
	}

	#[cfg(not(feature = "full_crypto"))]
	None
}
}

impl TraitPair for Pair {
	type Seed = Seed;
	type Public = Public;
	type Signature = Signature;

	fn from_seed_slice(seed_slice: &[u8]) -> Result<Self, SecretStringError> {
		// SPHINCS+ requires exactly 48 bytes of entropy
		// If seed is not 48 bytes, hash it to generate deterministic 48-byte seed
		let seed = if seed_slice.len() == 48 {
			let mut s = [0u8; 48];
			s.copy_from_slice(seed_slice);
			s
		} else {
			// Use blake2_256 twice to generate 48 bytes deterministically
			use crate::blake2_256;
			let hash1 = blake2_256(seed_slice);
			let hash2 = blake2_256(&hash1);
			let mut s = [0u8; 48];
			s[..32].copy_from_slice(&hash1);
			s[32..].copy_from_slice(&hash2[..16]);
			s
		};
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

	/// Generate a key pair from BIP39 phrase or simple string
	#[cfg(feature = "std")]
	fn from_phrase(
		phrase: &str,
		password: Option<&str>,
	) -> Result<(Self, Self::Seed), SecretStringError> {
		use bip39::{Language, Mnemonic};

		// Try to parse as BIP39 mnemonic first
		if let Ok(mnemonic) = Mnemonic::parse_in(Language::English, phrase) {
			let (entropy, entropy_len) = mnemonic.to_entropy_array();
			let mut seed_material = entropy[..entropy_len].to_vec();

			// Mix in password if provided
			if let Some(pass) = password {
				seed_material.extend_from_slice(pass.as_bytes());
			}

			// Hash to get 48-byte seed
			use crate::blake2_256;
			let hash1 = blake2_256(&seed_material);
			let hash2 = blake2_256(&hash1);
			let mut seed_bytes = [0u8; 48];
			seed_bytes[..32].copy_from_slice(&hash1);
			seed_bytes[32..].copy_from_slice(&hash2[..16]);

			let seed = Seed::from(seed_bytes);
			Ok((Self::from_seed(&seed), seed))
		} else {
			// Not a valid mnemonic, treat as simple string seed
			let mut seed_material = phrase.as_bytes().to_vec();
			if let Some(pass) = password {
				seed_material.extend_from_slice(pass.as_bytes());
			}

			// Hash to get 48-byte seed
			use crate::blake2_256;
			let hash1 = blake2_256(&seed_material);
			let hash2 = blake2_256(&hash1);
			let mut seed_bytes = [0u8; 48];
			seed_bytes[..32].copy_from_slice(&hash1);
			seed_bytes[32..].copy_from_slice(&hash2[..16]);

			let seed = Seed::from(seed_bytes);
			Ok((Self::from_seed(&seed), seed))
		}
	}

	/// Override from_string to handle simple seed phrases without derivation
	/// SPHINCS+ doesn't support HD key derivation, so we treat the entire string as a seed
	#[cfg(feature = "std")]
	fn from_string(s: &str, password_override: Option<&str>) -> Result<Self, SecretStringError> {
		Self::from_string_with_seed(s, password_override).map(|x| x.0)
	}

	/// Custom implementation that treats derivation-like syntax as simple seed material
	/// For SPHINCS+, "//Alice" is just treated as the seed string "Alice"
	#[cfg(feature = "std")]
	fn from_string_with_seed(
		s: &str,
		password_override: Option<&str>,
	) -> Result<(Self, Option<Self::Seed>), SecretStringError> {
		use alloc::str::FromStr;
		use crate::crypto::SecretUri;

		let SecretUri { junctions, phrase, password } = SecretUri::from_str(s)?;
		let password =
			password_override.or_else(|| password.as_ref().map(|p| p.expose_secret().as_str()));

		// For SPHINCS+, we don't support derivation paths
		// We'll use the phrase and any junction names as seed material
		let (root, seed) = if let Some(stripped) = phrase.expose_secret().strip_prefix("0x") {
			// Hex seed
			let d = match array_bytes::hex2bytes(stripped) {
				Ok(bytes) => bytes,
				Err(_) => return Err(SecretStringError::InvalidPhrase),
			};
			let pair = Self::from_seed_slice(&d)?;
			let seed = if d.len() == 48 {
				let mut s = [0u8; 48];
				s.copy_from_slice(&d);
				Seed::from(s)
			} else {
				// Hash to 48 bytes
				use crate::blake2_256;
				let hash1 = blake2_256(&d);
				let hash2 = blake2_256(&hash1);
				let mut s = [0u8; 48];
				s[..32].copy_from_slice(&hash1);
				s[32..].copy_from_slice(&hash2[..16]);
				Seed::from(s)
			};
			(pair, seed)
		} else {
			// Mnemonic phrase or simple string
			// For simple strings (like just a name), use them directly as seed material
			Self::from_phrase(phrase.expose_secret().as_str(), password)
				.map_err(|_| SecretStringError::InvalidPhrase)?
		};

		// If there are junctions (like //Alice), incorporate them into the seed
		// but don't try to derive - just use them as additional entropy
		if !junctions.is_empty() {
			use crate::blake2_256;
			let mut seed_bytes = seed.as_ref().to_vec();
			for junction in junctions.iter() {
				// Mix in the junction data
				match junction {
					DeriveJunction::Soft(cc) | DeriveJunction::Hard(cc) => {
						seed_bytes.extend_from_slice(cc);
					}
				}
			}
			// Hash the combined seed material to get final 48-byte seed
			let hash1 = blake2_256(&seed_bytes);
			let hash2 = blake2_256(&hash1);
			let mut final_seed = [0u8; 48];
			final_seed[..32].copy_from_slice(&hash1);
			final_seed[32..].copy_from_slice(&hash2[..16]);
			let seed_obj = Seed::from(final_seed);
			Ok((Self::from_seed(&seed_obj), Some(seed_obj)))
		} else {
			Ok((root, Some(seed)))
		}
	}

	fn public(&self) -> Self::Public {
		self.public
	}

	#[cfg(feature = "full_crypto")]
	fn sign(&self, message: &[u8]) -> Self::Signature {
		// Use the actual SPHINCS+ signing
		// First we need to reconstruct the secret key in the expected format
		let sk = match sphincs_impl::SecretKey::from_bytes(&self.secret) {
			Ok(sk) => sk,
			Err(_) => return Signature([0u8; SIGNATURE_SERIALIZED_SIZE]),
		};
		
		// Sign the message
		let signed_msg = sphincs_impl::sign(message, &sk);
		
		// Convert to our signature format
		let sig_bytes = signed_msg.as_bytes();
		let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
		let copy_len = sig_bytes.len().min(SIGNATURE_SERIALIZED_SIZE);
		signature[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);
		
		Signature(signature)
	}

	fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, public: &Self::Public) -> bool {
		sig.verify(message, public)
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.secret.to_vec()
	}
}

impl CryptoType for Pair {
	type Pair = Pair;
}

// SPHINCS+ is non-aggregatable (cannot combine signatures)
impl crate::proof_of_possession::NonAggregatable for Pair {}

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

	#[test]
	fn test_signature_size_for_satellite() {
		// Verify SPHINCS+ has large signatures unsuitable for satellites
		assert_eq!(SIGNATURE_SERIALIZED_SIZE, 49856);
		assert!(SIGNATURE_SERIALIZED_SIZE > 17000); // More than 17KB
		
		// At 9.6 kbps, this would take ~41 seconds to transmit!
		let bits = SIGNATURE_SERIALIZED_SIZE * 8;
		let transmission_time_sec = bits as f32 / 9600.0;
		assert!(transmission_time_sec > 30.0);
	}
}

// Implement comparison traits for satellite bandwidth analysis
#[cfg(feature = "full_crypto")]
impl crate::post_quantum::PostQuantumSignature for Signature {
	fn algorithm(&self) -> crate::post_quantum::PostQuantumAlgorithm {
		crate::post_quantum::PostQuantumAlgorithm::SphincsPlus
	}
	
	fn size(&self) -> usize {
		SIGNATURE_SERIALIZED_SIZE
	}
}
/// SPHINCS+ VRF implementation using signature-based pseudo-VRF
pub mod vrf {
	use super::*;
	#[cfg(feature = "full_crypto")]
	use crate::crypto::VrfSecret;
	use crate::crypto::{VrfCrypto, VrfPublic};
	use alloc::vec::Vec;
	use codec::{Decode, Encode, MaxEncodedLen};
	use scale_info::TypeInfo;

	/// VRF pre-output length for SPHINCS+
	pub const VRF_PREOUT_LENGTH: usize = 32;
	/// VRF proof length for SPHINCS+ (using signature as proof)
	pub const VRF_PROOF_LENGTH: usize = SIGNATURE_SERIALIZED_SIZE;

	const DEFAULT_EXTRA_DATA_LABEL: &[u8] = b"VRF";

	/// Transcript ready to be used for VRF related operations.
	///
	/// For SPHINCS+, this is a simple wrapper around transcript data.
	#[derive(Clone, Debug)]
	pub struct VrfTranscript {
		data: Vec<u8>,
	}

	impl VrfTranscript {
		/// Build a new transcript instance.
		///
		/// Each `data` element is a tuple `(domain, message)` used to build the transcript.
		pub fn new(label: &'static [u8], data: &[(&'static [u8], &[u8])]) -> Self {
			let mut transcript_data = label.to_vec();
			for (domain, message) in data.iter() {
				transcript_data.extend_from_slice(domain);
				transcript_data.extend_from_slice(message);
			}
			VrfTranscript { data: transcript_data }
		}

		/// Map transcript to `VrfSignData`.
		pub fn into_sign_data(self) -> VrfSignData {
			self.into()
		}

		/// Get transcript bytes for signing
		pub fn as_bytes(&self) -> &[u8] {
			&self.data
		}
	}

	/// VRF input - alias for transcript
	pub type VrfInput = VrfTranscript;

	/// VRF input ready to be used for VRF sign and verify operations.
	#[derive(Clone, Debug)]
	pub struct VrfSignData {
		/// Transcript data contributing to VRF output.
		pub(super) transcript: VrfTranscript,
		/// Extra transcript data to be signed by the VRF.
		pub(super) extra: Option<VrfTranscript>,
	}

	impl From<VrfInput> for VrfSignData {
		fn from(transcript: VrfInput) -> Self {
			VrfSignData { transcript, extra: None }
		}
	}

	impl AsRef<VrfInput> for VrfSignData {
		fn as_ref(&self) -> &VrfInput {
			&self.transcript
		}
	}

	impl VrfSignData {
		/// Build a new instance ready to be used for VRF signer and verifier.
		pub fn new(input: VrfTranscript) -> Self {
			input.into()
		}

		/// Add some extra data to be signed.
		pub fn with_extra(mut self, extra: VrfTranscript) -> Self {
			self.extra = Some(extra);
			self
		}

		/// Get combined transcript bytes for signing
		fn combined_bytes(&self) -> Vec<u8> {
			let mut combined = self.transcript.data.clone();
			if let Some(extra) = &self.extra {
				combined.extend_from_slice(DEFAULT_EXTRA_DATA_LABEL);
				combined.extend_from_slice(&extra.data);
			}
			combined
		}
	}

	/// VRF signature data combining pre-output and proof
	#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
	pub struct VrfSignature {
		/// VRF pre-output (deterministic hash of signature)
		pub pre_output: VrfPreOutput,
		/// VRF proof (SPHINCS+ signature serving as proof)
		pub proof: VrfProof,
	}

	/// VRF pre-output - deterministic output derived from SPHINCS+ signature
	#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
	pub struct VrfPreOutput(pub [u8; VRF_PREOUT_LENGTH]);

	/// VRF proof - SPHINCS+ signature serving as the VRF proof
	#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
	pub struct VrfProof(pub Signature);

	// Conversions for compatibility with BABE's [u8; 32] transcripts
	impl From<[u8; 32]> for VrfTranscript {
		fn from(data: [u8; 32]) -> Self {
			VrfTranscript { data: data.to_vec() }
		}
	}

	impl From<&[u8; 32]> for VrfTranscript {
		fn from(data: &[u8; 32]) -> Self {
			VrfTranscript { data: data.to_vec() }
		}
	}

	#[cfg(feature = "full_crypto")]
	impl VrfCrypto for Pair {
		type VrfInput = VrfTranscript;
		type VrfPreOutput = VrfPreOutput;
		type VrfSignData = VrfSignData;
		type VrfSignature = VrfSignature;
	}

	#[cfg(feature = "full_crypto")]
	impl VrfSecret for Pair {
		/// Create VRF signature using SPHINCS+ signature as proof
		fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature {
			// Get combined transcript bytes
			let message = data.combined_bytes();

			// Sign with SPHINCS+ to get proof
			let proof_signature = self.sign(&message);

			// Derive pre-output deterministically from signature
			// Use blake2_256 hash of the signature as VRF output
			use sp_crypto_hashing::blake2_256;
			let pre_output_bytes = blake2_256(proof_signature.as_ref());

			VrfSignature {
				pre_output: VrfPreOutput(pre_output_bytes),
				proof: VrfProof(proof_signature),
			}
		}

		/// Get VRF pre-output without creating full signature
		fn vrf_pre_output(&self, input: &Self::VrfInput) -> Self::VrfPreOutput {
			// For SPHINCS+, we need to sign to get deterministic output
			let signature = self.sign(input.as_bytes());
			use sp_crypto_hashing::blake2_256;
			let pre_output_bytes = blake2_256(signature.as_ref());
			VrfPreOutput(pre_output_bytes)
		}
	}

	impl VrfCrypto for Public {
		type VrfInput = VrfTranscript;
		type VrfPreOutput = VrfPreOutput;
		type VrfSignData = VrfSignData;
		type VrfSignature = VrfSignature;
	}

	impl VrfPublic for Public {
		/// Verify VRF signature by verifying SPHINCS+ signature and checking pre-output
		fn vrf_verify(&self, data: &Self::VrfSignData, signature: &Self::VrfSignature) -> bool {
			// Get combined transcript bytes
			let message = data.combined_bytes();

			// Verify the SPHINCS+ signature (proof)
			if !Pair::verify(&signature.proof.0, &message, self) {
				return false;
			}

			// Verify pre-output matches the signature hash
			use sp_crypto_hashing::blake2_256;
			let expected_pre_output = blake2_256(signature.proof.0.as_ref());

			expected_pre_output == signature.pre_output.0
		}
	}

	#[cfg(feature = "full_crypto")]
	impl Pair {
		/// Generate output bytes from the given VRF configuration.
		///
		/// This is used by BABE for randomness generation.
		pub fn make_bytes<const N: usize>(&self, context: &[u8], input: &VrfInput) -> [u8; N]
		where
			[u8; N]: Default,
		{
			// Create deterministic output by signing input and hashing
			let signature = self.sign(input.as_bytes());

			// Mix context and signature to derive output
			use sp_crypto_hashing::blake2_256;
			let mut combined = context.to_vec();
			combined.extend_from_slice(signature.as_ref());

			// Generate output of requested length
			let mut output = [0u8; N];
			let hash = blake2_256(&combined);

			// For outputs larger than 32 bytes, hash iteratively
			if N <= 32 {
				output[..N].copy_from_slice(&hash[..N]);
			} else {
				let mut offset = 0;
				let mut counter = 0u32;
				while offset < N {
					let mut hash_input = combined.clone();
					hash_input.extend_from_slice(&counter.to_le_bytes());
					let chunk = blake2_256(&hash_input);
					let copy_len = (N - offset).min(32);
					output[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
					offset += copy_len;
					counter += 1;
				}
			}

			output
		}
	}

	impl Public {
		/// Generate output bytes from the given VRF configuration.
		///
		/// This verifies the VRF and produces deterministic output.
		pub fn make_bytes<const N: usize>(
			&self,
			context: &[u8],
			input: &VrfInput,
			pre_output: &VrfPreOutput,
		) -> Result<[u8; N], codec::Error>
		where
			[u8; N]: Default,
		{
			// Mix context and pre-output to derive final output
			use sp_crypto_hashing::blake2_256;
			let mut combined = context.to_vec();
			combined.extend_from_slice(&pre_output.0);
			combined.extend_from_slice(input.as_bytes());

			// Generate output of requested length
			let mut output = [0u8; N];
			let hash = blake2_256(&combined);

			if N <= 32 {
				output[..N].copy_from_slice(&hash[..N]);
			} else {
				let mut offset = 0;
				let mut counter = 0u32;
				while offset < N {
					let mut hash_input = combined.clone();
					hash_input.extend_from_slice(&counter.to_le_bytes());
					let chunk = blake2_256(&hash_input);
					let copy_len = (N - offset).min(32);
					output[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
					offset += copy_len;
					counter += 1;
				}
			}

			Ok(output)
		}
	}

	impl VrfPreOutput {
		/// Generate output bytes from the given VRF configuration.
		pub fn make_bytes<const N: usize>(
			&self,
			context: &[u8],
			input: &VrfInput,
			public: &Public,
		) -> Result<[u8; N], codec::Error>
		where
			[u8; N]: Default,
		{
			public.make_bytes(context, input, self)
		}
	}
}

// Re-export VRF types for convenience
pub use vrf::{VrfInput, VrfPreOutput, VrfProof, VrfSignData, VrfSignature, VrfTranscript};
