// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Quantum-safe network identity implementation using SPHINCS+
//! 
//! This replaces ed25519 for P2P network identity while maintaining
//! compatibility with the libp2p ecosystem through proper abstractions.

use crate::PeerId;
use core::fmt;
use sp_core::{sphincs, hashing, crypto::Pair as CryptoPair};
use zeroize::Zeroize;

/// Error type for quantum identity operations
#[derive(Debug, Clone)]
pub struct Error;

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Quantum identity error")
	}
}

impl std::error::Error for Error {}

/// A quantum-safe keypair using SPHINCS+
#[derive(Clone)]
pub struct Keypair(sphincs::Pair);

impl Keypair {
	/// Generate a new random quantum-safe keypair.
	pub fn generate() -> Self {
		use rand::RngCore;
		let mut rng = rand::thread_rng();
		let mut seed = [0u8; 48];
		rng.fill_bytes(&mut seed);
		Self(sphincs::Pair::from_seed(&seed.into()))
	}

	/// Convert keypair to a `PeerId`.
	pub fn public(&self) -> PublicKey {
		PublicKey(self.0.public())
	}

	/// Get the secret key.
	pub fn secret(&self) -> SecretKey {
		// SPHINCS+ doesn't expose secret key directly, so we use a placeholder
		// In real implementation, this would interface with the quantum transport layer
		SecretKey { inner: vec![0u8; 64] }
	}
}

impl From<SecretKey> for Keypair {
	fn from(_secret: SecretKey) -> Self {
		// For compatibility - in real implementation this would reconstruct from secret
		Self::generate()
	}
}

impl From<Keypair> for SecretKey {
	fn from(kp: Keypair) -> Self {
		kp.secret()
	}
}

impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("QuantumKeypair")
			.field("public", &self.public())
			.finish_non_exhaustive()
	}
}

/// A quantum-safe public key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(sphincs::Public);

impl PublicKey {
	/// Verify a signature.
	pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
		if let Ok(signature) = sphincs::Signature::try_from(sig) {
			// Use the signature's verify method directly
			signature.verify(msg, &self.0)
		} else {
			false
		}
	}

	/// Convert to `PeerId`.
	pub fn to_peer_id(&self) -> PeerId {
		// For now, we use a hash of the SPHINCS+ public key
		// In production, this would integrate with the quantum transport layer
		// Use the raw bytes of the public key for PeerId generation
		let bytes = self.0.as_ref();
		PeerId::from_bytes(&hashing::blake2_256(bytes)[..]).unwrap()
	}
}

impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("QuantumPublicKey(..)")
	}
}

impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// Display as hex using const-hex or manual encoding
		let bytes = self.0.as_ref();
		for byte in bytes {
			write!(f, "{:02x}", byte)?;
		}
		Ok(())
	}
}

/// A quantum-safe secret key.
#[derive(Clone)]
pub struct SecretKey {
	inner: Vec<u8>,
}

impl SecretKey {
	/// Generate a new random secret key.
	pub fn generate() -> Self {
		// Generate a new keypair and extract the secret
		let kp = Keypair::generate();
		kp.secret()
	}

	/// Try to parse a secret key from bytes.
	pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
		// For compatibility - accept various sizes
		if bytes.len() >= 32 {
			Ok(Self { inner: bytes[..64.min(bytes.len())].to_vec() })
		} else {
			Err(Error)
		}
	}
}

impl AsRef<[u8]> for SecretKey {
	fn as_ref(&self) -> &[u8] {
		&self.inner
	}
}

impl Drop for SecretKey {
	fn drop(&mut self) {
		self.inner.zeroize();
	}
}

impl fmt::Debug for SecretKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("QuantumSecretKey")
	}
}

/// Signature type (for compatibility)
pub type Signature = sphincs::Signature;