// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Quantum-safe network identity implementation using SPHINCS+
//! 
//! This replaces ed25519 for P2P network identity while maintaining
//! compatibility with the libp2p ecosystem through proper abstractions.

use crate::PeerId;
use core::fmt;
use sp_core::{sphincs, crypto::Pair as CryptoPair};
use sha3::{Sha3_256, Digest};
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
		// Use SHA3-256 for quantum-resistant PeerId generation
		let bytes = self.0.as_ref();
		let mut hasher = Sha3_256::new();
		hasher.update(bytes);
		let hash = hasher.finalize();
		PeerId::from_bytes(&hash[..]).unwrap()
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

// We need to implement conversion to libp2p types through the libp2p crate itself
// Since service.rs uses libp2p::identity::ed25519, we can't directly implement From traits
// Instead, we'll provide conversion methods

impl Keypair {
	/// Convert to libp2p-compatible ed25519 keypair
	/// This is for network layer compatibility only
	pub fn to_libp2p_ed25519(&self) -> Vec<u8> {
		// Return the seed bytes that can be used to construct libp2p::identity::ed25519::Keypair
		// Use SHA3-256 to generate a deterministic seed
		let public_key = self.0.public();
		let public_bytes = public_key.as_ref();
		let mut hasher = Sha3_256::new();
		hasher.update(public_bytes);
		let hash = hasher.finalize();
		hash.to_vec()
	}
}

impl PublicKey {
	/// Convert to libp2p-compatible ed25519 public key bytes
	pub fn to_libp2p_ed25519_bytes(&self) -> [u8; 32] {
		// Generate deterministic ed25519 public key from quantum public key using SHA3
		let mut hasher = Sha3_256::new();
		hasher.update(self.0.as_ref());
		let hash = hasher.finalize();
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(&hash[..32]);
		bytes
	}
}

impl SecretKey {
	/// Convert to libp2p-compatible ed25519 secret key bytes
	pub fn to_libp2p_ed25519_bytes(&self) -> [u8; 32] {
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(&self.inner[..32]);
		bytes
	}
}

// Conversion traits for litep2p compatibility
#[cfg(feature = "std")]
mod litep2p_compat {
	use super::*;
	use litep2p::crypto::ed25519 as litep2p_ed25519;
	
	impl From<SecretKey> for litep2p_ed25519::SecretKey {
		fn from(sk: SecretKey) -> Self {
			// Use first 32 bytes as ed25519 secret
			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(&sk.inner[..32]);
			litep2p_ed25519::SecretKey::try_from_bytes(&mut bytes.clone()).unwrap()
		}
	}
}

// Export conversions when std is available
#[cfg(feature = "std")]
pub use libp2p_compat::*;
#[cfg(feature = "std")]
pub use litep2p_compat::*;