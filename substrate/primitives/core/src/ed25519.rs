// QUANTUM-SAFETY: Stub module for backward compatibility only
// This module exists only to prevent compilation errors during migration
// All verification will fail - use quantum-safe alternatives

use crate::crypto::{CryptoType, CryptoTypeId, Pair as TraitPair};
use crate::sphincs;

/// Ed25519 crypto type (stub only)
pub struct Ed25519Tag;

impl CryptoType for Ed25519Tag {
	type Pair = Pair;
}

/// Ed25519 public key (stub - uses SPHINCS+ internally)
pub type Public = sphincs::Public;

/// Ed25519 signature (stub - uses SPHINCS+ internally)
pub type Signature = sphincs::Signature;

/// Ed25519 key pair (stub - uses SPHINCS+ internally)
pub type Pair = sphincs::Pair;

/// Ed25519 crypto type identifier
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"ed25");