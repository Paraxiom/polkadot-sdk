// QUANTUM-SAFETY: Stub module for backward compatibility only
// This module exists only to prevent compilation errors during migration
// All verification will fail - use quantum-safe alternatives

use crate::crypto::{CryptoType, CryptoTypeId, Pair as TraitPair};
use crate::sphincs;

/// Sr25519 crypto type (stub only)
pub struct Sr25519Tag;

impl CryptoType for Sr25519Tag {
	type Pair = Pair;
}

/// Sr25519 public key (stub - uses SPHINCS+ internally)
pub type Public = sphincs::Public;

/// Sr25519 signature (stub - uses SPHINCS+ internally)
pub type Signature = sphincs::Signature;

/// Sr25519 key pair (stub - uses SPHINCS+ internally)
pub type Pair = sphincs::Pair;

/// Sr25519 crypto type identifier
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sr25");