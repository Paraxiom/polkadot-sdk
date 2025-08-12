// QUANTUM-SAFETY: Stub module for backward compatibility only
// This module exists only to prevent compilation errors during migration
// All verification will fail - use quantum-safe alternatives

use crate::crypto::{CryptoType, CryptoTypeId, Pair as TraitPair};
use crate::sphincs;

/// ECDSA crypto type (stub only)
pub struct EcdsaTag;

impl CryptoType for EcdsaTag {
	type Pair = Pair;
}

/// ECDSA public key (stub - uses SPHINCS+ internally)
pub type Public = sphincs::Public;

/// ECDSA signature (stub - uses SPHINCS+ internally)
pub type Signature = sphincs::Signature;

/// ECDSA key pair (stub - uses SPHINCS+ internally)
pub type Pair = sphincs::Pair;

/// ECDSA crypto type identifier
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"ecds");