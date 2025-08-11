//! Quantum-safe signature implementation for Substrate
//!
//! This module provides quantum-resistant signature types that can replace
//! the quantum-vulnerable MultiSignature currently used throughout Substrate.

use crate::{crypto, sphincs};
use crate::crypto::KeyTypeId;
use codec::{Decode, Encode, MaxEncodedLen, DecodeWithMemTracking};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A quantum-safe signature type that only supports post-quantum algorithms
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Hash))]
pub enum QuantumSignature {
    /// SPHINCS+ signature (post-quantum safe)
    Sphincs(sphincs::Signature),
}

impl QuantumSignature {
    /// Verify the signature against a message and public key
    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, signer: &QuantumPublic) -> bool {
        use QuantumSignature::*;
        match (self, signer) {
            (Sphincs(sig), QuantumPublic::Sphincs(public)) => {
                sig.verify(msg, public)
            },
            _ => false, // Mismatched signature/public key types
        }
    }
    
    /// Check if this signature uses quantum-safe cryptography
    pub fn is_quantum_safe(&self) -> bool {
        matches!(self, QuantumSignature::Sphincs(_))
    }
    
    /// Get the size of the signature in bytes
    pub fn size(&self) -> usize {
        match self {
            QuantumSignature::Sphincs(sig) => sig.0.len(),
        }
    }
}

/// A quantum-safe public key type
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Hash))]
pub enum QuantumPublic {
    /// SPHINCS+ public key (post-quantum safe)
    Sphincs(sphincs::Public),
}

impl QuantumPublic {
    /// Convert to AccountId32
    pub fn to_account_id(&self) -> crypto::AccountId32 {
        match self {
            QuantumPublic::Sphincs(public) => {
                // SPHINCS+ public keys are 64 bytes, we need to hash to 32 bytes
                use crate::hashing::blake2_256;
                crypto::AccountId32::from(blake2_256(&public.0))
            },
        }
    }
    
    /// Get key type ID for the preferred quantum-safe algorithm
    pub const ID: KeyTypeId = KeyTypeId(*b"sphn");
    
    /// Get the public key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        match self {
            QuantumPublic::Sphincs(public) => &public.0,
        }
    }
}

/// A quantum-safe signer type (for trait bounds)
pub type QuantumSigner = QuantumPublic;

impl AsRef<[u8]> for QuantumPublic {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl QuantumSignature {
    /// Create from raw bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        use crate::ByteArray;
        
        // Only decode as SPHINCS+
        if data.len() == sphincs::SIGNATURE_LENGTH {
            let mut arr = [0u8; sphincs::SIGNATURE_LENGTH];
            arr.copy_from_slice(data);
            Ok(QuantumSignature::Sphincs(sphincs::Signature(arr)))
        } else {
            Err(())
        }
    }
    
    /// Convert to inner signature bytes
    pub fn into_inner(self) -> Vec<u8> {
        match self {
            QuantumSignature::Sphincs(sig) => sig.0.to_vec(),
        }
    }
}

impl QuantumPublic {
    /// Create from raw bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        use crate::ByteArray;
        
        // Only decode as SPHINCS+
        if data.len() == sphincs::PUBLIC_KEY_LENGTH {
            let mut arr = [0u8; sphincs::PUBLIC_KEY_LENGTH];
            arr.copy_from_slice(data);
            Ok(QuantumPublic::Sphincs(sphincs::Public(arr)))
        } else {
            Err(())
        }
    }
}

// Implement signing methods for QuantumPublic
impl QuantumPublic {
    /// Sign a message (requires access to private key through keystore)
    pub fn sign<M: AsRef<[u8]>>(&self, msg: &M) -> Option<QuantumSignature> {
        // This would require access to the private key, which public keys don't have
        // In practice, signing is done through the keystore
        None
    }
    
    /// Verify a signature
    pub fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &QuantumSignature) -> bool {
        signature.verify(msg, self)
    }
}

impl sp_std::fmt::Debug for QuantumSignature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            QuantumSignature::Sphincs(_) => write!(f, "QuantumSignature::Sphincs"),
        }
    }
}

impl sp_std::fmt::Debug for QuantumPublic {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            QuantumPublic::Sphincs(_) => write!(f, "QuantumPublic::Sphincs"),
        }
    }
}

// MaxEncodedLen implementation
impl MaxEncodedLen for QuantumSignature {
    fn max_encoded_len() -> usize {
        // 1 byte for enum variant + max signature size (SPHINCS+ is largest at 49,856 bytes)
        1 + 49_856
    }
}

impl MaxEncodedLen for QuantumPublic {
    fn max_encoded_len() -> usize {
        // 1 byte for enum variant + SPHINCS+ public key size (64 bytes)
        1 + 64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn quantum_signature_is_quantum_safe() {
        let sphincs_sig = QuantumSignature::Sphincs(sphincs::Signature([0u8; 8192]));
        assert!(sphincs_sig.is_quantum_safe());
    }
}