//! Quantum-safe signature implementation for Substrate
//!
//! This module provides quantum-resistant signature types that can replace
//! the quantum-vulnerable MultiSignature currently used throughout Substrate.

use crate::{crypto, ed25519, sr25519, ecdsa, sphincs};
use crate::crypto::{Pair as TraitPair, KeyTypeId};
use codec::{Decode, Encode, MaxEncodedLen, DecodeWithMemTracking};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A quantum-safe signature type that supports both legacy and post-quantum algorithms
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Hash))]
pub enum QuantumSignature {
    /// SPHINCS+ signature (post-quantum safe)
    Sphincs(sphincs::Signature),
    /// Legacy Ed25519 (for migration period)
    #[deprecated(note = "Ed25519 is not quantum-safe, migrate to SPHINCS+")]
    Ed25519(ed25519::Signature),
    /// Legacy Sr25519 (for migration period)
    #[deprecated(note = "Sr25519 is not quantum-safe, migrate to SPHINCS+")]
    Sr25519(sr25519::Signature),
    /// Legacy ECDSA (for migration period)
    #[deprecated(note = "ECDSA is not quantum-safe, migrate to SPHINCS+")]
    Ecdsa(ecdsa::Signature),
}

impl QuantumSignature {
    /// Verify the signature against a message and public key
    pub fn verify<M: AsRef<[u8]>>(&self, msg: M, signer: &QuantumPublic) -> bool {
        use QuantumSignature::*;
        match (self, signer) {
            (Sphincs(sig), QuantumPublic::Sphincs(public)) => {
                sig.verify(msg, public)
            },
            #[allow(deprecated)]
            (Ed25519(sig), QuantumPublic::Ed25519(public)) => {
                use crate::ed25519;
                ed25519::Pair::verify(sig, msg, public)
            },
            #[allow(deprecated)]
            (Sr25519(sig), QuantumPublic::Sr25519(public)) => {
                use crate::sr25519;
                sr25519::Pair::verify(sig, msg, public)
            },
            #[allow(deprecated)]
            (Ecdsa(sig), QuantumPublic::Ecdsa(public)) => {
                use crate::ecdsa;
                ecdsa::Pair::verify(sig, msg, public)
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
            #[allow(deprecated)]
            QuantumSignature::Ed25519(sig) => sig.0.len(),
            #[allow(deprecated)]
            QuantumSignature::Sr25519(sig) => sig.0.len(),
            #[allow(deprecated)]
            QuantumSignature::Ecdsa(sig) => sig.0.len(),
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
    /// Legacy Ed25519 (for migration period)
    #[deprecated(note = "Ed25519 is not quantum-safe, migrate to SPHINCS+")]
    Ed25519(ed25519::Public),
    /// Legacy Sr25519 (for migration period)
    #[deprecated(note = "Sr25519 is not quantum-safe, migrate to SPHINCS+")]
    Sr25519(sr25519::Public),
    /// Legacy ECDSA (for migration period)
    #[deprecated(note = "ECDSA is not quantum-safe, migrate to SPHINCS+")]
    Ecdsa(ecdsa::Public),
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
            #[allow(deprecated)]
            QuantumPublic::Ed25519(public) => {
                crypto::AccountId32::from(public.0)
            },
            #[allow(deprecated)]
            QuantumPublic::Sr25519(public) => {
                crypto::AccountId32::from(public.0)
            },
            #[allow(deprecated)]
            QuantumPublic::Ecdsa(public) => {
                // ECDSA public keys are 33 bytes, we need to hash to 32 bytes
                use crate::hashing::blake2_256;
                crypto::AccountId32::from(blake2_256(&public.0))
            },
        }
    }
    
    /// Get key type ID for the preferred quantum-safe algorithm
    pub const ID: KeyTypeId = sphincs::SPHINCS_CRYPTO_ID;
    
    /// Get the public key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        match self {
            QuantumPublic::Sphincs(public) => &public.0,
            #[allow(deprecated)]
            QuantumPublic::Ed25519(public) => &public.0,
            #[allow(deprecated)]
            QuantumPublic::Sr25519(public) => &public.0,
            #[allow(deprecated)]
            QuantumPublic::Ecdsa(public) => &public.0,
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
        
        // Try to decode as SPHINCS+ first (preferred)
        if data.len() == sphincs::SIGNATURE_LENGTH {
            let mut arr = [0u8; sphincs::SIGNATURE_LENGTH];
            arr.copy_from_slice(data);
            return Ok(QuantumSignature::Sphincs(sphincs::Signature(arr)));
        }
        
        // Fallback to legacy formats
        #[allow(deprecated)]
        match data.len() {
            64 => {
                // Both Ed25519 and Sr25519 are 64 bytes, try Sr25519 first
                if let Ok(sig) = sr25519::Signature::try_from(data) {
                    Ok(QuantumSignature::Sr25519(sig))
                } else if let Ok(sig) = ed25519::Signature::try_from(data) {
                    Ok(QuantumSignature::Ed25519(sig))
                } else {
                    Err(())
                }
            },
            65 => {
                let sig = ecdsa::Signature::try_from(data).map_err(|_| ())?;
                Ok(QuantumSignature::Ecdsa(sig))
            },
            _ => Err(()),
        }
    }
    
    /// Convert to inner signature bytes
    pub fn into_inner(self) -> Vec<u8> {
        match self {
            QuantumSignature::Sphincs(sig) => sig.0.to_vec(),
            #[allow(deprecated)]
            QuantumSignature::Ed25519(sig) => sig.0.to_vec(),
            #[allow(deprecated)]
            QuantumSignature::Sr25519(sig) => sig.0.to_vec(),
            #[allow(deprecated)]
            QuantumSignature::Ecdsa(sig) => sig.0.to_vec(),
        }
    }
}

impl QuantumPublic {
    /// Create from raw bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
        use crate::ByteArray;
        
        // Try to decode as SPHINCS+ first (preferred)
        if data.len() == sphincs::PUBLIC_KEY_LENGTH {
            let mut arr = [0u8; sphincs::PUBLIC_KEY_LENGTH];
            arr.copy_from_slice(data);
            return Ok(QuantumPublic::Sphincs(sphincs::Public(arr)));
        }
        
        // Fallback to legacy formats
        #[allow(deprecated)]
        match data.len() {
            32 => {
                // Could be Ed25519 or Sr25519, default to Sr25519 for compatibility
                let key = sr25519::Public::try_from(data).map_err(|_| ())?;
                Ok(QuantumPublic::Sr25519(key))
            },
            33 => {
                let key = ecdsa::Public::try_from(data).map_err(|_| ())?;
                Ok(QuantumPublic::Ecdsa(key))
            },
            _ => Err(()),
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
            #[allow(deprecated)]
            QuantumSignature::Ed25519(_) => write!(f, "QuantumSignature::Ed25519"),
            #[allow(deprecated)]
            QuantumSignature::Sr25519(_) => write!(f, "QuantumSignature::Sr25519"),
            #[allow(deprecated)]
            QuantumSignature::Ecdsa(_) => write!(f, "QuantumSignature::Ecdsa"),
        }
    }
}

impl sp_std::fmt::Debug for QuantumPublic {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            QuantumPublic::Sphincs(_) => write!(f, "QuantumPublic::Sphincs"),
            #[allow(deprecated)]
            QuantumPublic::Ed25519(_) => write!(f, "QuantumPublic::Ed25519"),
            #[allow(deprecated)]
            QuantumPublic::Sr25519(_) => write!(f, "QuantumPublic::Sr25519"),
            #[allow(deprecated)]
            QuantumPublic::Ecdsa(_) => write!(f, "QuantumPublic::Ecdsa"),
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
        // 1 byte for enum variant + max public key size
        1 + 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn quantum_signature_is_quantum_safe() {
        let sphincs_sig = QuantumSignature::Sphincs(Default::default());
        assert!(sphincs_sig.is_quantum_safe());
        
        #[allow(deprecated)]
        let ed25519_sig = QuantumSignature::Ed25519(Default::default());
        assert!(!ed25519_sig.is_quantum_safe());
    }
}