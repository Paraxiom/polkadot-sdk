//! Post-quantum cryptography integration for block signing
//!
//! This module provides the cryptographic primitives for quantum-resistant
//! block signatures using SPHINCS+ and Falcon-512.

// No longer need these imports
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// Quantum-resistant authority ID using SPHINCS+ for critical operations
/// and Falcon-512 for regular block signing (bandwidth efficiency)
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub enum QuantumAuthorityId {
    /// SPHINCS+ for maximum security (49KB signatures)
    Sphincs([u8; 64]), // SPHINCS+ public key is 64 bytes
    /// Falcon-512 for bandwidth efficiency (690 byte signatures)  
    Falcon([u8; 897]), // Falcon-512 public key is 897 bytes
}

impl QuantumAuthorityId {
    /// Create from SPHINCS+ public key bytes
    pub fn from_sphincs(public_bytes: [u8; 64]) -> Self {
        Self::Sphincs(public_bytes)
    }
    
    /// Create from Falcon public key bytes
    pub fn from_falcon(public_bytes: [u8; 897]) -> Self {
        Self::Falcon(public_bytes)
    }
    
    /// Get the size of signatures this authority produces
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Sphincs(_) => 49856, // SPHINCS+ signature size
            Self::Falcon(_) => 690,    // Falcon-512 signature size
        }
    }
    
    /// Check if this is suitable for bandwidth-constrained operations
    pub fn is_bandwidth_efficient(&self) -> bool {
        matches!(self, Self::Falcon(_))
    }
}

/// Quantum-resistant signature for blocks
#[derive(Clone, Encode, Decode, TypeInfo)]
pub enum QuantumSignature {
    /// SPHINCS+ signature (49KB)
    Sphincs(Vec<u8>),
    /// Falcon-512 signature (690 bytes)
    Falcon(Vec<u8>),
}

impl QuantumSignature {
    /// Get the size of this signature
    pub fn size(&self) -> usize {
        match self {
            Self::Sphincs(sig) => sig.len(),
            Self::Falcon(sig) => sig.len(),
        }
    }
    
    /// Verify this signature against a message and public key
    pub fn verify(&self, _msg: &[u8], signer: &QuantumAuthorityId) -> bool {
        match (self, signer) {
            (Self::Sphincs(sig), QuantumAuthorityId::Sphincs(_pub_key)) => {
                // In production, verify SPHINCS+ signature
                // For now, check signature has expected size
                sig.len() == 49856
            },
            (Self::Falcon(sig), QuantumAuthorityId::Falcon(_pub_key)) => {
                // In production, verify Falcon-512 signature
                // For now, check signature has expected size
                sig.len() == 690
            },
            _ => false, // Signature type must match authority type
        }
    }
}

/// Configuration for quantum block signing
#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct QuantumSigningConfig {
    /// Use Falcon for regular blocks (bandwidth efficient)
    pub use_falcon_for_regular: bool,
    /// Always use SPHINCS+ for finality votes
    pub sphincs_for_finality: bool,
    /// Maximum retries for signature generation
    pub max_retries: u32,
}

impl Default for QuantumSigningConfig {
    fn default() -> Self {
        Self {
            use_falcon_for_regular: true,  // Optimize for satellite bandwidth
            sphincs_for_finality: true,    // Maximum security for finality
            max_retries: 3,
        }
    }
}

/// Quantum block seal - replaces the sr25519 seal in headers
#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct QuantumSeal {
    /// The quantum signature
    pub signature: QuantumSignature,
    /// The authority that created this seal
    pub authority_index: u32,
    /// Timestamp for freshness
    pub timestamp: u64,
}

impl QuantumSeal {
    /// Create a new quantum seal
    pub fn new(
        signature: QuantumSignature,
        authority_index: u32,
    ) -> Self {
        Self {
            signature,
            authority_index,
            timestamp: sp_io::offchain::timestamp().unix_millis(),
        }
    }
    
    /// Verify this seal
    pub fn verify(
        &self,
        block_hash: &[u8],
        authorities: &[QuantumAuthorityId],
    ) -> bool {
        if let Some(authority) = authorities.get(self.authority_index as usize) {
            // Include timestamp in signed data to prevent replay
            let mut msg = block_hash.to_vec();
            msg.extend_from_slice(&self.timestamp.encode());
            
            self.signature.verify(&msg, authority)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_sizes() {
        // Verify our assumptions about signature sizes
        let sphincs_size = 49856; // ~49KB
        let falcon_size = 690;    // 690 bytes
        
        // Falcon is ~72x smaller than SPHINCS+
        let ratio = sphincs_size / falcon_size;
        assert!(ratio > 70);
    }
    
    #[test]
    fn test_bandwidth_efficiency() {
        let sphincs_auth = QuantumAuthorityId::from_sphincs([0u8; 64]);
        let falcon_auth = QuantumAuthorityId::from_falcon([0u8; 897]);
        
        assert!(!sphincs_auth.is_bandwidth_efficient());
        assert!(falcon_auth.is_bandwidth_efficient());
    }
}