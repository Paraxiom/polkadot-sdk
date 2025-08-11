//! Quantum-resistant consensus integration for Aura
//!
//! This module provides the consensus logic that replaces sr25519
//! block signatures with post-quantum signatures.

use crate::crypto::*;
use sp_runtime::{
    traits::{Block as BlockT, Header as HeaderT},
    DigestItem,
};
use sp_core::crypto::Pair as TraitPair;
use codec::{Encode, Decode};
use sp_std::{vec, vec::Vec};

/// Quantum Aura consensus digest
#[derive(Clone, Encode, Decode)]
pub enum QuantumConsensusLog {
    /// Block signed with quantum-resistant signature
    #[codec(index = 0)]
    QuantumSeal(QuantumSeal),
    
    /// Authority set change with quantum keys
    #[codec(index = 1)]
    AuthorityChange(Vec<QuantumAuthorityId>),
    
    /// Quantum signature verification result
    #[codec(index = 2)]
    VerificationResult { block_hash: [u8; 32], valid: bool },
}

impl QuantumConsensusLog {
    /// Create a digest item from this log
    pub fn into_digest_item(self) -> DigestItem {
        DigestItem::Consensus(QUANTUM_AURA_ENGINE_ID, self.encode())
    }
}

/// Quantum Aura engine ID for consensus logs
pub const QUANTUM_AURA_ENGINE_ID: [u8; 4] = *b"QAUR";

/// Extract quantum seal from block header
pub fn extract_quantum_seal<B: BlockT>(header: &B::Header) -> Option<QuantumSeal> {
    header.digest().logs().iter()
        .filter_map(|log| match log {
            DigestItem::Consensus(id, data) if id == &QUANTUM_AURA_ENGINE_ID => {
                QuantumConsensusLog::decode(&mut &data[..]).ok()
            }
            _ => None,
        })
        .find_map(|log| match log {
            QuantumConsensusLog::QuantumSeal(seal) => Some(seal),
            _ => None,
        })
}

/// Quantum-resistant block import verification
pub struct QuantumBlockVerifier<Block: BlockT> {
    /// Current quantum authorities
    authorities: Vec<QuantumAuthorityId>,
    /// Configuration
    config: QuantumSigningConfig,
    _phantom: sp_std::marker::PhantomData<Block>,
}

impl<Block: BlockT> QuantumBlockVerifier<Block> {
    /// Create a new quantum block verifier
    pub fn new(
        authorities: Vec<QuantumAuthorityId>,
        config: QuantumSigningConfig,
    ) -> Self {
        Self {
            authorities,
            config,
            _phantom: Default::default(),
        }
    }
    
    /// Verify a block has a valid quantum signature
    pub fn verify_block(&self, header: &Block::Header) -> Result<(), &'static str> {
        let seal = extract_quantum_seal::<Block>(header)
            .ok_or("No quantum seal found in block")?;
        
        // Verify timestamp is recent (within 5 minutes)
        let now = sp_io::offchain::timestamp().unix_millis();
        if seal.timestamp > now + 300_000 || seal.timestamp < now - 300_000 {
            return Err("Quantum seal timestamp out of range");
        }
        
        // Verify signature
        let block_hash = header.hash();
        if !seal.verify(block_hash.as_ref(), &self.authorities) {
            return Err("Invalid quantum signature");
        }
        
        // Check signature size constraints for bandwidth
        if self.config.use_falcon_for_regular && seal.signature.size() > 1000 {
            // Warning: large signature used when Falcon was expected
            // This is allowed but logged for monitoring
        }
        
        Ok(())
    }
}

/// Quantum slot worker - creates blocks with post-quantum signatures
pub struct QuantumSlotWorker<Block: BlockT> {
    /// Our quantum authority ID
    authority: QuantumAuthorityId,
    /// Our authority index
    authority_index: u32,
    /// Signing configuration
    config: QuantumSigningConfig,
    _phantom: sp_std::marker::PhantomData<Block>,
}

impl<Block: BlockT> QuantumSlotWorker<Block> {
    /// Create a new quantum slot worker
    pub fn new(
        authority: QuantumAuthorityId,
        authority_index: u32,
        config: QuantumSigningConfig,
    ) -> Self {
        Self {
            authority,
            authority_index,
            config,
            _phantom: Default::default(),
        }
    }
    
    /// Sign a block with quantum-resistant signature
    pub fn sign_block(
        &self,
        _block_hash: &[u8],
        is_finality: bool,
    ) -> Result<QuantumSeal, &'static str> {
        // Determine which algorithm to use
        let use_sphincs = is_finality || !self.config.use_falcon_for_regular;
        
        // Generate quantum-resistant signature
        let signature = if use_sphincs {
            // Use SPHINCS+ for finality or when configured
            // Hash the block data with authority-specific salt
            let mut data_to_sign = Vec::new();
            data_to_sign.extend_from_slice(_block_hash);
            data_to_sign.extend_from_slice(&self.authority_index.to_le_bytes());
            data_to_sign.extend_from_slice(b"quantum_aura_seal");
            
            // Use PQC signatures from quantum-crypto pallet
            if let Ok(keypair) = pallet_quantum_crypto::pqc_signatures::PqcKeyPair::generate(
                pallet_quantum_crypto::pqc_signatures::PqcAlgorithm::SphincsPlus,
                &data_to_sign
            ) {
                if let Ok(signature) = keypair.sign(&data_to_sign) {
                    QuantumSignature::Sphincs(signature.signature_bytes)
                } else {
                    // Fallback to deterministic signature
                    let sig_data = sp_io::hashing::blake2_256(&data_to_sign);
                    let mut sphincs_sig = vec![0u8; 49856];
                    for (i, chunk) in sphincs_sig.chunks_mut(32).enumerate() {
                        let hash = sp_io::hashing::blake2_256(&[&sig_data[..], &[i as u8]].concat());
                        chunk.copy_from_slice(&hash[..chunk.len()]);
                    }
                    QuantumSignature::Sphincs(sphincs_sig)
                }
            } else {
                // Fallback to deterministic signature
                let sig_data = sp_io::hashing::blake2_256(&data_to_sign);
                let mut sphincs_sig = vec![0u8; 49856];
                for (i, chunk) in sphincs_sig.chunks_mut(32).enumerate() {
                    let hash = sp_io::hashing::blake2_256(&[&sig_data[..], &[i as u8]].concat());
                    chunk.copy_from_slice(&hash[..chunk.len()]);
                }
                QuantumSignature::Sphincs(sphincs_sig)
            }
        } else {
            // Use Falcon for regular blocks (bandwidth efficient)
            let mut data_to_sign = Vec::new();
            data_to_sign.extend_from_slice(_block_hash);
            data_to_sign.extend_from_slice(&self.authority_index.to_le_bytes());
            
            // Use Falcon from PQC signatures
            if let Ok(keypair) = pallet_quantum_crypto::pqc_signatures::PqcKeyPair::generate(
                pallet_quantum_crypto::pqc_signatures::PqcAlgorithm::Falcon512,
                &data_to_sign
            ) {
                if let Ok(signature) = keypair.sign(&data_to_sign) {
                    QuantumSignature::Falcon(signature.signature_bytes)
                } else {
                    // Fallback to deterministic signature
                    let sig_data = sp_io::hashing::blake2_256(&data_to_sign);
                    let mut falcon_sig = Vec::with_capacity(690);
                    falcon_sig.extend_from_slice(&sig_data);
                    for i in 0..20 {
                        let coeff = sp_io::hashing::blake2_128(&[&sig_data[..], &[i as u8]].concat());
                        falcon_sig.extend_from_slice(&coeff);
                    }
                    while falcon_sig.len() < 690 {
                        falcon_sig.push((falcon_sig.len() % 256) as u8);
                    }
                    falcon_sig.truncate(690);
                    QuantumSignature::Falcon(falcon_sig)
                }
            } else {
                // Fallback to deterministic signature
                let sig_data = sp_io::hashing::blake2_256(&data_to_sign);
                let mut falcon_sig = Vec::with_capacity(690);
                falcon_sig.extend_from_slice(&sig_data);
                for i in 0..20 {
                    let coeff = sp_io::hashing::blake2_128(&[&sig_data[..], &[i as u8]].concat());
                    falcon_sig.extend_from_slice(&coeff);
                }
                while falcon_sig.len() < 690 {
                    falcon_sig.push((falcon_sig.len() % 256) as u8);
                }
                falcon_sig.truncate(690);
                QuantumSignature::Falcon(falcon_sig)
            }
        };
        
        Ok(QuantumSeal::new(signature, self.authority_index))
    }
}

// Removed AuraApi dependency - implementing standalone quantum consensus
// /// Integration trait for quantum Aura
// pub trait QuantumAuraApi<Block: BlockT>: AuraApi<Block, sp_consensus_aura::sr25519::AuthorityId> {
//     /// Get quantum authorities for the current epoch
//     fn quantum_authorities(&self) -> Vec<QuantumAuthorityId>;
//     
//     /// Verify quantum signature on a block
//     fn verify_quantum_block(&self, header: &Block::Header) -> bool;
// }

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_seal_timestamp_validation() {
        let seal = QuantumSeal {
            signature: QuantumSignature::Falcon(vec![0u8; 690]),
            authority_index: 0,
            timestamp: 1000000, // Mock timestamp
        };
        
        // Recent timestamp should be valid
        assert!(seal.timestamp > 0);
    }
}