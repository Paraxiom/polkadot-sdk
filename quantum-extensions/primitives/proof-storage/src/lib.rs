//! Proof storage primitives
//! 
//! Defines how STARK proofs are stored on-chain vs off-chain

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

/// On-chain proof record (minimal storage)
#[derive(Encode, Decode, TypeInfo, RuntimeDebug, Clone, PartialEq, Eq, MaxEncodedLen)]
pub struct OnChainProofRecord {
    /// Hash of the full proof
    pub proof_hash: H256,
    
    /// Hash of public witness
    pub public_witness_hash: H256,
    
    /// Verifier signature (if verified off-chain)
    pub verifier_signature: Option<[u8; 64]>,
    
    /// Block number when proof was submitted
    pub block_number: u32,
    
    /// Type of proof
    pub proof_type: u8,
}

/// Proof availability status
#[derive(Encode, Decode, TypeInfo, RuntimeDebug, Clone, Copy, PartialEq, Eq, MaxEncodedLen)]
pub enum ProofAvailability {
    /// Proof is available in archive nodes
    Available,
    
    /// Proof is being fetched
    Fetching,
    
    /// Proof is not available
    NotAvailable,
    
    /// Proof has expired
    Expired,
}

/// Trait for proof storage backends
pub trait ProofStorage {
    /// Store a proof and return its ID
    fn store_proof(&mut self, proof: &[u8]) -> Result<H256, &'static str>;
    
    /// Retrieve a proof by ID
    fn get_proof(&self, proof_id: &H256) -> Option<Vec<u8>>;
    
    /// Check if proof is available
    fn is_available(&self, proof_id: &H256) -> ProofAvailability;
    
    /// Remove expired proofs
    fn cleanup_expired(&mut self, current_block: u32);
}