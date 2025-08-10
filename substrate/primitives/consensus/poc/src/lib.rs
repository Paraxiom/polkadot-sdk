#![cfg_attr(not(feature = "std"), no_std)]

//! Proof of Coherence (PoC) consensus mechanism
//! 
//! This implements a quantum-based consensus for democracy where:
//! - Authority is based on hardware investment (QKD devices)
//! - Quantum coherence measurements determine block validity
//! - No token staking required

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::traits::Block as BlockT;
use sp_std::vec::Vec;

/// Proof of Coherence digest item
#[derive(Decode, Encode, Clone, PartialEq, Eq, TypeInfo)]
pub struct PoCDigest {
    /// Quantum coherence measurement
    pub coherence_value: u32,
    /// QKD device MAC address that produced this measurement
    pub device_mac: [u8; 6],
    /// QBER at time of measurement
    pub qber: u32,
    /// Entropy bits used
    pub entropy_consumed: u32,
}

/// Authority information for PoC consensus
#[derive(Decode, Encode, Clone, PartialEq, Eq, TypeInfo)]
pub struct PoCAuthority {
    /// Account ID of the hardware operator
    pub operator: Vec<u8>,
    /// Total QKD devices operated
    pub device_count: u32,
    /// Authority weight (based on hardware contribution)
    pub weight: u32,
}

/// Proof of Coherence configuration
pub trait PoCConfig {
    /// Minimum coherence value required for valid blocks
    const MIN_COHERENCE: u32;
    
    /// Maximum QBER allowed during consensus
    const MAX_QBER: u32;
    
    /// Minimum entropy required per block
    const MIN_ENTROPY_PER_BLOCK: u32;
}

/// Default PoC configuration
pub struct DefaultPoCConfig;

impl PoCConfig for DefaultPoCConfig {
    const MIN_COHERENCE: u32 = 700; // 70%
    const MAX_QBER: u32 = 110; // 11%
    const MIN_ENTROPY_PER_BLOCK: u32 = 256; // bits
}

/// Verify Proof of Coherence
pub fn verify_poc<B: BlockT, C: PoCConfig>(
    block: &B,
    poc_digest: &PoCDigest,
) -> Result<(), VerificationError> {
    // Check coherence threshold
    if poc_digest.coherence_value < C::MIN_COHERENCE {
        return Err(VerificationError::InsufficientCoherence);
    }
    
    // Check QBER
    if poc_digest.qber > C::MAX_QBER {
        return Err(VerificationError::QBERTooHigh);
    }
    
    // Check entropy
    if poc_digest.entropy_consumed < C::MIN_ENTROPY_PER_BLOCK {
        return Err(VerificationError::InsufficientEntropy);
    }
    
    Ok(())
}

/// PoC verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Coherence value below threshold
    InsufficientCoherence,
    /// QBER too high (possible eavesdropping)
    QBERTooHigh,
    /// Not enough quantum entropy used
    InsufficientEntropy,
}

/// Calculate authority weight based on hardware contribution
pub fn calculate_authority_weight(
    device_count: u32,
    total_entropy_contributed: u128,
    reliability_score: u32,
) -> u32 {
    // Weight formula:
    // 40% device count
    // 30% entropy contribution  
    // 30% reliability
    let device_weight = device_count * 400;
    let entropy_weight = ((total_entropy_contributed / 1000) as u32).min(3000);
    let reliability_weight = reliability_score * 3 / 10;
    
    device_weight + entropy_weight + reliability_weight
}

/// Select next block producer based on quantum randomness and hardware weights
pub fn select_block_producer(
    authorities: &[PoCAuthority],
    quantum_random: &[u8; 32],
) -> Option<usize> {
    if authorities.is_empty() {
        return None;
    }
    
    // Calculate total weight
    let total_weight: u32 = authorities.iter().map(|a| a.weight).sum();
    if total_weight == 0 {
        return None;
    }
    
    // Use quantum randomness to select
    let random_value = u32::from_le_bytes([
        quantum_random[0],
        quantum_random[1], 
        quantum_random[2],
        quantum_random[3],
    ]);
    
    let target = random_value % total_weight;
    let mut accumulated = 0u32;
    
    for (idx, authority) in authorities.iter().enumerate() {
        accumulated += authority.weight;
        if accumulated > target {
            return Some(idx);
        }
    }
    
    None
}