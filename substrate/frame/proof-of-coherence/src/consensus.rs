//! Consensus integration for Proof of Coherence
//! 
//! This module implements the 6-factor scoring system and integrates it with block production.
//! The 6 factors are:
//! 1. Photon Coherence Time - Measured via QBER from QKD
//! 2. Tonnetz Harmonic Validation - Musical theory-based network coherence
//! 3. Modified Merkle Trees - Quantum-safe merkle proofs
//! 4. QPP Compliance - Quantum Pair Protocol adherence
//! 5. Governance Votes - Community consensus weight
//! 6. Combined Coherence Score - Weighted average of all factors

use crate::*;
use frame_support::traits::{Currency, Get};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_std::vec::Vec;
use codec::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::SaturatedConversion;
use sp_core::H256;

/// Weight configuration for the 6-factor scoring system
pub struct ScoringWeights {
    pub photon_coherence: u32,      // Weight: 25%
    pub tonnetz_harmonic: u32,       // Weight: 20%
    pub merkle_validation: u32,      // Weight: 15%
    pub qpp_compliance: u32,         // Weight: 20%
    pub governance_votes: u32,       // Weight: 10%
    pub combined_coherence: u32,     // Weight: 10%
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            photon_coherence: 25,
            tonnetz_harmonic: 20,
            merkle_validation: 15,
            qpp_compliance: 20,
            governance_votes: 10,
            combined_coherence: 10,
        }
    }
}

/// Complete coherence score with all 6 factors
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct CoherenceScore {
    /// Factor 1: Photon Coherence Time (0-100)
    pub photon_coherence_time: u8,
    
    /// Factor 2: Tonnetz Harmonic Validation (0-100)
    pub tonnetz_harmonic_validation: u8,
    
    /// Factor 3: Modified Merkle Trees validation (0-100)
    pub modified_merkle_trees: u8,
    
    /// Factor 4: QPP Compliance score (0-100)
    pub qpp_compliance: u8,
    
    /// Factor 5: Governance Votes weight (0-100)
    pub governance_votes: u8,
    
    /// Factor 6: Combined Coherence Score (0-100)
    pub combined_coherence_score: u8,
    
    /// Total weighted score (0-10000 for precision)
    pub total_score: u32,
    
    /// QBER measurement that influenced the score
    pub qber: u32,
    
    /// Block number when calculated
    pub block_number: u32,
}

impl<T: Config> Pallet<T> {
    /// Calculate the complete 6-factor coherence score for a validator
    pub fn calculate_six_factor_score(
        validator: &T::AccountId,
        qber: u32,
    ) -> Result<CoherenceScore, Error<T>> {
        // Factor 1: Photon Coherence Time - derived from QBER
        let photon_coherence_time = Self::calculate_photon_coherence(qber);
        
        // Factor 2: Tonnetz Harmonic Validation
        let tonnetz_harmonic = Self::calculate_tonnetz_harmonic(validator)?;
        
        // Factor 3: Modified Merkle Trees
        let merkle_validation = Self::calculate_merkle_validation(validator)?;
        
        // Factor 4: QPP Compliance
        let qpp_compliance = Self::calculate_qpp_compliance(validator)?;
        
        // Factor 5: Governance Votes
        let governance_votes = Self::calculate_governance_weight(validator);
        
        // Factor 6: Combined previous coherence history
        let combined_coherence = Self::calculate_combined_coherence(validator);
        
        // Calculate weighted total with precision
        let weights = ScoringWeights::default();
        let total_score = (
            photon_coherence_time as u32 * weights.photon_coherence +
            tonnetz_harmonic as u32 * weights.tonnetz_harmonic +
            merkle_validation as u32 * weights.merkle_validation +
            qpp_compliance as u32 * weights.qpp_compliance +
            governance_votes as u32 * weights.governance_votes +
            combined_coherence as u32 * weights.combined_coherence
        );
        
        Ok(CoherenceScore {
            photon_coherence_time,
            tonnetz_harmonic_validation: tonnetz_harmonic,
            modified_merkle_trees: merkle_validation,
            qpp_compliance,
            governance_votes,
            combined_coherence_score: combined_coherence,
            total_score,
            qber,
            block_number: frame_system::Pallet::<T>::block_number().saturated_into(),
        })
    }
    
    /// Factor 1: Calculate photon coherence time from QBER
    fn calculate_photon_coherence(qber: u32) -> u8 {
        // QBER thresholds:
        // 0-1% = Excellent coherence (score 90-100)
        // 1-3% = Good coherence (score 70-90)
        // 3-6% = Acceptable coherence (score 50-70)
        // 6-11% = Poor coherence (score 20-50)
        // >11% = No coherence (score 0-20)
        
        match qber {
            0..=100 => 100,           // 0-1% QBER
            101..=300 => (90 - (qber - 100) / 10) as u8,  // 1-3% QBER
            301..=600 => (70 - (qber - 300) / 15) as u8,  // 3-6% QBER
            601..=1100 => (50 - (qber - 600) / 16) as u8, // 6-11% QBER
            _ => 0,                   // >11% QBER - insecure
        }
    }
    
    /// Factor 2: Calculate Tonnetz harmonic validation
    fn calculate_tonnetz_harmonic(validator: &T::AccountId) -> Result<u8, Error<T>> {
        // Get network harmonic state
        let harmonic_state = NetworkHarmonicState::<T>::get();
        
        // Check if validator's frequency is in harmonic relationship
        if let Some(proof) = CoherenceProofs::<T>::get(validator) {
            // Calculate harmonic intervals (perfect fifth, major third, etc.)
            let fundamental = harmonic_state.fundamental_frequency;
            let validator_freq = proof.frequency;
            
            // Check for harmonic ratios (3:2 = perfect fifth, 5:4 = major third, etc.)
            let ratio = if fundamental > 0 {
                (validator_freq * 1000) / fundamental
            } else {
                1000
            };
            
            // Score based on harmonic consonance
            let score = match ratio {
                1500 => 100,  // Perfect fifth (3:2)
                1250 => 95,   // Major third (5:4)
                1333 => 90,   // Perfect fourth (4:3)
                1667 => 85,   // Major sixth (5:3)
                2000 => 80,   // Octave (2:1)
                _ => {
                    // Calculate dissonance penalty
                    let deviation = if ratio > 1000 {
                        ratio - 1000
                    } else {
                        1000 - ratio
                    };
                    (100u32.saturating_sub(deviation / 10)).min(100) as u8
                }
            };
            
            Ok(score)
        } else {
            Ok(0)
        }
    }
    
    /// Factor 3: Calculate modified Merkle tree validation
    fn calculate_merkle_validation(validator: &T::AccountId) -> Result<u8, Error<T>> {
        // Check if validator has valid quantum-safe merkle proofs
        if let Some(proof) = CoherenceProofs::<T>::get(validator) {
            // Verify the merkle root is properly constructed
            let expected_root = Self::calculate_proof_hash(
                validator,
                proof.frequency,
                proof.phase,
            );
            
            if proof.merkle_root == expected_root {
                // Additional validation for quantum-safe properties
                // Check if using approved hash functions (BLAKE2, SHA3, etc.)
                Ok(95) // High score for valid quantum-safe merkle proof
            } else {
                Ok(20) // Low score for invalid proof
            }
        } else {
            Ok(0)
        }
    }
    
    /// Factor 4: Calculate QPP (Quantum Pair Protocol) compliance
    fn calculate_qpp_compliance(validator: &T::AccountId) -> Result<u8, Error<T>> {
        // Check if validator is maintaining quantum pair relationships
        // This would integrate with the QPP enforcement in the wallet
        
        // For now, check if they have valid quantum hardware
        if pallet_quantum_crypto::Pallet::<T>::node_hardware(validator).is_some() {
            // Check network QBER as a proxy for QPP compliance
            if let Some(network_qber) = pallet_quantum_crypto::Pallet::<T>::calculate_network_qber() {
                // Score based on network QBER (lower is better)
                if network_qber < 600 {
                    Ok(90) // Excellent QPP compliance
                } else if network_qber < 1100 {
                    Ok(70) // Good QPP compliance
                } else if network_qber < 2000 {
                    Ok(40) // Some QPP activity
                } else {
                    Ok(20) // Poor QPP compliance
                }
            } else {
                Ok(50) // Has hardware but no QBER data
            }
        } else {
            Err(Error::<T>::NoQuantumHardware)
        }
    }
    
    /// Factor 5: Calculate governance voting weight
    fn calculate_governance_weight(_validator: &T::AccountId) -> u8 {
        // TODO: Integrate with governance pallet when available
        // For now, return a default score
        50
    }
    
    /// Factor 6: Calculate combined coherence from history
    fn calculate_combined_coherence(validator: &T::AccountId) -> u8 {
        // Get historical coherence score
        let current_score = CoherenceScores::<T>::get(validator);
        
        // Convert to 0-100 scale
        (current_score / 100).min(100) as u8
    }
    
    /// Select block producer based on 6-factor coherence scores
    pub fn select_block_producer() -> Option<T::AccountId> {
        let validators = Validators::<T>::get();
        let mut best_validator = None;
        let mut best_score = 0u32;
        
        // Calculate 6-factor scores for all validators
        for validator in validators.iter() {
            // Get current network QBER
            let network_qber = pallet_quantum_crypto::Pallet::<T>::calculate_network_qber()
                .unwrap_or(9999);
            
            // Calculate 6-factor score
            if let Ok(score) = Self::calculate_six_factor_score(validator, network_qber) {
                if score.total_score > best_score {
                    best_score = score.total_score;
                    best_validator = Some(validator.clone());
                    
                    // Store the detailed score
                    <CoherenceScores<T>>::insert(validator, score.total_score);
                }
            }
        }
        
        best_validator
    }
    
    /// Check if block can be finalized based on coherence consensus
    pub fn can_finalize_block(block_number: BlockNumberFor<T>) -> bool {
        let validators = Validators::<T>::get();
        if validators.is_empty() {
            return false;
        }
        
        let mut coherent_validators = 0u32;
        let mut total_weighted_score = 0u32;
        
        // Check each validator's 6-factor score
        for validator in validators.iter() {
            if let Some(proof) = CoherenceProofs::<T>::get(validator) {
                // Only count recent proofs
                let current_block = frame_system::Pallet::<T>::block_number();
                if proof.timestamp + T::CoherencePeriod::get() >= current_block {
                    let score = CoherenceScores::<T>::get(validator);
                    
                    // Require minimum total score of 5000 (50% weighted)
                    if score >= 5000 {
                        coherent_validators += 1;
                        total_weighted_score += score;
                    }
                }
            }
        }
        
        // Require 2/3 of validators with good coherence scores
        let required_validators = (validators.len() as u32 * 2) / 3;
        let has_quorum = coherent_validators >= required_validators;
        
        // Also require average score above 6000 (60% weighted)
        let avg_score = if coherent_validators > 0 {
            total_weighted_score / coherent_validators
        } else {
            0
        };
        
        has_quorum && avg_score >= 6000
    }
}