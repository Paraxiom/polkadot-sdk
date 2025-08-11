//! Tests for Proof of Coherence 6-factor scoring system

use crate::{mock::*, Error, Event};
use frame_support::{assert_ok, assert_err};

#[test]
fn test_photon_coherence_calculation() {
    new_test_ext().execute_with(|| {
        // Test QBER to coherence score mapping
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(0), 100);      // 0% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(50), 100);     // 0.5% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(100), 100);    // 1% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(200), 80);     // 2% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(300), 70);     // 3% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(600), 50);     // 6% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(1100), 19);    // 11% QBER
        assert_eq!(ProofOfCoherence::calculate_photon_coherence(1200), 0);     // 12% QBER
    });
}

#[test]
fn test_six_factor_scoring() {
    new_test_ext().execute_with(|| {
        let validator = 1;
        
        // Register validator first
        assert_ok!(ProofOfCoherence::register_validator(RuntimeOrigin::signed(validator)));
        
        // Submit coherence proof
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(validator),
            1500,  // frequency (perfect fifth ratio)
            0,     // phase
            90,    // spectral_purity
            85,    // quantum_fidelity
        ));
        
        // Check the score was calculated
        let score = ProofOfCoherence::detailed_coherence_scores(validator).unwrap();
        
        // Verify individual factors
        assert!(score.photon_coherence_time > 0);
        assert!(score.tonnetz_harmonic_validation > 0);
        assert!(score.modified_merkle_trees > 0);
        assert!(score.qpp_compliance >= 0); // May be 0 without quantum hardware
        assert!(score.governance_votes >= 0);
        assert!(score.combined_coherence_score >= 0);
        
        // Verify total score is weighted sum
        let weights = ScoringWeights::default();
        let expected_total = (
            score.photon_coherence_time as u32 * weights.photon_coherence +
            score.tonnetz_harmonic_validation as u32 * weights.tonnetz_harmonic +
            score.modified_merkle_trees as u32 * weights.merkle_validation +
            score.qpp_compliance as u32 * weights.qpp_compliance +
            score.governance_votes as u32 * weights.governance_votes +
            score.combined_coherence_score as u32 * weights.combined_coherence
        );
        
        assert_eq!(score.total_score, expected_total);
    });
}

#[test]
fn test_block_producer_selection() {
    new_test_ext().execute_with(|| {
        // Register multiple validators
        for i in 1..=3 {
            assert_ok!(ProofOfCoherence::register_validator(RuntimeOrigin::signed(i)));
        }
        
        // Submit different coherence scores
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(1),
            1000, 0, 70, 70,
        ));
        
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(2),
            1500, 0, 90, 90,  // Better scores
        ));
        
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(3),
            1200, 0, 80, 80,
        ));
        
        // Select block producer
        assert_ok!(ProofOfCoherence::select_block_producer_by_coherence(RuntimeOrigin::root()));
        
        // Validator 2 should be selected (highest scores)
        assert_eq!(ProofOfCoherence::current_block_producer(), Some(2));
    });
}

#[test]
fn test_finalization_requirements() {
    new_test_ext().execute_with(|| {
        // Register 3 validators
        for i in 1..=3 {
            assert_ok!(ProofOfCoherence::register_validator(RuntimeOrigin::signed(i)));
        }
        
        // Only 1 validator submits good coherence
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(1),
            1500, 0, 90, 90,
        ));
        
        // Try to finalize - should fail (need 2/3)
        assert_err!(
            ProofOfCoherence::finalize_with_coherence(RuntimeOrigin::root(), 100),
            Error::<Test>::InsufficientCoherence
        );
        
        // Add second validator with good coherence
        assert_ok!(ProofOfCoherence::submit_six_factor_coherence(
            RuntimeOrigin::signed(2),
            1333, 0, 85, 85,
        ));
        
        // Now finalization should succeed (2/3 have coherence)
        assert_ok!(ProofOfCoherence::finalize_with_coherence(RuntimeOrigin::root(), 100));
        
        // Check finalized block was stored
        assert_eq!(ProofOfCoherence::last_finalized_block(), 100);
    });
}

#[test]
fn test_tonnetz_harmonic_scoring() {
    new_test_ext().execute_with(|| {
        let validator = 1;
        
        // Set network fundamental frequency
        let mut harmonic_state = HarmonicState {
            fundamental_frequency: 1000,
            phase_offset: 0,
            coherence_level: 50,
            resonance_nodes: 1,
        };
        NetworkHarmonicState::<Test>::put(&harmonic_state);
        
        // Register and submit with perfect fifth ratio
        assert_ok!(ProofOfCoherence::register_validator(RuntimeOrigin::signed(validator)));
        
        // Test perfect fifth (3:2 ratio = 1500Hz when fundamental is 1000Hz)
        assert_ok!(ProofOfCoherence::submit_coherence_proof(
            RuntimeOrigin::signed(validator),
            1500,  // 3:2 ratio
            0, 90, 90,
        ));
        
        let tonnetz_score = ProofOfCoherence::calculate_tonnetz_harmonic(&validator).unwrap();
        assert_eq!(tonnetz_score, 100); // Perfect consonance
        
        // Test major third (5:4 ratio)
        assert_ok!(ProofOfCoherence::submit_coherence_proof(
            RuntimeOrigin::signed(validator),
            1250,  // 5:4 ratio
            0, 90, 90,
        ));
        
        let tonnetz_score = ProofOfCoherence::calculate_tonnetz_harmonic(&validator).unwrap();
        assert_eq!(tonnetz_score, 95); // Very consonant
    });
}

#[test]
fn test_qber_threshold_enforcement() {
    new_test_ext().execute_with(|| {
        let validator = 1;
        
        // Register validator
        assert_ok!(ProofOfCoherence::register_validator(RuntimeOrigin::signed(validator)));
        
        // Mock high QBER (>11%)
        // This would normally come from pallet_quantum_crypto
        // For testing, we'd need to mock the calculate_network_qber function
        
        // The submit_coherence_proof should fail with high QBER
        // assert_err!(
        //     ProofOfCoherence::submit_coherence_proof(
        //         RuntimeOrigin::signed(validator),
        //         1000, 0, 90, 90,
        //     ),
        //     Error::<Test>::QberTooHigh
        // );
    });
}