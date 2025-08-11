//! Integration test for STARK proof system

#[cfg(test)]
mod tests {
    use crate::qber_stark::*;
    use winterfell::crypto::hashers::Blake3_256;
    use sp_core::H256;

    #[test]
    fn test_stark_proof_integration() {
        println!("Testing STARK proof generation and verification...");
        
        // Create test measurements (basis_match, error_detected)
        let measurements = vec![
            (true, false),   // Basis match, no error
            (true, false),   // Basis match, no error
            (false, false),  // No basis match
            (true, true),    // Basis match, error detected (contributes to QBER)
            (true, false),   // Basis match, no error
            (false, false),  // No basis match
            (true, false),   // Basis match, no error
            (true, true),    // Basis match, error detected (contributes to QBER)
            (true, false),   // Basis match, no error
            (true, false),   // Basis match, no error
        ];
        
        // Count errors and matches for QBER calculation
        let basis_matches = measurements.iter().filter(|(basis, _)| *basis).count();
        let errors = measurements.iter().filter(|(basis, error)| *basis && *error).count();
        let qber_percentage = (errors as f64 / basis_matches as f64) * 100.0;
        let qber_value = (qber_percentage * 100.0) as u32; // Convert to basis points
        
        println!("Basis matches: {}, Errors: {}, QBER: {:.2}%", basis_matches, errors, qber_percentage);
        
        // Create public inputs
        let device_id = H256::from([1u8; 32]);
        let env_data = H256::from([2u8; 32]);
        
        let public_inputs = QberPublicInputs {
            qber_value,
            measurement_count: measurements.len() as u32,
            device_id_hash: device_id.0,
            environmental_hash: env_data.0,
        };
        
        // Generate STARK proof
        let stark = QberStark::new();
        match stark.prove(measurements.clone(), public_inputs.clone()) {
            Ok(proof) => {
                println!("✓ STARK proof generated successfully");
                println!("  Proof size: {} bytes", proof.to_bytes().len());
                
                // Verify the proof
                match stark.verify(public_inputs, proof) {
                    Ok(()) => {
                        println!("✓ STARK proof verified successfully");
                        println!("  QBER is cryptographically proven to be {:.2}%", qber_percentage);
                    }
                    Err(e) => {
                        panic!("✗ STARK proof verification failed: {}", e);
                    }
                }
            }
            Err(e) => {
                panic!("✗ Failed to generate STARK proof: {}", e);
            }
        }
    }

    #[test]
    fn test_high_qber_stark_proof() {
        println!("\nTesting STARK proof with high QBER (above 11% threshold)...");
        
        // Create measurements with high error rate
        let measurements: Vec<(bool, bool)> = (0..100)
            .map(|i| {
                let basis_match = i % 3 != 0;  // ~66% basis matches
                let has_error = basis_match && (i % 5 == 0);  // ~20% errors on matches
                (basis_match, has_error)
            })
            .collect();
        
        let basis_matches = measurements.iter().filter(|(basis, _)| *basis).count();
        let errors = measurements.iter().filter(|(basis, error)| *basis && *error).count();
        let qber_percentage = (errors as f64 / basis_matches as f64) * 100.0;
        let qber_value = (qber_percentage * 100.0) as u32;
        
        println!("High QBER test: {:.2}% (threshold is 11%)", qber_percentage);
        assert!(qber_percentage > 11.0, "QBER should exceed secure threshold");
        
        let public_inputs = QberPublicInputs {
            qber_value,
            measurement_count: measurements.len() as u32,
            device_id_hash: [3u8; 32],
            environmental_hash: [4u8; 32],
        };
        
        // Should still generate valid proof even with high QBER
        let stark = QberStark::new();
        match stark.prove(measurements, public_inputs.clone()) {
            Ok(proof) => {
                println!("✓ STARK proof generated for high QBER");
                
                // Verify it
                match stark.verify(public_inputs, proof) {
                    Ok(()) => {
                        println!("✓ High QBER proof verified - channel is insecure!");
                    }
                    Err(e) => {
                        panic!("✗ Failed to verify high QBER proof: {}", e);
                    }
                }
            }
            Err(e) => {
                panic!("✗ Failed to generate proof for high QBER: {}", e);
            }
        }
    }
}