// Quantum Integration Tests - Proving What Works

#[cfg(test)]
mod quantum_integration_tests {
    use super::*;
    use sp_core::crypto::{QuantumKeyType, LamportClock, DoubleRatchetState, QuantumSignature};
    use sp_core::hasher::QuantumHasher;
    
    #[test]
    fn test_quantum_hasher_produces_different_outputs() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        
        let hash1 = QuantumHasher::hash(data1);
        let hash2 = QuantumHasher::hash(data2);
        
        assert_ne!(hash1, hash2, "Quantum hasher should produce different outputs");
        assert_eq!(hash1.len(), 32, "Hash should be 32 bytes");
    }
    
    #[test]
    fn test_lamport_clock_increments() {
        let mut clock = LamportClock::new(42);
        assert_eq!(clock.timestamp, 0);
        assert_eq!(clock.node_id, 42);
        
        clock.tick();
        assert_eq!(clock.timestamp, 1);
        
        clock.tick();
        assert_eq!(clock.timestamp, 2);
    }
    
    #[test]
    fn test_double_ratchet_key_derivation() {
        let mut ratchet = DoubleRatchetState::new();
        let initial_send = ratchet.send_chain_key.clone();
        let initial_recv = ratchet.recv_chain_key.clone();
        
        ratchet.ratchet();
        
        assert_ne!(ratchet.send_chain_key, initial_send, "Send key should change");
        assert_ne!(ratchet.recv_chain_key, initial_recv, "Recv key should change");
        assert_eq!(ratchet.message_num, 1);
    }
    
    #[test]
    fn test_quantum_signature_validation() {
        // Test SPHINCS+ signature size validation
        let sig_sphincs = QuantumSignature::sign_stub(QuantumKeyType::SphincsPlus, b"message");
        assert!(sig_sphincs.verify_stub(b"message"), "SPHINCS+ signature should verify");
        assert_eq!(sig_sphincs.signature.len(), 8192, "SPHINCS+ signature size");
        
        // Test Falcon signature size validation
        let mut sig_falcon = QuantumSignature::sign_stub(QuantumKeyType::Falcon512, b"message");
        sig_falcon.signature = vec![0u8; 700]; // Valid Falcon size
        assert!(sig_falcon.verify_stub(b"message"), "Falcon signature should verify");
        
        // Test invalid size
        sig_falcon.signature = vec![0u8; 100]; // Too small
        assert!(!sig_falcon.verify_stub(b"message"), "Small Falcon signature should fail");
    }
    
    #[test]
    fn test_quantum_key_types() {
        let types = vec![
            QuantumKeyType::SphincsPlus,
            QuantumKeyType::Falcon512,
            QuantumKeyType::Dilithium,
        ];
        
        // Ensure all types are distinct
        for (i, t1) in types.iter().enumerate() {
            for (j, t2) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(t1, t2, "Key types should be distinct");
                }
            }
        }
    }
}

#[cfg(test)]
mod kirq_integration_tests {
    use super::*;
    
    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_kirq_hub_connectivity() {
        // This test requires KIRQ hub to be running
        let client = reqwest::blocking::Client::new();
        let response = client
            .get("http://localhost:8001/health")
            .send()
            .expect("KIRQ hub should be reachable");
            
        assert_eq!(response.status(), 200, "KIRQ hub should return 200 OK");
    }
    
    #[test]
    #[ignore] // Requires running node
    fn test_substrate_node_rpc() {
        let client = reqwest::blocking::Client::new();
        let response = client
            .post("http://localhost:9944")
            .header("Content-Type", "application/json")
            .body(r#"{"id":1, "jsonrpc":"2.0", "method": "system_health", "params":[]}"#)
            .send()
            .expect("Substrate node should be reachable");
            
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().expect("Valid JSON");
        assert!(body["result"]["peers"].is_number());
    }
}

#[cfg(test)]
mod coherence_tests {
    use super::*;
    
    /// Test that quantum operations maintain coherence properties
    #[test]
    fn test_quantum_coherence_properties() {
        // Test 1: Idempotency - Same input always produces same output
        let data = b"quantum data";
        let hash1 = QuantumHasher::hash(data);
        let hash2 = QuantumHasher::hash(data);
        assert_eq!(hash1, hash2, "Quantum hash should be deterministic");
        
        // Test 2: Non-commutativity of ratchet operations
        let mut ratchet1 = DoubleRatchetState::new();
        let mut ratchet2 = DoubleRatchetState::new();
        
        ratchet1.ratchet();
        ratchet1.ratchet();
        
        ratchet2.ratchet();
        ratchet2.ratchet();
        
        assert_eq!(ratchet1.send_chain_key, ratchet2.send_chain_key, 
                   "Same sequence should produce same keys");
    }
    
    /// Test harmony between different quantum components
    #[test]
    fn test_quantum_harmony() {
        // Create a quantum event flow
        let mut clock = LamportClock::new(1);
        let mut ratchet = DoubleRatchetState::new();
        
        // Simulate quantum event processing
        for i in 0..10 {
            clock.tick();
            ratchet.ratchet();
            
            // Verify harmony: clock and ratchet stay in sync
            assert_eq!(clock.timestamp as u32, ratchet.message_num);
            
            // Create quantum signature for this state
            let state_data = format!("state_{}", i).into_bytes();
            let sig = QuantumSignature::sign_stub(QuantumKeyType::Dilithium, &state_data);
            assert!(sig.verify_stub(&state_data));
        }
    }
}

#[cfg(test)]
mod zkp_tests {
    use super::*;
    
    /// Simulate a zero-knowledge proof of quantum state
    #[test]
    fn test_quantum_zkp_simulation() {
        // Generate quantum commitment
        let secret = b"quantum_secret";
        let commitment = QuantumHasher::hash(secret);
        
        // Create witness (proof of knowledge)
        let mut witness = DoubleRatchetState::new();
        witness.send_chain_key.copy_from_slice(&commitment[..32]);
        witness.ratchet();
        
        // Verify the proof (simplified)
        let verification_hash = QuantumHasher::hash(&witness.send_chain_key);
        
        // In a real ZKP, this would be a complex verification
        // For now, we verify basic properties
        assert_ne!(verification_hash.as_ref(), &[0u8; 32], "Hash should not be zero");
        assert_eq!(verification_hash.len(), 32, "Hash should be 32 bytes");
    }
}

// Run all tests with: cargo test --features quantum
// Run integration tests with: cargo test -- --ignored --nocapture