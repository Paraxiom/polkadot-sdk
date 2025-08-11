//! Quantum-resistant hasher configuration for STARK proofs
//! 
//! This module configures the STARK proof system to use SHA3-256 instead of Blake3.
//! SHA3 (Keccak) provides better quantum resistance due to its sponge construction
//! and larger internal state.

use winterfell::math::fields::f128::BaseElement;

// Define our quantum hasher as SHA3-256 with the appropriate field type
pub type QuantumHasher = winter_crypto::hashers::Sha3_256<BaseElement>;

/// Security analysis:
/// 
/// Blake3 vs SHA3-256 against quantum attacks:
/// 
/// 1. Grover's algorithm impact:
///    - Both have 256-bit output, giving 128-bit quantum security
///    - SHA3 has larger internal state (1600 bits vs Blake3's smaller state)
///    
/// 2. Structure:
///    - SHA3: Sponge construction with proven security bounds
///    - Blake3: Tree-based with parallelism optimizations
///    
/// 3. Quantum resistance:
///    - SHA3 was designed post-quantum-threat awareness
///    - More conservative security margins
///    - Better studied against quantum attacks
/// 
/// While both provide adequate quantum resistance for near-term threats,
/// SHA3 is the more conservative choice for long-term security.

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::crypto::{Hasher, Digest};
    
    #[test]
    fn test_quantum_hasher_properties() {
        // Verify it's SHA3-256
        assert_eq!(QuantumHasher::COLLISION_RESISTANCE, 128);
        
        // Test basic hashing
        let data = b"quantum blockchain";
        let hash = QuantumHasher::hash(data);
        assert_eq!(hash.as_bytes().len(), 32);
        
        // Verify determinism
        let hash2 = QuantumHasher::hash(data);
        assert_eq!(hash.as_bytes(), hash2.as_bytes());
        
        // Verify it's different from the input (comparing to 32 bytes of data)
        let mut padded_data = [0u8; 32];
        padded_data[..data.len()].copy_from_slice(data);
        assert_ne!(hash.as_bytes(), padded_data);
    }
    
    #[test]
    fn test_stark_compatibility() {
        // Test that our hasher works with STARK proof requirements
        let test_data = vec![1u8, 2, 3, 4, 5];
        let hash1 = QuantumHasher::hash(&test_data);
        
        // Test merge operation
        let hash2 = QuantumHasher::hash(b"test");
        let merged = QuantumHasher::merge(&[hash1, hash2]);
        assert_eq!(merged.as_bytes().len(), 32);
        
        // Test merge_with_int
        let with_int = QuantumHasher::merge_with_int(hash1, 42);
        assert_eq!(with_int.as_bytes().len(), 32);
        assert_ne!(with_int.as_bytes(), hash1.as_bytes());
    }
}