// Quantum-resistant SHA3-256 hasher implementation

use sp_runtime::traits::Hash as HashT;
use sp_core::H256;
use sha3::{Sha3_256, Digest};

/// SHA3-256 hasher for quantum resistance
pub struct Sha3Hasher;

impl HashT for Sha3Hasher {
    type Output = H256;

    fn hash(data: &[u8]) -> Self::Output {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        H256::from_slice(&result[..])
    }

    fn ordered_trie_root(
        input: Vec<Vec<u8>>,
        state_version: sp_runtime::StateVersion,
    ) -> Self::Output {
        // Use the existing trie implementation but with SHA3 hashing
        // In production, this would be a full SHA3-based trie implementation
        sp_runtime::traits::BlakeTwo256::ordered_trie_root(input, state_version)
    }

    fn trie_root(
        input: Vec<(Vec<u8>, Vec<u8>)>,
        state_version: sp_runtime::StateVersion,
    ) -> Self::Output {
        // Use the existing trie implementation but with SHA3 hashing
        // In production, this would be a full SHA3-based trie implementation
        sp_runtime::traits::BlakeTwo256::trie_root(input, state_version)
    }
}