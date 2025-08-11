//! Quantum-resistant Merkle tree implementation
//!
//! This module provides a Merkle tree implementation that uses
//! quantum-resistant hash functions (SHA3-256) instead of classical
//! ones (Blake2) to ensure post-quantum security.

use sp_std::{vec, vec::Vec};
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use sp_core::H256;
use sha3::{Sha3_256, Digest};

/// Quantum-resistant Merkle tree
#[derive(Clone, Debug, Encode, Decode, TypeInfo)]
pub struct QuantumMerkleTree {
    /// Tree nodes stored in level order
    nodes: Vec<H256>,
    /// Number of leaves
    leaf_count: u32,
}

/// Merkle proof for quantum-resistant verification
#[derive(Clone, Debug, Encode, Decode, TypeInfo)]
pub struct QuantumMerkleProof {
    /// Sibling hashes needed for verification
    siblings: Vec<H256>,
    /// Leaf index
    leaf_index: u32,
}

impl QuantumMerkleTree {
    /// Create a new Merkle tree from leaves
    pub fn new(leaves: Vec<Vec<u8>>) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![],
                leaf_count: 0,
            };
        }
        
        let leaf_count = leaves.len() as u32;
        let tree_size = 2 * leaves.len() - 1;
        let mut nodes = vec![H256::zero(); tree_size];
        
        // Hash leaves with quantum-resistant hash
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[tree_size - leaves.len() + i] = Self::quantum_hash(leaf);
        }
        
        // Build tree bottom-up
        for i in (0..tree_size - leaves.len()).rev() {
            let left_child = 2 * i + 1;
            let right_child = 2 * i + 2;
            
            if right_child < tree_size {
                nodes[i] = Self::hash_pair(&nodes[left_child], &nodes[right_child]);
            } else {
                // Odd number of nodes, promote the left child
                nodes[i] = nodes[left_child];
            }
        }
        
        Self { nodes, leaf_count }
    }
    
    /// Get the root hash
    pub fn root(&self) -> H256 {
        if self.nodes.is_empty() {
            H256::zero()
        } else {
            self.nodes[0]
        }
    }
    
    /// Generate a proof for a leaf at given index
    pub fn generate_proof(&self, leaf_index: u32) -> Option<QuantumMerkleProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }
        
        let mut siblings = Vec::new();
        let mut index = (self.nodes.len() - self.leaf_count as usize) + leaf_index as usize;
        
        while index > 0 {
            let parent = (index - 1) / 2;
            let sibling = if index % 2 == 1 {
                index + 1  // Right sibling
            } else {
                index - 1  // Left sibling
            };
            
            if sibling < self.nodes.len() {
                siblings.push(self.nodes[sibling]);
            }
            
            index = parent;
        }
        
        Some(QuantumMerkleProof {
            siblings,
            leaf_index,
        })
    }
    
    /// Verify a Merkle proof
    pub fn verify_proof(
        root: &H256,
        leaf_data: &[u8],
        proof: &QuantumMerkleProof,
    ) -> bool {
        let mut hash = Self::quantum_hash(leaf_data);
        let mut index = proof.leaf_index;
        
        for sibling in &proof.siblings {
            if index % 2 == 0 {
                hash = Self::hash_pair(&hash, sibling);
            } else {
                hash = Self::hash_pair(sibling, &hash);
            }
            index /= 2;
        }
        
        &hash == root
    }
    
    /// Quantum-resistant hash function (SHA3-256)
    fn quantum_hash(data: &[u8]) -> H256 {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        H256::from_slice(&result)
    }
    
    /// Hash two nodes together
    fn hash_pair(left: &H256, right: &H256) -> H256 {
        let mut hasher = Sha3_256::new();
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        let result = hasher.finalize();
        H256::from_slice(&result)
    }
}

/// Quantum Merkle tree for state roots
#[derive(Clone, Debug, Encode, Decode, TypeInfo)]
pub struct QuantumStateTree {
    /// The Merkle tree
    tree: QuantumMerkleTree,
    /// State version
    version: u64,
}

impl QuantumStateTree {
    /// Create a new state tree
    pub fn new(state_items: Vec<(Vec<u8>, Vec<u8>)>, version: u64) -> Self {
        // Encode key-value pairs for hashing
        let leaves: Vec<Vec<u8>> = state_items
            .into_iter()
            .map(|(key, value)| {
                let mut data = key;
                data.extend(value);
                data
            })
            .collect();
        
        Self {
            tree: QuantumMerkleTree::new(leaves),
            version,
        }
    }
    
    /// Get the state root
    pub fn state_root(&self) -> H256 {
        self.tree.root()
    }
    
    /// Get the version
    pub fn version(&self) -> u64 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quantum_merkle_tree() {
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
            b"leaf4".to_vec(),
        ];
        
        let tree = QuantumMerkleTree::new(leaves.clone());
        let root = tree.root();
        
        // Verify each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i as u32).unwrap();
            assert!(QuantumMerkleTree::verify_proof(&root, leaf, &proof));
        }
    }
    
    #[test]
    fn test_quantum_resistant_hash() {
        let data = b"quantum blockchain";
        let hash1 = QuantumMerkleTree::quantum_hash(data);
        let hash2 = QuantumMerkleTree::quantum_hash(data);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different from zero
        assert_ne!(hash1, H256::zero());
    }
    
    #[test]
    fn test_state_tree() {
        let state_items = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
            (b"key3".to_vec(), b"value3".to_vec()),
        ];
        
        let state_tree = QuantumStateTree::new(state_items, 1);
        let root = state_tree.state_root();
        
        assert_ne!(root, H256::zero());
        assert_eq!(state_tree.version(), 1);
    }
}