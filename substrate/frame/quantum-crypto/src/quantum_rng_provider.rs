//! No-std Quantum RNG Provider for Runtime
//!
//! This module provides quantum randomness to all cryptographic operations
//! in a no_std environment suitable for blockchain runtime execution.

use crate::{Config, Pallet, Error};
use sp_std::{vec::Vec, convert::TryInto};
use frame_support::{traits::Randomness, ensure, pallet_prelude::DispatchError};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Hash;
use sp_core::H256;
use codec::Encode;

/// Quantum RNG provider that feeds all cryptographic operations
pub struct QuantumRngProvider<T: Config> {
    _phantom: sp_std::marker::PhantomData<T>,
}

impl<T: Config> QuantumRngProvider<T> {
    /// Get quantum randomness for SPHINCS+ key generation
    pub fn sphincs_key_gen_seed() -> Result<[u8; 32], DispatchError> {
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        // Ensure we have high quality entropy
        ensure!(pool.quality_score >= 90, Error::<T>::InsufficientEntropy);
        ensure!(pool.entropy.len() >= 32, Error::<T>::InsufficientEntropy);
        
        // Extract 32 bytes for SPHINCS+
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pool.entropy[..32]);
        
        // Update pool (remove used entropy)
        let mut new_pool = pool;
        new_pool.entropy = new_pool.entropy[32..].to_vec().try_into()
            .map_err(|_| Error::<T>::EntropyPoolFull)?;
        crate::EntropyPoolStorage::<T>::put(new_pool);
        
        Ok(seed)
    }
    
    /// Get quantum randomness for SPHINCS+ signing
    pub fn sphincs_signing_randomness() -> Result<[u8; 32], DispatchError> {
        // For signing, we can use slightly lower quality entropy
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        ensure!(pool.quality_score >= 80, Error::<T>::InsufficientEntropy);
        ensure!(pool.entropy.len() >= 32, Error::<T>::InsufficientEntropy);
        
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&pool.entropy[..32]);
        
        // Update pool
        let mut new_pool = pool;
        new_pool.entropy = new_pool.entropy[32..].to_vec().try_into()
            .map_err(|_| Error::<T>::EntropyPoolFull)?;
        crate::EntropyPoolStorage::<T>::put(new_pool);
        
        Ok(randomness)
    }
    
    /// Get quantum randomness for Falcon key generation
    pub fn falcon_key_gen_seed() -> Result<[u8; 32], DispatchError> {
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        ensure!(pool.quality_score >= 90, Error::<T>::InsufficientEntropy);
        ensure!(pool.entropy.len() >= 32, Error::<T>::InsufficientEntropy);
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pool.entropy[..32]);
        
        // Update pool
        let mut new_pool = pool;
        new_pool.entropy = new_pool.entropy[32..].to_vec().try_into()
            .map_err(|_| Error::<T>::EntropyPoolFull)?;
        crate::EntropyPoolStorage::<T>::put(new_pool);
        
        Ok(seed)
    }
    
    /// Get quantum randomness for Falcon signing (40 bytes)
    pub fn falcon_signing_nonce() -> Result<[u8; 40], DispatchError> {
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        ensure!(pool.quality_score >= 80, Error::<T>::InsufficientEntropy);
        ensure!(pool.entropy.len() >= 40, Error::<T>::InsufficientEntropy);
        
        let mut nonce = [0u8; 40];
        nonce.copy_from_slice(&pool.entropy[..40]);
        
        // Update pool
        let mut new_pool = pool;
        new_pool.entropy = new_pool.entropy[40..].to_vec().try_into()
            .map_err(|_| Error::<T>::EntropyPoolFull)?;
        crate::EntropyPoolStorage::<T>::put(new_pool);
        
        Ok(nonce)
    }
    
    /// Get quantum randomness for consensus/leader election
    pub fn consensus_randomness(subject: &[u8]) -> Result<H256, DispatchError> {
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        ensure!(pool.quality_score >= 85, Error::<T>::InsufficientEntropy);
        ensure!(pool.entropy.len() >= 32, Error::<T>::InsufficientEntropy);
        
        // Mix quantum entropy with subject for deterministic randomness
        let mut data = Vec::new();
        data.extend_from_slice(subject);
        data.extend_from_slice(&pool.entropy[..32]);
        
        let randomness = T::Hashing::hash(&data);
        
        // Update pool
        let mut new_pool = pool;
        new_pool.entropy = new_pool.entropy[32..].to_vec().try_into()
            .map_err(|_| Error::<T>::EntropyPoolFull)?;
        crate::EntropyPoolStorage::<T>::put(new_pool);
        
        Ok(H256::from_slice(randomness.as_ref()))
    }
    
    /// Check if sufficient entropy is available
    pub fn has_sufficient_entropy(required_bytes: usize, min_quality: u8) -> bool {
        let pool = crate::EntropyPoolStorage::<T>::get();
        pool.entropy.len() >= required_bytes && pool.quality_score >= min_quality
    }
    
    /// Emergency entropy generation (fallback only)
    /// This should only be used if quantum sources fail
    pub fn emergency_entropy(length: usize) -> Vec<u8> {
        // Use block hash as emergency entropy source
        // This is NOT quantum-secure but prevents complete system failure
        let block_number = frame_system::Pallet::<T>::block_number();
        let block_hash = frame_system::Pallet::<T>::block_hash(block_number);
        
        let mut result = Vec::new();
        let mut counter = 0u64;
        
        while result.len() < length {
            let mut data = Vec::new();
            data.extend_from_slice(block_hash.as_ref());
            data.extend_from_slice(&counter.to_le_bytes());
            
            let hash = T::Hashing::hash(&data);
            result.extend_from_slice(hash.as_ref());
            counter += 1;
        }
        
        result.truncate(length);
        result
    }
}

/// Implement Randomness trait for consensus mechanisms
impl<T: Config> Randomness<H256, BlockNumberFor<T>> for QuantumRngProvider<T> {
    fn random(subject: &[u8]) -> (H256, BlockNumberFor<T>) {
        let block_number = frame_system::Pallet::<T>::block_number();
        
        // Try to get quantum randomness
        let randomness = Self::consensus_randomness(subject)
            .unwrap_or_else(|_| {
                // Fallback to hash-based randomness if quantum pool is empty
                let mut data = Vec::new();
                data.extend_from_slice(subject);
                data.extend_from_slice(&block_number.encode());
                H256::from_slice(T::Hashing::hash(&data).as_ref())
            });
        
        (randomness, block_number)
    }
}

/// Storage adapter for post-quantum signature schemes
pub struct QuantumRngAdapter;

impl QuantumRngAdapter {
    /// Get entropy for any post-quantum operation
    pub fn get_entropy<T: Config>(size: usize) -> Result<Vec<u8>, &'static str> {
        let pool = crate::EntropyPoolStorage::<T>::get();
        
        if pool.entropy.len() >= size && pool.quality_score >= 80 {
            Ok(pool.entropy[..size].to_vec())
        } else {
            Err("Insufficient quantum entropy")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::*;
    
    #[test]
    fn test_quantum_rng_operations() {
        new_test_ext().execute_with(|| {
            // Add entropy to pool
            let entropy = vec![0x42; 256];
            let pool = EntropyPool {
                entropy: entropy.try_into().unwrap(),
                source: EntropySource::QkdSiftedKeys,
                quality_score: 95,
                last_refresh: 0,
            };
            crate::EntropyPoolStorage::<Test>::put(pool);
            
            // Test SPHINCS+ seed generation
            let seed = QuantumRngProvider::<Test>::sphincs_key_gen_seed().unwrap();
            assert_eq!(seed.len(), 32);
            
            // Test Falcon nonce generation
            let nonce = QuantumRngProvider::<Test>::falcon_signing_nonce().unwrap();
            assert_eq!(nonce.len(), 40);
            
            // Check entropy was consumed
            let remaining_pool = crate::EntropyPoolStorage::<Test>::get();
            assert_eq!(remaining_pool.entropy.len(), 256 - 32 - 40);
        });
    }
}