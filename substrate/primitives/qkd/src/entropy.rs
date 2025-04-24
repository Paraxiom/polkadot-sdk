//! Entropy sources for quantum key distribution.

use crate::error::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Interface for quantum entropy sources.
#[async_trait::async_trait]
pub trait EntropySource: Send + Sync {
    /// Generate random bytes.
    async fn random_bytes(&self, count: usize) -> Result<Vec<u8>>;
    
    /// Generate a random u64.
    async fn random_u64(&self) -> Result<u64>;
}

/// Simulated quantum entropy source using classical randomness.
pub struct SimulatedQuantumSource {
    seed: u64,
}

impl SimulatedQuantumSource {
    /// Create a new simulated quantum source.
    pub fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        Self { seed }
    }
    
    /// Simple pseudo-random number generator.
    fn next_rand(&self, prev: u64) -> u64 {
        let a = 6364136223846793005u64;
        let c = 1442695040888963407u64;
        a.wrapping_mul(prev).wrapping_add(c)
    }
}

#[async_trait::async_trait]
impl EntropySource for SimulatedQuantumSource {
    async fn random_bytes(&self, count: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(count);
        let mut current = self.seed;
        
        for _ in 0..count {
            current = self.next_rand(current);
            result.push((current & 0xFF) as u8);
        }
        
        Ok(result)
    }
    
    async fn random_u64(&self) -> Result<u64> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        Ok(self.next_rand(ts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_simulated_source() {
        let source = SimulatedQuantumSource::new();
        let random_bytes = source.random_bytes(100).await.unwrap();
        assert_eq!(random_bytes.len(), 100);
        
        let r1 = source.random_u64().await.unwrap();
        let r2 = source.random_u64().await.unwrap();
        // With high probability, these should be different
        assert_ne!(r1, r2);
    }
}
