#!/bin/bash

# Create directory structure for the QKD crate
mkdir -p substrate/primitives/qkd
mkdir -p substrate/primitives/qkd/src

# Create Cargo.toml for the QKD crate
cat > substrate/primitives/qkd/Cargo.toml << 'EOF'
[package]
name = "sp-qkd"
version = "0.1.0"
edition = "2021"
authors = ["Paraxiom"]
description = "Quantum Key Distribution primitives for Substrate"
license = "MIT OR Apache-2.0"

[dependencies]
async-trait = "0.1.73"
parking_lot = "0.12.1"
log = "0.4.20"
thiserror = "1.0.48"
hex = { version = "0.4.3", default-features = false, features = ["alloc"] }

# Optional: Only needed if you want to integrate with Substrate runtime
sp-runtime = { git = "https://github.com/paritytech/polkadot-sdk", branch = "release-polkadot-v1.10.1", optional = true, default-features = false }
sp-core = { git = "https://github.com/paritytech/polkadot-sdk", branch = "release-polkadot-v1.10.1", optional = true, default-features = false }

[features]
default = ["std"]
std = [
    "sp-runtime?/std",
    "sp-core?/std",
]

[dev-dependencies]
tempfile = "3.8.0"
EOF

# Create the main library file
cat > substrate/primitives/qkd/src/lib.rs << 'EOF'
//! Quantum Key Distribution (QKD) primitives for Substrate.
//! 
//! This crate provides the core types and traits for implementing
//! quantum-secure communication channels in blockchain networks.

#![cfg_attr(not(feature = "std"), no_std)]

mod bb84;
mod entropy;
mod key_store;
mod error;

pub use bb84::{BB84Protocol, BB84Session};
pub use entropy::{EntropySource, SimulatedQuantumSource};
pub use key_store::{KeyStore, QuantumKey, InMemoryKeyStore};
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
EOF

# Create the error module
cat > substrate/primitives/qkd/src/error.rs << 'EOF'
//! Error types for QKD operations.

use thiserror::Error;

/// Error type for QKD operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Error during key generation.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    /// Error during protocol execution.
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Error with quantum hardware.
    #[error("Quantum hardware error: {0}")]
    Hardware(String),
    
    /// Key not found in store.
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    /// General error.
    #[error("QKD error: {0}")]
    Other(String),
}

/// Result type for QKD operations.
pub type Result<T> = std::result::Result<T, Error>;
EOF

# Create the entropy source module
cat > substrate/primitives/qkd/src/entropy.rs << 'EOF'
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
EOF

# Create the key store module
cat > substrate/primitives/qkd/src/key_store.rs << 'EOF'
//! Storage for quantum-derived key material.

use crate::error::{Error, Result};
use std::collections::HashMap;
use parking_lot::Mutex;

/// Quantum key information.
#[derive(Debug, Clone)]
pub struct QuantumKey {
    /// Session identifier.
    pub id: u64,
    /// Key material.
    pub key: Vec<u8>,
    /// Timestamp when the key was created.
    pub created_at: u64,
    /// Whether the key has been used.
    pub used: bool,
}

/// Interface for quantum key storage.
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a new quantum key.
    async fn store_key(&self, session_id: u64, key: &[u8]) -> Result<()>;
    
    /// Retrieve a quantum key.
    async fn get_key(&self, session_id: u64) -> Result<QuantumKey>;
    
    /// Mark a key as used.
    async fn mark_used(&self, session_id: u64) -> Result<()>;
    
    /// Delete a key.
    async fn delete_key(&self, session_id: u64) -> Result<()>;
}

/// In-memory implementation of key storage.
pub struct InMemoryKeyStore {
    keys: Mutex<HashMap<u64, QuantumKey>>,
}

impl InMemoryKeyStore {
    /// Create a new in-memory key store.
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
    
    /// Get current timestamp.
    fn current_time() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }
}

#[async_trait::async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn store_key(&self, session_id: u64, key: &[u8]) -> Result<()> {
        let mut keys = self.keys.lock();
        keys.insert(session_id, QuantumKey {
            id: session_id,
            key: key.to_vec(),
            created_at: Self::current_time(),
            used: false,
        });
        Ok(())
    }
    
    async fn get_key(&self, session_id: u64) -> Result<QuantumKey> {
        let keys = self.keys.lock();
        keys.get(&session_id)
            .cloned()
            .ok_or(Error::KeyNotFound(format!("Key with session ID {} not found", session_id)))
    }
    
    async fn mark_used(&self, session_id: u64) -> Result<()> {
        let mut keys = self.keys.lock();
        if let Some(key) = keys.get_mut(&session_id) {
            key.used = true;
            return Ok(());
        }
        Err(Error::KeyNotFound(format!("Key with session ID {} not found", session_id)))
    }
    
    async fn delete_key(&self, session_id: u64) -> Result<()> {
        let mut keys = self.keys.lock();
        if keys.remove(&session_id).is_some() {
            return Ok(());
        }
        Err(Error::KeyNotFound(format!("Key with session ID {} not found", session_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_store() {
        let store = InMemoryKeyStore::new();
        let session_id = 123;
        let key = vec![1, 2, 3, 4];
        
        store.store_key(session_id, &key).await.unwrap();
        
        let retrieved = store.get_key(session_id).await.unwrap();
        assert_eq!(retrieved.id, session_id);
        assert_eq!(retrieved.key, key);
        assert!(!retrieved.used);
        
        store.mark_used(session_id).await.unwrap();
        
        let retrieved = store.get_key(session_id).await.unwrap();
        assert!(retrieved.used);
        
        store.delete_key(session_id).await.unwrap();
        assert!(store.get_key(session_id).await.is_err());
    }
}
EOF

# Create the BB84 protocol module
cat > substrate/primitives/qkd/src/bb84.rs << 'EOF'
//! BB84 quantum key distribution protocol implementation.

use crate::entropy::EntropySource;
use crate::key_store::KeyStore;
use crate::error::{Error, Result};
use std::sync::Arc;

/// State of a BB84 protocol session.
#[derive(Debug)]
pub struct BB84Session {
    /// Session identifier.
    pub id: u64,
    /// Current state of the protocol.
    pub state: BB84State,
    /// Raw bits generated by the sender.
    pub raw_bits: Vec<u8>,
    /// Bases used for encoding/measuring.
    pub bases: Vec<u8>,
    /// Matched key positions after basis reconciliation.
    pub matched_positions: Vec<usize>,
    /// Error rate estimated during reconciliation.
    pub error_rate: f64,
    /// Final key after error correction and privacy amplification.
    pub final_key: Vec<u8>,
}

/// Internal state of the BB84 protocol.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BB84State {
    /// Initial state.
    New,
    /// Quantum bits have been transmitted.
    BitsTransmitted,
    /// Bases have been reconciled.
    BasesReconciled,
    /// Error detection has been performed.
    ErrorDetected,
    /// Privacy amplification has been applied.
    PrivacyAmplified,
    /// Final key has been established.
    KeyEstablished,
    /// Error occurred during the protocol.
    Error,
}

/// Implementation of the BB84 quantum key distribution protocol.
pub struct BB84Protocol {
    /// Entropy source for quantum randomness.
    entropy_source: Arc<dyn EntropySource>,
    /// Key store for managing quantum keys.
    key_store: Arc<dyn KeyStore>,
}

impl BB84Protocol {
    /// Create a new BB84 protocol instance.
    pub fn new(
        entropy_source: Arc<dyn EntropySource>,
        key_store: Arc<dyn KeyStore>,
    ) -> Self {
        Self {
            entropy_source,
            key_store,
        }
    }

    /// Initialize a new BB84 session.
    pub async fn new_session(&self) -> Result<BB84Session> {
        let id = self.entropy_source.random_u64().await?;
        
        Ok(BB84Session {
            id,
            state: BB84State::New,
            raw_bits: Vec::new(),
            bases: Vec::new(),
            matched_positions: Vec::new(),
            error_rate: 0.0,
            final_key: Vec::new(),
        })
    }

    /// Generate quantum bits for transmission.
    pub async fn generate_quantum_bits(&self, session: &mut BB84Session, bit_count: usize) -> Result<Vec<u8>> {
        if session.state != BB84State::New {
            session.state = BB84State::Error;
            return Err(Error::Protocol("Invalid session state".to_string()));
        }

        // Generate random bits and bases
        session.raw_bits = self.entropy_source.random_bytes(bit_count).await?;
        session.bases = self.entropy_source.random_bytes(bit_count).await?;
        session.state = BB84State::BitsTransmitted;
        
        // In a real implementation, this would interact with quantum hardware
        // For now, return the classical representation of the quantum state
        Ok(session.raw_bits.clone())
    }

    /// Process received quantum bits.
    pub async fn process_received_bits(
        &self, 
        session: &mut BB84Session,
        received_bits: &[u8],
        measurement_bases: &[u8],
    ) -> Result<()> {
        if session.state != BB84State::New {
            session.state = BB84State::Error;
            return Err(Error::Protocol("Invalid session state".to_string()));
        }

        // Store the bits and bases
        session.raw_bits = received_bits.to_vec();
        session.bases = measurement_bases.to_vec();
        session.state = BB84State::BitsTransmitted;
        
        Ok(())
    }

    /// Perform basis reconciliation.
    pub async fn reconcile_bases(
        &self,
        session: &mut BB84Session,
        other_bases: &[u8],
    ) -> Result<Vec<usize>> {
        if session.state != BB84State::BitsTransmitted {
            session.state = BB84State::Error;
            return Err(Error::Protocol("Invalid session state".to_string()));
        }

        // Find where bases match
        let mut matched = Vec::new();
        for i in 0..session.bases.len().min(other_bases.len()) {
            if session.bases[i] == other_bases[i] {
                matched.push(i);
            }
        }

        session.matched_positions = matched.clone();
        session.state = BB84State::BasesReconciled;
        
        Ok(matched)
    }

    /// Perform error detection.
    pub async fn detect_errors(
        &self,
        session: &mut BB84Session,
        sample_bits: &[(usize, u8)],
    ) -> Result<f64> {
        if session.state != BB84State::BasesReconciled {
            session.state = BB84State::Error;
            return Err(Error::Protocol("Invalid session state".to_string()));
        }

        let mut error_count = 0;
        let sample_size = sample_bits.len();

        // Compare bits at sample positions
        for (pos, bit) in sample_bits {
            if *pos < session.raw_bits.len() && session.raw_bits[*pos] != *bit {
                error_count += 1;
            }
        }

        let error_rate = if sample_size > 0 {
            error_count as f64 / sample_size as f64
        } else {
            0.0
        };

        session.error_rate = error_rate;
        session.state = BB84State::ErrorDetected;
        
        Ok(error_rate)
    }

    /// Perform privacy amplification and generate final key.
    pub async fn privacy_amplification(
        &self,
        session: &mut BB84Session,
        final_length: usize,
    ) -> Result<Vec<u8>> {
        if session.state != BB84State::ErrorDetected {
            session.state = BB84State::Error;
            return Err(Error::Protocol("Invalid session state".to_string()));
        }

        // Extract sifted key from matched positions
        let mut sifted_key = Vec::with_capacity(session.matched_positions.len());
        for &pos in &session.matched_positions {
            if pos < session.raw_bits.len() {
                sifted_key.push(session.raw_bits[pos]);
            }
        }

        // In a real implementation, this would apply privacy amplification
        // For this example, we'll just truncate to the desired length
        let final_key = if sifted_key.len() > final_length {
            sifted_key[0..final_length].to_vec()
        } else {
            sifted_key
        };

        session.final_key = final_key.clone();
        session.state = BB84State::KeyEstablished;
        
        // Store the key in the key store
        self.key_store.store_key(session.id, &final_key).await?;
        
        Ok(final_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SimulatedQuantumSource;
    use crate::key_store::InMemoryKeyStore;
    
    #[tokio::test]
    async fn test_bb84_protocol() {
        let entropy_source = Arc::new(SimulatedQuantumSource::new());
        let key_store = Arc::new(InMemoryKeyStore::new());
        
        let protocol = BB84Protocol::new(entropy_source, key_store);
        
        // Initialize a session
        let mut session = protocol.new_session().await.unwrap();
        assert_eq!(session.state, BB84State::New);
        
        // Generate quantum bits
        let bits = protocol.generate_quantum_bits(&mut session, 100).await.unwrap();
        assert_eq!(bits.len(), 100);
        assert_eq!(session.state, BB84State::BitsTransmitted);
        
        // For testing, we'll simulate another party with same bases
        let other_bases = session.bases.clone();
        
        // Reconcile bases
        let matched = protocol.reconcile_bases(&mut session, &other_bases).await.unwrap();
        assert!(!matched.is_empty());
        assert_eq!(session.state, BB84State::BasesReconciled);
        
        // Test error detection (no errors in this test)
        let sample_indices: Vec<(usize, u8)> = matched.iter()
            .take(10)
            .map(|&idx| (idx, session.raw_bits[idx]))
            .collect();
            
        let error_rate = protocol.detect_errors(&mut session, &sample_indices).await.unwrap();
        assert_eq!(error_rate, 0.0);
        assert_eq!(session.state, BB84State::ErrorDetected);
        
        // Generate final key
        let final_key = protocol.privacy_amplification(&mut session, 32).await.unwrap();
        assert!(!final_key.is_empty());
        assert_eq!(session.state, BB84State::KeyEstablished);
        
        // Check key in store
        let stored_key = protocol.key_store.get_key(session.id).await.unwrap();
        assert_eq!(stored_key.key, final_key);
    }
}
EOF

# Update the workspace Cargo.toml to include the QKD crate
if ! grep -q "sp-qkd" substrate/Cargo.toml; then
    # First, find where the member list begins
    MEMBERS_LINE=$(grep -n '\[workspace.members\]' substrate/Cargo.toml | cut -d: -f1)
    
    if [ -n "$MEMBERS_LINE" ]; then
        # Add our crate to the members list
        sed -i "$MEMBERS_LINE a \"primitives/qkd\"," substrate/Cargo.toml
    fi
fi

echo "QKD crate has been set up at substrate/primitives/qkd/"
echo "This provides a clean, separate implementation that you can build upon incrementally."
