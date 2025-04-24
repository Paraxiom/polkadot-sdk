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
