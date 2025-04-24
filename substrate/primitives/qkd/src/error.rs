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
