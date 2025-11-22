//! Backward compatibility stub for Sr25519 keyring
//! Redirects to SPHINCS+ for post-quantum security

pub use super::sphincs::Keyring;
