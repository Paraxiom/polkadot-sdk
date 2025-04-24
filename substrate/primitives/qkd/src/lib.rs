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
