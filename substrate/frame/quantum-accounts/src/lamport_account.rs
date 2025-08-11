//! # Lamport-based Quantum Accounts
//!
//! This module extends quantum accounts to support Lamport signatures,
//! leveraging our existing double ratchet implementation for true post-quantum security.

use crate::*;
use sp_std::vec::Vec;
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_core::H256;

/// Lamport account type for quantum accounts
#[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq)]
pub struct LamportAccount {
    /// Current Lamport public key (16KB)
    pub current_key: BoundedVec<u8, ConstU32<16384>>,
    /// Next public key for key rotation
    pub next_key: BoundedVec<u8, ConstU32<16384>>,
    /// Key usage counter (for one-time signature enforcement)
    pub key_usage: u32,
    /// Maximum uses before rotation (usually 1 for Lamport)
    pub max_uses: u32,
}

/// Lamport signature wrapper
#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct LamportSignatureWrapper {
    /// The Lamport signature (8KB)
    pub signature: Vec<u8>,
    /// Public key this signature was created with
    pub public_key: Vec<u8>,
    /// Sequence number for replay protection
    pub sequence: u32,
}

impl<T: Config> Pallet<T> {
    /// Register a Lamport-based quantum account
    pub fn register_lamport_account(
        origin: OriginFor<T>,
        initial_public_key: Vec<u8>,
        next_public_key: Vec<u8>,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        
        // Validate key sizes (16KB for Lamport public keys)
        ensure!(
            initial_public_key.len() == 16384,
            Error::<T>::InvalidPublicKeySize
        );
        ensure!(
            next_public_key.len() == 16384,
            Error::<T>::InvalidPublicKeySize
        );
        
        // Create account ID from initial key hash
        let key_hash = sp_io::hashing::blake2_256(&initial_public_key);
        let account_id = QuantumAccountId {
            algorithm: QuantumAlgorithm::Lamport,
            key_hash: H256::from(key_hash),
        };
        
        // Create Lamport account
        let lamport_account = LamportAccount {
            current_key: initial_public_key.try_into()
                .map_err(|_| Error::<T>::InvalidPublicKeySize)?,
            next_key: next_public_key.try_into()
                .map_err(|_| Error::<T>::InvalidPublicKeySize)?,
            key_usage: 0,
            max_uses: 1, // One-time signatures
        };
        
        // Store in runtime storage
        crate::LamportAccounts::<T>::insert(&account_id, lamport_account);
        
        // Also register as quantum account
        let info = AccountInfo {
            nonce: 0,
            public_key: BoundedVec::default(), // We store full key in LamportAccounts
            registered_at: frame_system::Pallet::<T>::block_number(),
        };
        
        crate::QuantumAccounts::<T>::insert(&account_id, info);
        
        crate::Pallet::<T>::deposit_event(crate::Event::QuantumAccountRegistered {
            account: account_id.key_hash,
            algorithm: 3, // Lamport = 3
        });
        
        Ok(())
    }
    
    /// Rotate Lamport keys after use
    pub fn rotate_lamport_key(
        account: &QuantumAccountId,
        new_next_key: Vec<u8>,
    ) -> DispatchResult {
        ensure!(
            new_next_key.len() == 16384,
            Error::<T>::InvalidPublicKeySize
        );
        
        crate::LamportAccounts::<T>::mutate(account, |maybe_account| {
            if let Some(lamport) = maybe_account {
                // Move next key to current
                lamport.current_key = lamport.next_key.clone();
                // Set new next key
                lamport.next_key = new_next_key.try_into()
                    .map_err(|_| Error::<T>::InvalidPublicKeySize)?;
                // Reset usage counter
                lamport.key_usage = 0;
                
                Ok(())
            } else {
                Err(Error::<T>::AccountNotRegistered.into())
            }
        })
    }
    
    /// Verify a Lamport signature
    pub fn verify_lamport_signature(
        account: &QuantumAccountId,
        signature: &crate::lamport_account::LamportSignatureWrapper,
        message: &[u8],
    ) -> Result<(), Error<T>> {
        // Get Lamport account
        let lamport_account = crate::LamportAccounts::<T>::get(account)
            .ok_or(Error::<T>::AccountNotRegistered)?;
        
        // Check if key needs rotation
        ensure!(
            lamport_account.key_usage < lamport_account.max_uses,
            Error::<T>::KeyRotationRequired
        );
        
        // Verify signature matches current key
        ensure!(
            signature.public_key == lamport_account.current_key.to_vec(),
            Error::<T>::KeyMismatch
        );
        
        // Verify signature sizes
        ensure!(
            signature.signature.len() == 8192, // LAMPORT_SIGNATURE_SIZE
            Error::<T>::InvalidQuantumSignature
        );
        ensure!(
            signature.public_key.len() == 16384, // LAMPORT_PUBLIC_KEY_SIZE
            Error::<T>::InvalidQuantumSignature
        );
        
        // Verify the Lamport signature using the verification function from quantum-crypto
        let verified = pallet_quantum_crypto::double_ratchet_lamport::verify_lamport_signature(
            message,
            &signature.signature,
            &signature.public_key,
        );
        
        ensure!(verified, Error::<T>::InvalidQuantumSignature);
        
        // Increment usage counter
        crate::LamportAccounts::<T>::mutate(account, |maybe_account| {
            if let Some(lamport) = maybe_account {
                lamport.key_usage += 1;
            }
        });
        
        // Emit event if rotation needed
        if lamport_account.key_usage + 1 >= lamport_account.max_uses {
            Self::deposit_event(Event::KeyRotationRequired {
                account: account.key_hash,
            });
        }
        
        Ok(())
    }
}

// Storage moved to main pallet module

// Note: The QuantumAlgorithm enum already has Lamport variant in lib.rs

// Extended events and errors are defined inline in the pallet macro

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lamport_account_creation() {
        // Create mock keys (16KB each)
        let initial_key = vec![0xAA; 16384];
        let next_key = vec![0xBB; 16384];
        
        let lamport = LamportAccount {
            current_key: initial_key.try_into().unwrap(),
            next_key: next_key.try_into().unwrap(),
            key_usage: 0,
            max_uses: 1,
        };
        
        assert_eq!(lamport.current_key.len(), 16384);
        assert_eq!(lamport.key_usage, 0);
    }
}