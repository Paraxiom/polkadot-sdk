//! # Quantum Account Wrapper
//!
//! R&D implementation that adds quantum security on top of existing accounts
//! without breaking compatibility.

use crate::*;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_std::vec::Vec;
use sp_core::H256;

/// Quantum wrapper for classical accounts
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct QuantumWrapper<T: Config> {
    /// Classical account being wrapped
    pub classical_account: T::AccountId,
    
    /// Current Lamport public key hash
    pub quantum_key_hash: H256,
    
    /// Number of transactions signed
    pub tx_count: u32,
    
    /// Block when quantum protection was enabled
    pub enabled_at: BlockNumberFor<T>,
    
    /// Whether to enforce quantum signatures
    pub enforcement_mode: EnforcementMode,
}

/// Enforcement modes for gradual rollout
#[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Quantum signatures optional (logging only)
    #[default]
    Optional,
    /// Required for high-value transactions
    HighValueOnly,
    /// Required for all transactions
    Required,
    /// Testing mode - accept invalid signatures but log
    Testing,
}

/// Quantum-wrapped transaction
#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct QuantumWrappedTx<T: Config> {
    /// The inner transaction
    pub inner_tx: Vec<u8>, // Generic transaction bytes
    
    /// Quantum signature over tx hash
    pub quantum_signature: Option<crate::lamport_account::LamportSignatureWrapper>,
    
    /// Account that created this
    pub from: T::AccountId,
    
    /// Nonce for replay protection
    pub nonce: u32,
}

// Storage moved to main pallet module

impl<T: Config> Pallet<T> {
    /// Enable quantum protection for an account
    pub fn enable_quantum_wrapper(
        origin: OriginFor<T>,
        initial_quantum_key: Vec<u8>,
        mode: EnforcementMode,
    ) -> DispatchResult {
        let account = ensure_signed(origin)?;
        
        // Validate key size (Lamport public key)
        ensure!(
            initial_quantum_key.len() == 16384,
            Error::<T>::InvalidPublicKeySize
        );
        
        // Create key hash
        let key_hash = H256::from(sp_io::hashing::blake2_256(&initial_quantum_key));
        
        // Store Lamport key in separate storage
        let quantum_account_id = QuantumAccountId {
            algorithm: QuantumAlgorithm::Lamport,
            key_hash,
        };
        
        // Create wrapper
        let wrapper = QuantumWrapper {
            classical_account: account.clone(),
            quantum_key_hash: key_hash,
            tx_count: 0,
            enabled_at: frame_system::Pallet::<T>::block_number(),
            enforcement_mode: mode.clone(),
        };
        
        crate::QuantumWrappers::<T>::insert(&account, wrapper);
        
        crate::Pallet::<T>::deposit_event(crate::Event::QuantumWrapperEnabled {
            account,
            key_hash,
            mode: mode as u8,
        });
        
        Ok(())
    }
    
    /// Process a quantum-wrapped transaction
    pub fn submit_quantum_wrapped_tx(
        origin: OriginFor<T>,
        wrapped_tx: QuantumWrappedTx<T>,
    ) -> DispatchResult {
        let sender = ensure_signed(origin)?;
        
        // Get wrapper for account
        let wrapper = crate::QuantumWrappers::<T>::get(&sender)
            .ok_or(Error::<T>::NoQuantumWrapper)?;
        
        // Check enforcement mode
        let enforce = match wrapper.enforcement_mode {
            EnforcementMode::Optional => false,
            EnforcementMode::Required => true,
            EnforcementMode::Testing => false, // Log but don't enforce
            EnforcementMode::HighValueOnly => {
                // Check if transaction is high value
                // Decode the inner transaction to check for balance transfers
                if let Ok(call) = <T as frame_system::Config>::RuntimeCall::decode(
                    &mut &wrapped_tx.inner_tx[..]
                ) {
                    // Check if it's a balance transfer above threshold
                    // In production, this would check actual amounts in various pallets
                    match call {
                        // For now, we consider any transaction with data > 500 bytes as high value
                        // This could include batch calls, multi-sig operations, etc.
                        _ => wrapped_tx.inner_tx.len() > 500
                    }
                } else {
                    // If we can't decode, treat as high value to be safe
                    true
                }
            }
        };
        
        // Verify quantum signature if provided
        if let Some(ref quantum_sig) = wrapped_tx.quantum_signature {
            let tx_hash = sp_io::hashing::blake2_256(&wrapped_tx.inner_tx);
            
            // Create quantum account ID for verification
            let quantum_account = QuantumAccountId {
                algorithm: QuantumAlgorithm::Lamport,
                key_hash: wrapper.quantum_key_hash,
            };
            
            // Verify signature
            match Self::verify_lamport_signature(&quantum_account, quantum_sig, &tx_hash) {
                Ok(_) => {
                    // Success - increment counter
                    crate::QuantumWrappers::<T>::mutate(&sender, |w| {
                        if let Some(wrapper) = w {
                            wrapper.tx_count = wrapper.tx_count.saturating_add(1);
                        }
                    });
                    
                    crate::Pallet::<T>::deposit_event(crate::Event::QuantumTxVerified {
                        account: sender.clone(),
                        tx_count: wrapper.tx_count + 1,
                    });
                }
                Err(e) => {
                    if enforce {
                        return Err(e.into());
                    } else {
                        // Log failure but continue
                        crate::Pallet::<T>::deposit_event(crate::Event::QuantumVerificationFailed {
                            account: sender.clone(),
                            reason: format!("{:?}", e).into_bytes(),
                        });
                    }
                }
            }
        } else if enforce {
            return Err(Error::<T>::QuantumSignatureRequired.into());
        }
        
        // Process inner transaction (simplified - in real implementation would decode and execute)
        crate::Pallet::<T>::deposit_event(crate::Event::QuantumWrappedTxProcessed {
            account: sender,
            success: true,
        });
        
        Ok(())
    }
    
    /// Set global enforcement mode (governance only)
    pub fn set_global_enforcement(
        origin: OriginFor<T>,
        mode: EnforcementMode,
    ) -> DispatchResult {
        ensure_root(origin)?;
        
        crate::GlobalEnforcementMode::<T>::put(&mode);
        
        crate::Pallet::<T>::deposit_event(crate::Event::GlobalEnforcementChanged {
            new_mode: mode as u8,
        });
        
        Ok(())
    }
    
    /// Get quantum protection status for an account
    pub fn get_quantum_status(account: &T::AccountId) -> Option<(bool, EnforcementMode)> {
        crate::QuantumWrappers::<T>::get(account).map(|w| {
            (true, w.enforcement_mode)
        })
    }
}

// Note: Additional events and errors for quantum wrapper should be added to the main pallet in lib.rs

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enforcement_modes() {
        assert_eq!(
            EnforcementMode::Optional.encode().len(),
            1, // Single byte enum
        );
        
        // Test gradual rollout
        let modes = vec![
            EnforcementMode::Optional,
            EnforcementMode::Testing,
            EnforcementMode::HighValueOnly,
            EnforcementMode::Required,
        ];
        
        for (i, mode) in modes.iter().enumerate() {
            println!("Phase {}: {:?}", i, mode);
        }
    }
}