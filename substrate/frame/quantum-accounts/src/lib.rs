//! # Quantum Accounts Pallet
//!
//! This pallet enforces post-quantum signatures for all transactions,
//! replacing classical ed25519/sr25519 with quantum-resistant alternatives.
//!
//! ## Overview
//!
//! The pallet provides:
//! - Quantum-resistant account creation
//! - Post-quantum transaction signature verification
//! - Migration path from classical to quantum accounts
//! - Support for both Falcon-512 (efficient) and SPHINCS+ (maximum security)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

// R&D modules for quantum account experimentation
pub mod lamport_account;
pub mod quantum_wrapper;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::{vec::Vec, vec};
    use core::fmt::Debug;
    use sp_core::{H256, crypto::KeyTypeId};
    
    /// Quantum account key type
    pub const QUANTUM_ACCOUNT: KeyTypeId = KeyTypeId(*b"qact");
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config {
        
        /// Maximum size of a quantum signature (SPHINCS+ = 49KB)
        #[pallet::constant]
        type MaxQuantumSignatureSize: Get<u32>;
        
        /// Whether to allow Falcon-512 for regular transactions
        #[pallet::constant]
        type AllowFalconForTransactions: Get<bool>;
        
        /// Migration deadline block number (after which classical signatures are rejected)
        #[pallet::constant]
        type ClassicalSignatureSunsetBlock: Get<BlockNumberFor<Self>>;
    }
    
    /// Type alias for nonce
    pub type Nonce = u32;
    
    /// Quantum signature algorithms
    #[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq)]
    pub enum QuantumAlgorithm {
        /// Falcon-512 (690 bytes) - efficient
        Falcon512,
        /// SPHINCS+ (49KB) - maximum security
        SphincsPlus,
        /// Lamport (8KB signatures, 16KB keys) - information-theoretic security
        Lamport,
    }
    
    impl QuantumAlgorithm {
        fn to_u8(&self) -> u8 {
            match self {
                QuantumAlgorithm::Falcon512 => 0,
                QuantumAlgorithm::SphincsPlus => 1,
                QuantumAlgorithm::Lamport => 2,
            }
        }
    }
    
    /// Quantum account identifier
    #[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, PartialEq, Eq)]
    pub struct QuantumAccountId {
        /// Algorithm used
        pub algorithm: QuantumAlgorithm,
        /// Public key hash (32 bytes)
        pub key_hash: H256,
    }
    
    /// Quantum signature for transactions
    #[derive(Clone, Encode, Decode, TypeInfo)]
    pub struct QuantumSignature {
        /// Algorithm used
        pub algorithm: QuantumAlgorithm,
        /// The actual signature bytes
        pub signature: Vec<u8>,
        /// Timestamp for replay protection
        pub timestamp: u64,
    }
    
    /// Mapping from classical accounts to quantum accounts (for migration)
    #[pallet::storage]
    #[pallet::getter(fn quantum_migration)]
    pub type QuantumMigration<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        QuantumAccountId,
        OptionQuery,
    >;
    
    /// Registered quantum accounts
    #[pallet::storage]
    #[pallet::getter(fn quantum_accounts)]
    pub type QuantumAccounts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        QuantumAccountId,
        AccountInfo<T>,
        OptionQuery,
    >;
    
    /// Storage for Lamport accounts
    #[pallet::storage]
    pub type LamportAccounts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        QuantumAccountId,
        crate::lamport_account::LamportAccount,
        OptionQuery,
    >;
    
    /// Storage for quantum wrappers
    #[pallet::storage]
    pub type QuantumWrappers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        crate::quantum_wrapper::QuantumWrapper<T>,
        OptionQuery,
    >;
    
    /// Global quantum enforcement mode
    #[pallet::storage]
    pub type GlobalEnforcementMode<T: Config> = StorageValue<
        _,
        crate::quantum_wrapper::EnforcementMode,
        ValueQuery,
    >;
    
    /// Account information
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct AccountInfo<T: Config> {
        /// Account nonce
        pub nonce: Nonce,
        /// Public key bytes
        pub public_key: BoundedVec<u8, ConstU32<1024>>, // Max 1KB for public keys
        /// Registration block
        pub registered_at: BlockNumberFor<T>,
    }
    
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Quantum account registered
        QuantumAccountRegistered {
            account: H256, // Key hash
            algorithm: u8,
        },
        
        /// Classical account migrated to quantum
        AccountMigrated {
            classical: T::AccountId,
            quantum: H256, // Key hash
        },
        
        /// Quantum transaction validated
        QuantumTransactionValidated {
            account: H256, // Key hash
            nonce: Nonce,
        },
        
        /// Classical signature rejected after sunset
        ClassicalSignatureRejected {
            account: T::AccountId,
            current_block: BlockNumberFor<T>,
        },
        
        /// Key rotation required for Lamport account
        KeyRotationRequired {
            account: H256,
        },
        
        /// Quantum wrapper enabled for account
        QuantumWrapperEnabled {
            account: T::AccountId,
            key_hash: H256,
            mode: u8, // EnforcementMode as u8
        },
        
        /// Quantum transaction verified successfully
        QuantumTxVerified {
            account: T::AccountId,
            tx_count: u32,
        },
        
        /// Quantum verification failed (but tx may proceed)
        QuantumVerificationFailed {
            account: T::AccountId,
            reason: Vec<u8>, // String as bytes
        },
        
        /// Quantum wrapped transaction processed
        QuantumWrappedTxProcessed {
            account: T::AccountId,
            success: bool,
        },
        
        /// Global enforcement mode changed
        GlobalEnforcementChanged {
            new_mode: u8, // EnforcementMode as u8
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// Quantum signature too large
        SignatureTooLarge,
        /// Invalid quantum signature
        InvalidQuantumSignature,
        /// Account not registered
        AccountNotRegistered,
        /// Classical signatures no longer accepted
        ClassicalSignaturesSunset,
        /// Falcon not allowed for this operation
        FalconNotAllowed,
        /// Invalid public key size
        InvalidPublicKeySize,
        /// Account already migrated
        AlreadyMigrated,
        /// Nonce mismatch
        NonceMismatch,
        /// Key rotation required before next use
        KeyRotationRequired,
        /// Public key mismatch
        KeyMismatch,
        /// Account has no quantum wrapper
        NoQuantumWrapper,
        /// Quantum signature required but not provided
        QuantumSignatureRequired,
        /// Invalid quantum wrapper configuration
        InvalidWrapperConfig,
    }
    
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new quantum account
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn register_quantum_account(
            origin: OriginFor<T>,
            algorithm: u8,
            public_key: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            
            // Convert u8 to QuantumAlgorithm
            let algorithm = match algorithm {
                0 => QuantumAlgorithm::Falcon512,
                1 => QuantumAlgorithm::SphincsPlus,
                2 => QuantumAlgorithm::Lamport,
                _ => return Err(Error::<T>::InvalidQuantumSignature.into()),
            };
            
            // Validate public key size
            let max_size = match algorithm {
                QuantumAlgorithm::Falcon512 => 897,  // Falcon-512 public key
                QuantumAlgorithm::SphincsPlus => 64, // SPHINCS+ public key
                QuantumAlgorithm::Lamport => 8192,   // Lamport public key
            };
            
            ensure!(
                public_key.len() <= max_size,
                Error::<T>::InvalidPublicKeySize
            );
            
            // Create account ID from key hash
            let key_hash = sp_io::hashing::blake2_256(&public_key);
            let account_id = QuantumAccountId {
                algorithm: algorithm.clone(),
                key_hash: H256::from(key_hash),
            };
            
            // Store account info
            let bounded_key: BoundedVec<u8, ConstU32<1024>> = public_key
                .try_into()
                .map_err(|_| Error::<T>::InvalidPublicKeySize)?;
                
            let info = AccountInfo {
                nonce: 0,
                public_key: bounded_key,
                registered_at: frame_system::Pallet::<T>::block_number(),
            };
            
            QuantumAccounts::<T>::insert(&account_id, info);
            
            Self::deposit_event(Event::QuantumAccountRegistered {
                account: account_id.key_hash,
                algorithm: algorithm.to_u8(),
            });
            
            Ok(())
        }
        
        /// Migrate a classical account to quantum
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(150_000, 0))]
        pub fn migrate_to_quantum(
            origin: OriginFor<T>,
            quantum_key_hash: H256,
            algorithm: u8,
            _proof: Vec<u8>, // Proof of ownership
        ) -> DispatchResult {
            let classical_account = ensure_signed(origin)?;
            
            // Convert u8 to QuantumAlgorithm
            let algorithm = match algorithm {
                0 => QuantumAlgorithm::Falcon512,
                1 => QuantumAlgorithm::SphincsPlus,
                2 => QuantumAlgorithm::Lamport,
                _ => return Err(Error::<T>::InvalidQuantumSignature.into()),
            };
            
            // Reconstruct quantum account ID
            let quantum_account = QuantumAccountId {
                algorithm,
                key_hash: quantum_key_hash,
            };
            
            // Check not already migrated
            ensure!(
                !QuantumMigration::<T>::contains_key(&classical_account),
                Error::<T>::AlreadyMigrated
            );
            
            // Verify the quantum account exists
            ensure!(
                QuantumAccounts::<T>::contains_key(&quantum_account),
                Error::<T>::AccountNotRegistered
            );
            
            // TODO: Verify proof of ownership
            // In production, this would verify a signature from the quantum key
            // proving ownership of the classical account
            
            // Store migration mapping
            QuantumMigration::<T>::insert(&classical_account, &quantum_account);
            
            Self::deposit_event(Event::AccountMigrated {
                classical: classical_account,
                quantum: quantum_account.key_hash,
            });
            
            Ok(())
        }
    }
    
    // Transaction validation
    impl<T: Config> Pallet<T> {
        /// Validate a quantum signature
        pub fn validate_quantum_signature(
            account: &QuantumAccountId,
            signature: &QuantumSignature,
            message: &[u8],
        ) -> Result<(), Error<T>> {
            // Check signature size
            let max_size = match signature.algorithm {
                QuantumAlgorithm::Falcon512 => 690,
                QuantumAlgorithm::SphincsPlus => 49856,
                QuantumAlgorithm::Lamport => 8192,
            };
            
            ensure!(
                signature.signature.len() <= max_size,
                Error::<T>::SignatureTooLarge
            );
            
            // Check if Falcon is allowed
            if matches!(signature.algorithm, QuantumAlgorithm::Falcon512) {
                ensure!(
                    T::AllowFalconForTransactions::get(),
                    Error::<T>::FalconNotAllowed
                );
            }
            
            // Get account info
            let info = QuantumAccounts::<T>::get(account)
                .ok_or(Error::<T>::AccountNotRegistered)?;
            
            // In production, verify the actual quantum signature
            // For now, we just check the algorithm matches
            ensure!(
                account.algorithm == signature.algorithm,
                Error::<T>::InvalidQuantumSignature
            );
            
            Ok(())
        }
        
        /// Check if classical signatures are still allowed
        pub fn check_classical_sunset() -> Result<(), Error<T>> {
            let current_block = frame_system::Pallet::<T>::block_number();
            let sunset_block = T::ClassicalSignatureSunsetBlock::get();
            
            if current_block >= sunset_block {
                return Err(Error::<T>::ClassicalSignaturesSunset);
            }
            
            Ok(())
        }
    }
    
    /// Hooks for enforcing quantum signatures
    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Check if we've reached the classical signature sunset
            if n == T::ClassicalSignatureSunsetBlock::get() {
                log::warn!(
                    "Classical signature sunset reached at block {:?}. \
                    Only quantum signatures will be accepted from now on.",
                    n
                );
            }
            
            Weight::from_parts(1000, 0)
        }
    }
}

/// Extension trait for quantum signature verification
pub trait QuantumVerify {
    /// Verify a quantum signature
    fn verify_quantum(&self, message: &[u8], signer: &QuantumAccountId) -> bool;
}

impl QuantumVerify for QuantumSignature {
    fn verify_quantum(&self, _message: &[u8], signer: &QuantumAccountId) -> bool {
        // In production, this would call the actual quantum signature verification
        // For now, just check algorithm compatibility
        self.algorithm == signer.algorithm
    }
}