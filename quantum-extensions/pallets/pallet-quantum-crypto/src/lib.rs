#![cfg_attr(not(feature = "std"), no_std)]

//! # Quantum Crypto Pallet
//!
//! Implements post-quantum cryptography and QKD integration for the blockchain.
//! 
//! ## Features
//! - Dual signature schemes (SPHINCS+ and Falcon)
//! - Context-aware signature switching
//! - QKD integration for key distribution
//! - Quantum entropy management
//! - STARK proof verification

use frame_support::{
    dispatch::DispatchResult,
    pallet_prelude::*,
    traits::{Randomness, UnixTime},
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{BlakeTwo256, Hash, Saturating, Zero};
use sp_std::{vec::Vec, prelude::*};
use codec::{Encode, Decode};
use scale_info::TypeInfo;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        
        /// Source of randomness for quantum operations
        type QuantumRandomness: Randomness<Self::Hash, BlockNumberFor<Self>>;
        
        /// Unix time provider
        type UnixTime: UnixTime;
        
        /// Minimum QBER threshold for QKD (11% = 110 per mille)
        #[pallet::constant]
        type MaxQBER: Get<u32>;
        
        /// Minimum entropy required for operations (bits)
        #[pallet::constant]
        type MinEntropy: Get<u32>;
        
        /// Maximum size for SPHINCS+ signatures
        #[pallet::constant]
        type MaxSignatureSize: Get<u32>;
    }

    /// Quantum signature schemes available
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub enum SignatureScheme {
        /// SPHINCS+ for high security (larger signatures)
        SphincsPlus,
        /// Falcon for bandwidth-constrained environments
        Falcon512,
    }

    /// QKD key metadata
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct QKDKey {
        /// Key ID from QKD system
        pub id: Vec<u8>,
        /// Quantum Bit Error Rate (per mille)
        pub qber: u32,
        /// Key material (encrypted)
        pub encrypted_key: Vec<u8>,
        /// Source QKD device
        pub source: Vec<u8>,
        /// Timestamp of generation
        pub timestamp: u64,
    }

    /// Quantum entropy pool entry
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct EntropyEntry {
        /// Raw entropy data
        pub data: Vec<u8>,
        /// Source (KIRQ, QKD, etc)
        pub source: Vec<u8>,
        /// Quality metric (0-1000)
        pub quality: u32,
        /// Block number when added
        pub block_number: BlockNumberFor<T>,
    }

    /// Context for signature scheme selection
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct SignatureContext {
        /// Available bandwidth (bytes/sec)
        pub bandwidth: u32,
        /// Security level required (1-5)
        pub security_level: u8,
        /// Is this a critical operation?
        pub is_critical: bool,
    }

    #[pallet::storage]
    #[pallet::getter(fn qkd_keys)]
    pub type QKDKeys<T: Config> = StorageMap<_, Blake2_128Concat, Vec<u8>, QKDKey>;

    #[pallet::storage]
    #[pallet::getter(fn entropy_pool)]
    pub type EntropyPool<T: Config> = StorageValue<_, Vec<EntropyEntry<T>>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn preferred_scheme)]
    pub type PreferredScheme<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, SignatureScheme>;

    #[pallet::storage]
    #[pallet::getter(fn total_entropy_bits)]
    pub type TotalEntropyBits<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// QKD key registered
        QKDKeyRegistered { key_id: Vec<u8>, qber: u32 },
        
        /// Entropy added to pool
        EntropyAdded { source: Vec<u8>, bits: u32 },
        
        /// Signature scheme switched
        SchemeChanged { 
            who: T::AccountId, 
            from: SignatureScheme, 
            to: SignatureScheme 
        },
        
        /// STARK proof verified
        STARKProofVerified { proof_hash: T::Hash },
        
        /// Low entropy warning
        LowEntropyWarning { available: u32, required: u32 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// QBER too high (potential eavesdropping)
        QBERTooHigh,
        /// Insufficient entropy
        InsufficientEntropy,
        /// Invalid signature
        InvalidSignature,
        /// QKD key not found
        QKDKeyNotFound,
        /// Signature too large
        SignatureTooLarge,
        /// Invalid STARK proof
        InvalidSTARKProof,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new QKD key
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn register_qkd_key(
            origin: OriginFor<T>,
            key_id: Vec<u8>,
            qber: u32,
            encrypted_key: Vec<u8>,
            source: Vec<u8>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            // Check QBER threshold
            ensure!(qber <= T::MaxQBER::get(), Error::<T>::QBERTooHigh);
            
            let timestamp = T::UnixTime::now().as_secs();
            
            let qkd_key = QKDKey {
                id: key_id.clone(),
                qber,
                encrypted_key,
                source,
                timestamp,
            };
            
            QKDKeys::<T>::insert(&key_id, &qkd_key);
            
            Self::deposit_event(Event::QKDKeyRegistered { key_id, qber });
            
            Ok(())
        }
        
        /// Add entropy to the pool
        #[pallet::call_index(1)]
        #[pallet::weight(5_000)]
        pub fn add_entropy(
            origin: OriginFor<T>,
            data: Vec<u8>,
            source: Vec<u8>,
            quality: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            let bits = (data.len() * 8) as u32;
            let block_number = frame_system::Pallet::<T>::block_number();
            
            let entry = EntropyEntry {
                data,
                source: source.clone(),
                quality,
                block_number,
            };
            
            EntropyPool::<T>::mutate(|pool| {
                pool.push(entry);
                // Keep pool size reasonable
                if pool.len() > 100 {
                    pool.remove(0);
                }
            });
            
            TotalEntropyBits::<T>::mutate(|total| *total = total.saturating_add(bits));
            
            Self::deposit_event(Event::EntropyAdded { source, bits });
            
            Ok(())
        }
        
        /// Set preferred signature scheme
        #[pallet::call_index(2)]
        #[pallet::weight(1_000)]
        pub fn set_signature_scheme(
            origin: OriginFor<T>,
            scheme: SignatureScheme,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            let old_scheme = PreferredScheme::<T>::get(&who)
                .unwrap_or(SignatureScheme::SphincsPlus);
            
            PreferredScheme::<T>::insert(&who, &scheme);
            
            Self::deposit_event(Event::SchemeChanged {
                who,
                from: old_scheme,
                to: scheme,
            });
            
            Ok(())
        }
        
        /// Verify a STARK proof
        #[pallet::call_index(3)]
        #[pallet::weight(50_000)]
        pub fn verify_stark_proof(
            origin: OriginFor<T>,
            proof: Vec<u8>,
            public_input: Vec<u8>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            // TODO: Implement actual STARK verification
            // For now, we just check basic validity
            ensure!(!proof.is_empty(), Error::<T>::InvalidSTARKProof);
            ensure!(!public_input.is_empty(), Error::<T>::InvalidSTARKProof);
            
            let proof_hash = T::Hashing::hash(&proof);
            
            Self::deposit_event(Event::STARKProofVerified { proof_hash });
            
            Ok(())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Select signature scheme based on context
        pub fn select_scheme(context: &SignatureContext) -> SignatureScheme {
            if context.is_critical {
                // Critical operations always use SPHINCS+
                SignatureScheme::SphincsPlus
            } else if context.bandwidth < 1000 {
                // Low bandwidth: use Falcon
                SignatureScheme::Falcon512
            } else if context.security_level >= 4 {
                // High security: use SPHINCS+
                SignatureScheme::SphincsPlus
            } else {
                // Default to Falcon for efficiency
                SignatureScheme::Falcon512
            }
        }
        
        /// Check if sufficient entropy is available
        pub fn check_entropy() -> Result<(), Error<T>> {
            let available = TotalEntropyBits::<T>::get();
            let required = T::MinEntropy::get();
            
            if available < required {
                Self::deposit_event(Event::LowEntropyWarning { available, required });
                return Err(Error::<T>::InsufficientEntropy);
            }
            
            Ok(())
        }
        
        /// Get quantum randomness
        pub fn get_quantum_random(length: usize) -> Vec<u8> {
            let (random_seed, _) = T::QuantumRandomness::random(&b"quantum"[..]);
            let mut result = random_seed.encode();
            result.resize(length, 0);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn scheme_selection_works() {
        // Low bandwidth selects Falcon
        let context = SignatureContext {
            bandwidth: 500,
            security_level: 3,
            is_critical: false,
        };
        assert_eq!(Pallet::<Test>::select_scheme(&context), SignatureScheme::Falcon512);
        
        // Critical operations select SPHINCS+
        let context = SignatureContext {
            bandwidth: 10000,
            security_level: 2,
            is_critical: true,
        };
        assert_eq!(Pallet::<Test>::select_scheme(&context), SignatureScheme::SphincsPlus);
    }
}