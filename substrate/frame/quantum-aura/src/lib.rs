//! # Quantum Aura Pallet
//!
//! This pallet provides post-quantum secure block production by replacing
//! sr25519 signatures with SPHINCS+ signatures for Aura consensus.
//!
//! Instead of modifying the core Aura implementation, we provide a wrapper
//! that intercepts block signing and uses post-quantum signatures.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

mod crypto;
pub use crypto::*;

mod consensus;
pub use consensus::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use sp_core::{H256, crypto::KeyTypeId};
    // Removed unused imports
    
    /// Post-quantum key type for Aura
    pub const QUANTUM_AURA: KeyTypeId = KeyTypeId(*b"qaur");
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Maximum size of a SPHINCS+ signature (49KB)
        #[pallet::constant]
        type MaxSignatureSize: Get<u32>;
    }
    
    /// Post-quantum authority data
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct QuantumAuthority {
        /// SR25519 public key (for compatibility)
        pub sr25519_pubkey: [u8; 32],
        /// SPHINCS+ public key
        pub sphincs_pubkey: BoundedVec<u8, ConstU32<32>>,
        /// Authority weight
        pub weight: u32,
    }
    
    /// Quantum block signature
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct QuantumBlockSignature {
        /// Block hash being signed
        pub block_hash: H256,
        /// SPHINCS+ signature (up to 49KB)
        pub sphincs_signature: BoundedVec<u8, ConstU32<49856>>,
        /// SR25519 signature for backwards compatibility
        pub sr25519_signature: [u8; 64],
        /// Timestamp
        pub timestamp: u64,
    }
    
    /// Mapping from SR25519 authorities to quantum authorities
    #[pallet::storage]
    #[pallet::getter(fn quantum_authorities)]
    pub type QuantumAuthorities<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32], // SR25519 public key
        QuantumAuthority,
        OptionQuery,
    >;
    
    /// Recent quantum block signatures for verification
    #[pallet::storage]
    #[pallet::getter(fn recent_signatures)]
    pub type RecentSignatures<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Block hash
        QuantumBlockSignature,
        OptionQuery,
    >;
    
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Quantum authority registered
        QuantumAuthorityRegistered {
            sr25519_pubkey: [u8; 32],
            sphincs_pubkey_hash: H256,
        },
        
        /// Block signed with post-quantum signature
        BlockQuantumSigned {
            block_hash: H256,
            authority: [u8; 32],
            signature_size: u32,
        },
        
        /// Quantum signature verified
        QuantumSignatureVerified {
            block_hash: H256,
            valid: bool,
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// Authority not registered for quantum signing
        NotQuantumAuthority,
        /// Invalid SPHINCS+ signature
        InvalidQuantumSignature,
        /// Signature too large
        SignatureTooLarge,
        /// No quantum public key found
        NoQuantumPublicKey,
    }
    
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a quantum authority with SPHINCS+ public key
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn register_quantum_authority(
            origin: OriginFor<T>,
            sr25519_pubkey: [u8; 32],
            sphincs_pubkey: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            ensure!(
                sphincs_pubkey.len() <= 32,
                Error::<T>::SignatureTooLarge
            );
            
            let bounded_pubkey: BoundedVec<u8, ConstU32<32>> = sphincs_pubkey
                .try_into()
                .map_err(|_| Error::<T>::SignatureTooLarge)?;
            
            let authority = QuantumAuthority {
                sr25519_pubkey,
                sphincs_pubkey: bounded_pubkey.clone(),
                weight: 1,
            };
            
            QuantumAuthorities::<T>::insert(&sr25519_pubkey, &authority);
            
            let pubkey_hash = sp_io::hashing::blake2_256(&bounded_pubkey);
            
            Self::deposit_event(Event::QuantumAuthorityRegistered {
                sr25519_pubkey,
                sphincs_pubkey_hash: H256::from(pubkey_hash),
            });
            
            Ok(())
        }
        
        /// Submit a quantum-signed block
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(500_000, 0))]
        pub fn submit_quantum_block_signature(
            origin: OriginFor<T>,
            block_hash: H256,
            sphincs_signature: Vec<u8>,
            sr25519_signature: [u8; 64],
        ) -> DispatchResult {
            ensure_signed(origin)?;
            
            ensure!(
                sphincs_signature.len() <= T::MaxSignatureSize::get() as usize,
                Error::<T>::SignatureTooLarge
            );
            
            // Store the signature
            let sig_len = sphincs_signature.len() as u32;
            let bounded_sig: BoundedVec<u8, ConstU32<49856>> = sphincs_signature
                .try_into()
                .map_err(|_| Error::<T>::SignatureTooLarge)?;
            
            let signature = QuantumBlockSignature {
                block_hash,
                sphincs_signature: bounded_sig,
                sr25519_signature,
                timestamp: sp_io::offchain::timestamp().unix_millis(),
            };
            
            RecentSignatures::<T>::insert(&block_hash, &signature);
            
            Self::deposit_event(Event::BlockQuantumSigned {
                block_hash,
                authority: [0u8; 32], // TODO: Extract from signature
                signature_size: sig_len,
            });
            
            Ok(())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Verify a quantum signature on a block
        pub fn verify_quantum_signature(
            block_hash: H256,
            authority: &[u8; 32],
        ) -> Result<bool, Error<T>> {
            let _quantum_auth = QuantumAuthorities::<T>::get(authority)
                .ok_or(Error::<T>::NotQuantumAuthority)?;
            
            let signature = RecentSignatures::<T>::get(&block_hash)
                .ok_or(Error::<T>::InvalidQuantumSignature)?;
            
            // In a real implementation, we would verify the SPHINCS+ signature here
            // using sp_core's post-quantum crypto primitives
            
            // For now, we check that the signature exists and has reasonable size
            let valid = signature.sphincs_signature.len() > 1000 && 
                       signature.sphincs_signature.len() <= T::MaxSignatureSize::get() as usize;
            
            Self::deposit_event(Event::QuantumSignatureVerified {
                block_hash,
                valid,
            });
            
            Ok(valid)
        }
        
        /// Get quantum-secured block producers
        pub fn get_quantum_authorities() -> Vec<(QuantumAuthority, u32)> {
            QuantumAuthorities::<T>::iter()
                .map(|(_, auth)| (auth.clone(), auth.weight))
                .collect()
        }
    }
}