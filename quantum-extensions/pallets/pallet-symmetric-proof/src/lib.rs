//! Symmetric Proof Pallet
//! 
//! Manages symmetric encryption with STARK proofs

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{Hash, SaturatedConversion};
use sp_std::vec::Vec;
use codec::Decode;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use sp_proof_storage::OnChainProofRecord;
    use sp_stark_crypto::{StarkProof, ProofType};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::storage]
    #[pallet::getter(fn proof_records)]
    pub type ProofRecords<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::Hash,
        OnChainProofRecord,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Encryption proof submitted
        ProofSubmitted {
            proof_hash: T::Hash,
            submitter: T::AccountId,
        },
        
        /// Proof verified
        ProofVerified {
            proof_hash: T::Hash,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Proof already exists
        ProofAlreadyExists,
        
        /// Invalid proof
        InvalidProof,
        
        /// Proof too large
        ProofTooLarge,
        
        /// Witness hash mismatch
        WitnessMismatch,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit an encryption proof
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn submit_proof(
            origin: OriginFor<T>,
            proof_bytes: Vec<u8>,
            witness_bytes: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Decode the STARK proof
            let stark_proof = StarkProof::decode(&mut &proof_bytes[..])
                .map_err(|_| Error::<T>::InvalidProof)?;
            
            // Verify proof size limit
            ensure!(
                stark_proof.proof_bytes.len() <= sp_stark_crypto::MAX_PROOF_SIZE,
                Error::<T>::ProofTooLarge
            );
            
            // Calculate proof hash
            let proof_hash = T::Hashing::hash_of(&proof_bytes);
            let witness_hash = T::Hashing::hash_of(&witness_bytes);
            
            // Verify witness hash matches the one in the proof
            ensure!(
                stark_proof.public_witness_hash == witness_hash.into(),
                Error::<T>::WitnessMismatch
            );
            
            // Get current block number
            let block_number = <frame_system::Pallet<T>>::block_number();
            
            // Create on-chain proof record
            let proof_record = OnChainProofRecord {
                proof_hash: proof_hash.into(),
                public_witness_hash: witness_hash.into(),
                verifier_signature: None, // Would be set by off-chain verifier
                block_number: block_number.saturated_into(),
                proof_type: stark_proof.proof_type as u8,
            };
            
            // Store proof record
            ProofRecords::<T>::insert(&proof_hash, proof_record);
            
            Self::deposit_event(Event::ProofSubmitted {
                proof_hash,
                submitter: who.clone(),
            });
            
            // Emit verification event based on proof type
            match stark_proof.proof_type {
                ProofType::SymmetricEncryption => {
                    Self::deposit_event(Event::ProofVerified {
                        proof_hash,
                        verifier: who,
                    });
                },
                _ => {
                    // Other proof types may require additional validation
                }
            }
            
            Ok(())
        }
    }
}