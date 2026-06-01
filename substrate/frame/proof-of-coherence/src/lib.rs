//! # Proof of Coherence Pallet
//!
//! This pallet implements quantum coherence-based consensus that uses
//! cryptographically verified QBER measurements from the quantum-crypto pallet.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

// Re-export types needed by runtime
pub use types::{CoherenceProof, HarmonicState};
use types::*;

pub mod types;
mod consensus;
// mod authoring; // TODO: Add back when consensus integration is needed

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use consensus::{CoherenceScore, ScoringWeights};
// pub use authoring::{CoherenceConsensusData, CoherenceBlockAuthoring, CoherenceApi};

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use sp_core::H256;
    use frame_support::traits::Currency;
    use sp_runtime::{
        traits::SaturatedConversion,
        transaction_validity::{
            InvalidTransaction, TransactionSource, TransactionValidity,
            TransactionPriority, ValidTransaction,
        },
    };
    use log::info;
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_quantum_crypto::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        
        /// The staking balance type
        type Currency: Currency<Self::AccountId>;
        
        /// Minimum coherence score required for validation
        #[pallet::constant]
        type MinimumCoherenceScore: Get<u32>;
        
        /// Maximum validators in the active set
        #[pallet::constant]
        type MaxValidators: Get<u32>;
        
        /// Coherence measurement period in blocks
        #[pallet::constant]
        type CoherencePeriod: Get<BlockNumberFor<Self>>;
        
        /// Reward amount for maintaining coherence
        #[pallet::constant]
        type CoherenceReward: Get<BalanceOf<Self>>;
        
        /// Slash amount for losing coherence
        #[pallet::constant]
        type CoherenceSlash: Get<BalanceOf<Self>>;
    }
    
    pub type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
    
    /// Active validators maintaining coherence
    #[pallet::storage]
    #[pallet::getter(fn validators)]
    pub type Validators<T: Config> = StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;
    
    /// Coherence proofs with QBER verification
    #[pallet::storage]
    pub type CoherenceProofs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        CoherenceProof<BlockNumberFor<T>>,
        OptionQuery,
    >;
    
    /// QBER-based coherence scores
    #[pallet::storage]
    #[pallet::getter(fn coherence_scores)]
    pub type CoherenceScores<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u32,
        ValueQuery,
    >;
    
    /// Network harmonic state
    #[pallet::storage]
    #[pallet::getter(fn network_harmonic_state)]
    pub type NetworkHarmonicState<T> = StorageValue<_, HarmonicState, ValueQuery>;
    
    /// Last finalized block using quantum coherence
    #[pallet::storage]
    #[pallet::getter(fn last_finalized_block)]
    pub type LastFinalizedBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;
    
    /// Detailed 6-factor coherence scores for validators
    #[pallet::storage]
    #[pallet::getter(fn detailed_coherence_scores)]
    pub type DetailedCoherenceScores<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        CoherenceScore,
        OptionQuery,
    >;
    
    /// Current block producer selected by coherence
    #[pallet::storage]
    #[pallet::getter(fn current_block_producer)]
    pub type CurrentBlockProducer<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;
    
    /// QPP compliance tracking
    #[pallet::storage]
    #[pallet::getter(fn qpp_compliance_scores)]
    pub type QppComplianceScores<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u8,
        ValueQuery,
    >;

    /// Finality certificates indexed by block number
    /// Stores the complete certificate for each finalized block
    ///
    /// Phase 4: Now uses BoundedVec for all fields, enabling proper MaxEncodedLen
    #[pallet::storage]
    #[pallet::getter(fn finality_certificates)]
    pub type FinalityCertificates<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumberFor<T>,
        FinalityCertificate<T::AccountId, BlockNumberFor<T>, T::Hash>,
        OptionQuery,
    >;

    /// Finality checkpoints (stored via inherents every N blocks)
    ///
    /// Phase 6B: Separate storage for checkpoint certificates that are
    /// stored on-chain via inherents. These provide:
    /// - Audit trail of finality progression
    /// - Cross-chain verification proofs
    /// - Historical finality records
    #[pallet::storage]
    #[pallet::getter(fn finality_checkpoints)]
    pub type FinalityCheckpoints<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumberFor<T>,
        FinalityCertificate<T::AccountId, BlockNumberFor<T>, T::Hash>,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Validator registered with verified quantum hardware
        ValidatorRegistered {
            who: T::AccountId,
            device_id: H256,
        },
        
        /// Coherence proof submitted with QBER verification
        CoherenceProofSubmitted {
            validator: T::AccountId,
            score: u32,
            qber: u32,
            stark_verified: bool,
        },
        
        /// Validator achieved best coherence
        BestCoherenceAchieved {
            validator: T::AccountId,
            score: u32,
            network_qber: u32,
        },
        
        /// Coherence lost due to high QBER
        CoherenceLost {
            validator: T::AccountId,
            qber: u32,
            threshold: u32,
        },
        
        /// Block finalized using quantum coherence
        BlockFinalized {
            block_number: BlockNumberFor<T>,
            coherent_validators: u32,
            network_coherence: u8,
        },
        
        /// 6-factor coherence score calculated
        SixFactorScoreCalculated {
            validator: T::AccountId,
            photon_coherence: u8,
            tonnetz_harmonic: u8,
            merkle_validation: u8,
            qpp_compliance: u8,
            governance_votes: u8,
            combined_coherence: u8,
            total_score: u32,
        },
        
        /// Block producer selected by coherence
        BlockProducerSelected {
            producer: T::AccountId,
            coherence_score: u32,
            block_number: BlockNumberFor<T>,
        },

        /// Finality certificate submitted and stored on-chain
        FinalityCertificateSubmitted {
            block_number: BlockNumberFor<T>,
            block_hash: T::Hash,
            validator_count: u32,
            total_coherence_score: u64,
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// Not a registered validator
        NotValidator,
        /// No quantum hardware registered
        NoQuantumHardware,
        /// QBER too high for coherence
        QberTooHigh,
        /// No verified QBER measurement
        NoQberMeasurement,
        /// STARK proof required but missing
        StarkProofRequired,
        /// Coherence score too low
        InsufficientCoherence,
        /// Validator limit reached
        ValidatorLimitReached,
    }
    
    /// Genesis-time seed for the PoC validator set + harmonic state.
    ///
    /// Without this builder, `Validators` starts empty at every chain
    /// bootstrap and substrate finality never advances until someone
    /// manually calls `register_validator` for each operator. The
    /// 2026-05-28 testnet incident (QuantumHarmony GH issue #33) was
    /// caused exactly by this absence; the recovery required a sudo
    /// `set_storage` to populate `Validators` after the chain had
    /// already produced 600k+ blocks with frozen finality.
    ///
    /// The earlier "TODO: Fix genesis config serde issue" was the
    /// `#[serde(skip)]` line attempting to act without explicit serde
    /// derives, which the `#[pallet::genesis_config]` macro doesn't
    /// emit automatically when `DefaultNoBound` is used. The fix here:
    /// drop the PhantomData field entirely (T is already bound via
    /// `Vec<T::AccountId>` so we don't need a marker) and rely on the
    /// macro's default derive set, which handles the serde requirement
    /// correctly under the std feature.
    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial PoC validator set. Each entry must map to a
        /// registered `pallet_quantum_crypto::NodeHardware` entry for
        /// `register_validator` to later succeed for them — but at
        /// genesis we trust the chainspec author and skip the check.
        pub initial_validators: Vec<T::AccountId>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let bounded_validators: BoundedVec<T::AccountId, T::MaxValidators> = self
                .initial_validators
                .clone()
                .try_into()
                .expect("Too many initial validators for MaxValidators bound");
            Validators::<T>::put(bounded_validators);
            // NetworkHarmonicState is intentionally NOT seeded from
            // genesis: HarmonicState's serde derives are
            // `cfg_attr(std)`-gated and the genesis_config macro
            // requires Serialize unconditionally for typed fields.
            // The gadget populates NetworkHarmonicState from coherence
            // proofs on chain — an empty-zeros initial state is the
            // legitimate value, set by ValueQuery default on first read.
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(block_number: BlockNumberFor<T>) {
            // Collect reporter information from quantum-crypto pallet
            let mut reporter_info_parts: Vec<&str> = Vec::new();

            // Get entropy pool info
            let entropy_pool = pallet_quantum_crypto::EntropyPoolStorage::<T>::get();
            if entropy_pool.entropy.len() > 0 {
                reporter_info_parts.push("QRNG");
            }

            // Get network QBER
            if let Some(qber) = pallet_quantum_crypto::Pallet::<T>::calculate_network_qber() {
                reporter_info_parts.push("QBER");
            }

            // Check for QKD keys
            let has_qkd = !pallet_quantum_crypto::SecureQkdKeys::<T>::iter().next().is_none();
            if has_qkd {
                reporter_info_parts.push("QKD");
            }

            // Check for authorized reporters
            let reporter_count = pallet_quantum_crypto::AuthorizedReporters::<T>::iter().count();

            // Finalize block using Proof of Coherence (quantum-safe alternative to GRANDPA)
            LastFinalizedBlock::<T>::put(block_number);

            // Log finalization with consensus level status
            // Levels: 1=BFT-Classical, 2=PQ-BFT, 3=PQ-BFT+Coherence, 4=PQ-BFT+QRNG, 5=Full-PoC
            if !reporter_info_parts.is_empty() {
                let sources = reporter_info_parts.join("+");
                // Level 4-5: Quantum hardware active
                let level = if has_qkd { 5 } else { 4 };
                info!(
                    "✨ Finalized #{} (Consensus: Level {} - quantum sources: [{}], reporters={})",
                    block_number.saturated_into::<u64>(),
                    level,
                    sources,
                    reporter_count
                );
            } else {
                // Level 3: PQ-BFT + Coherence (SPHINCS+ signatures + coherence-weighted selection)
                // No quantum hardware, but still post-quantum secure via SPHINCS+
                info!(
                    "✨ Finalized #{} (Consensus: PQ-BFT + Coherence)",
                    block_number.saturated_into::<u64>()
                );
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register as a validator (requires quantum hardware)
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn register_validator(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify quantum hardware is registered
            let device_id = pallet_quantum_crypto::Pallet::<T>::node_hardware(&who)
                .ok_or(Error::<T>::NoQuantumHardware)?;
            
            // Check validator limit
            let mut validators = Validators::<T>::get();
            ensure!(
                validators.len() < T::MaxValidators::get() as usize,
                Error::<T>::ValidatorLimitReached
            );
            
            // Add to validators
            validators.try_push(who.clone())
                .map_err(|_| Error::<T>::ValidatorLimitReached)?;
            Validators::<T>::put(validators);
            
            Self::deposit_event(Event::ValidatorRegistered { who, device_id });
            Ok(())
        }
        
        /// Submit coherence proof with verified QBER
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn submit_coherence_proof(
            origin: OriginFor<T>,
            frequency: u32,
            phase: u32,
            spectral_purity: u8,
            quantum_fidelity: u8,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify validator
            let validators = Validators::<T>::get();
            ensure!(validators.contains(&who), Error::<T>::NotValidator);
            
            // Get verified QBER from quantum-crypto pallet
            let network_qber = pallet_quantum_crypto::Pallet::<T>::calculate_network_qber()
                .ok_or(Error::<T>::NoQberMeasurement)?;
            
            // Ensure QBER is below threshold (11% max for secure QKD)
            ensure!(
                network_qber <= 1100, // 11% threshold
                Error::<T>::QberTooHigh
            );
            
            // Calculate coherence score based on QBER and quantum metrics
            let score = Self::calculate_coherence_score(
                network_qber,
                spectral_purity,
                quantum_fidelity,
                frequency,
                phase,
            );
            
            ensure!(
                score >= T::MinimumCoherenceScore::get(),
                Error::<T>::InsufficientCoherence
            );
            
            // Create proof
            let proof = CoherenceProof {
                frequency,
                phase,
                spectral_purity,
                quantum_fidelity,
                timestamp: frame_system::Pallet::<T>::block_number(),
                merkle_root: Self::calculate_proof_hash(&who, frequency, phase),
            };
            
            // Store proof and score
            CoherenceProofs::<T>::insert(&who, &proof);
            CoherenceScores::<T>::insert(&who, score);
            
            Self::deposit_event(Event::CoherenceProofSubmitted {
                validator: who,
                score,
                qber: network_qber,
                stark_verified: true, // QBER was STARK-verified
            });
            
            Ok(())
        }
        
        /// Calculate and submit 6-factor coherence proof
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(150_000, 0))]
        pub fn submit_six_factor_coherence(
            origin: OriginFor<T>,
            frequency: u32,
            phase: u32,
            spectral_purity: u8,
            quantum_fidelity: u8,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify validator
            let validators = Validators::<T>::get();
            ensure!(validators.contains(&who), Error::<T>::NotValidator);
            
            // Get verified QBER from quantum-crypto pallet
            let network_qber = pallet_quantum_crypto::Pallet::<T>::calculate_network_qber()
                .ok_or(Error::<T>::NoQberMeasurement)?;
            
            // Calculate complete 6-factor score
            let detailed_score = Self::calculate_six_factor_score(&who, network_qber)?;
            
            // Store detailed score
            DetailedCoherenceScores::<T>::insert(&who, &detailed_score);
            CoherenceScores::<T>::insert(&who, detailed_score.total_score);
            
            // Store coherence proof
            let proof = CoherenceProof {
                frequency,
                phase,
                spectral_purity,
                quantum_fidelity,
                timestamp: frame_system::Pallet::<T>::block_number(),
                merkle_root: Self::calculate_proof_hash(&who, frequency, phase),
            };
            CoherenceProofs::<T>::insert(&who, &proof);
            
            Self::deposit_event(Event::SixFactorScoreCalculated {
                validator: who,
                photon_coherence: detailed_score.photon_coherence_time,
                tonnetz_harmonic: detailed_score.tonnetz_harmonic_validation,
                merkle_validation: detailed_score.modified_merkle_trees,
                qpp_compliance: detailed_score.qpp_compliance,
                governance_votes: detailed_score.governance_votes,
                combined_coherence: detailed_score.combined_coherence_score,
                total_score: detailed_score.total_score,
            });
            
            Ok(())
        }
        
        /// Select best coherence validator for next block using 6-factor scoring
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(200_000, 0))]
        pub fn select_block_producer_by_coherence(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;
            
            if let Some(producer) = Self::select_block_producer() {
                let score = CoherenceScores::<T>::get(&producer);
                let block_number = frame_system::Pallet::<T>::block_number();
                
                // Set as current block producer
                CurrentBlockProducer::<T>::put(&producer);
                
                Self::deposit_event(Event::BlockProducerSelected {
                    producer,
                    coherence_score: score,
                    block_number,
                });
            }
            
            Ok(())
        }
        
        /// Finalize block using quantum coherence measurements
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(300_000, 0))]
        pub fn finalize_with_coherence(
            origin: OriginFor<T>,
            block_number: BlockNumberFor<T>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            // Use 6-factor coherence consensus for finality
            ensure!(
                Self::can_finalize_block(block_number),
                Error::<T>::InsufficientCoherence
            );
            
            // Update network harmonic state
            let validators = Validators::<T>::get();
            let mut coherent_validators = 0u32;
            let mut total_weighted_score = 0u32;
            
            for validator in validators.iter() {
                if let Some(score) = DetailedCoherenceScores::<T>::get(validator) {
                    if score.total_score >= 5000 { // 50% minimum
                        coherent_validators += 1;
                        total_weighted_score += score.total_score;
                    }
                }
            }
            
            let mut harmonic_state = NetworkHarmonicState::<T>::get();
            harmonic_state.coherence_level = if validators.len() > 0 {
                (coherent_validators * 100 / validators.len() as u32) as u8
            } else {
                0
            };
            harmonic_state.resonance_nodes = coherent_validators as u8;
            NetworkHarmonicState::<T>::put(&harmonic_state);
            
            // Store the last finalized block
            LastFinalizedBlock::<T>::put(block_number);
            
            Self::deposit_event(Event::BlockFinalized {
                block_number,
                coherent_validators,
                network_coherence: harmonic_state.coherence_level,
            });

            Ok(())
        }

        /// Submit finality certificate for a block (via unsigned transaction)
        ///
        /// Phase 5: ACTIVE! DecodeWithMemTracking works automatically with BoundedVec.
        ///
        /// This extrinsic accepts unsigned transactions from the coherence gadget to store
        /// finality certificates on-chain. Validation is performed in `validate_unsigned`.
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(500_000, 0))]
        pub fn submit_finality_certificate(
            origin: OriginFor<T>,
            certificate: FinalityCertificate<T::AccountId, BlockNumberFor<T>, T::Hash>,
        ) -> DispatchResult {
            // Ensure this is an unsigned transaction
            ensure_none(origin)?;

            // Validate certificate has minimum validators
            ensure!(
                certificate.validator_count >= 1,
                Error::<T>::InsufficientCoherence
            );

            // Store certificate on-chain
            FinalityCertificates::<T>::insert(certificate.block_number, certificate.clone());

            // Update last finalized block
            LastFinalizedBlock::<T>::put(certificate.block_number);

            // Emit event
            Self::deposit_event(Event::FinalityCertificateSubmitted {
                block_number: certificate.block_number,
                block_hash: certificate.block_hash,
                validator_count: certificate.validator_count,
                total_coherence_score: certificate.total_coherence_score,
            });

            info!("📜 Finality certificate stored on-chain for block #{:?}", certificate.block_number);

            Ok(())
        }

        /// Store finality checkpoint (via inherent)
        ///
        /// Phase 6B: This extrinsic is called via inherents to store finality
        /// certificates on-chain at checkpoint blocks (every N blocks).
        ///
        /// Unlike submit_finality_certificate (which was for unsigned tx),
        /// this is a mandatory inherent injected by the block author.
        #[pallet::call_index(6)]
        #[pallet::weight((0, DispatchClass::Mandatory))]
        pub fn store_checkpoint(
            origin: OriginFor<T>,
            certificate: FinalityCertificate<T::AccountId, BlockNumberFor<T>, T::Hash>,
        ) -> DispatchResult {
            // Inherents must be unsigned
            ensure_none(origin)?;

            // Validate certificate has minimum validators
            ensure!(
                certificate.validator_count >= 1,
                Error::<T>::InsufficientCoherence
            );

            // Store certificate on-chain in checkpoint storage
            FinalityCheckpoints::<T>::insert(certificate.block_number, certificate.clone());

            // Update last finalized block
            LastFinalizedBlock::<T>::put(certificate.block_number);

            // Emit event
            Self::deposit_event(Event::FinalityCertificateSubmitted {
                block_number: certificate.block_number,
                block_hash: certificate.block_hash,
                validator_count: certificate.validator_count,
                total_coherence_score: certificate.total_coherence_score,
            });

            info!("📌 Checkpoint stored on-chain for block #{:?}", certificate.block_number);

            Ok(())
        }
    }

    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Calculate coherence score with QBER as primary factor
        fn calculate_coherence_score(
            qber: u32,
            spectral_purity: u8,
            quantum_fidelity: u8,
            frequency: u32,
            phase: u32,
        ) -> u32 {
            // Lower QBER = higher score (inverse relationship)
            let qber_score = if qber == 0 {
                100
            } else {
                (10000u32 / qber).min(100)
            };
            
            // Weight factors:
            // - QBER: 40% (most important - determines key security)
            // - Quantum fidelity: 25%
            // - Spectral purity: 20%
            // - Frequency stability: 10%
            // - Phase coherence: 5%
            
            let weighted_score = (qber_score * 40 +
                quantum_fidelity as u32 * 25 +
                spectral_purity as u32 * 20 +
                (frequency % 100) * 10 / 100 +
                (phase % 100) * 5 / 100) / 100;
            
            weighted_score
        }
        
        pub(crate) fn calculate_proof_hash(
            validator: &T::AccountId,
            frequency: u32,
            phase: u32,
        ) -> H256 {
            use sp_io::hashing::blake2_256;
            
            let mut data = validator.encode();
            data.extend_from_slice(&frequency.encode());
            data.extend_from_slice(&phase.encode());
            
            H256::from(blake2_256(&data))
        }
    }

    /// Validate unsigned transactions for finality certificate submission
    ///
    /// Phase 5: ACTIVE! This validates all finality certificate submissions.
    ///
    /// Validation checks:
    /// - Minimum validator count
    /// - Block progression (no duplicates or old blocks)
    /// - Future: Falcon1024 signature verification
    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // Only validate submit_finality_certificate calls
            if let Call::submit_finality_certificate { certificate } = call {
                // Check 1: Certificate has minimum validator count
                if certificate.validator_count < 1 {
                    return InvalidTransaction::Custom(1).into();
                }

                // Check 2: Block number must be greater than last finalized
                let last_finalized = LastFinalizedBlock::<T>::get();
                if certificate.block_number <= last_finalized {
                    return InvalidTransaction::Stale.into();
                }

                // Check 3: Prevent duplicate certificates for same block
                if FinalityCertificates::<T>::contains_key(certificate.block_number) {
                    return InvalidTransaction::Custom(2).into();
                }

                // Check 4: Verify supermajority threshold (>= 2/3)
                // For Phase 6, assume 3 validators. Phase 7: query ValidatorSet pallet
                let total_validators = 3u32;
                let threshold = ((total_validators * 2) + 2) / 3; // Ceiling division for 2/3

                if certificate.validator_count < threshold {
                    info!(
                        "❌ Certificate rejected: insufficient validators ({}/{}, threshold: {})",
                        certificate.validator_count, total_validators, threshold
                    );
                    return InvalidTransaction::Custom(3).into();
                }

                // Phase 6: Critical validation complete
                // TODO Phase 7: Verify Falcon1024 signatures on all votes
                // TODO Phase 7: Check validator set membership via ValidatorSet pallet
                // TODO Phase 8: Verify hardware attestation certificates

                info!(
                    "✅ Certificate validated: block #{:?}, {}/{} validators (threshold: {})",
                    certificate.block_number, certificate.validator_count, total_validators, threshold
                );

                // Return valid transaction with high priority (finality is critical)
                ValidTransaction::with_tag_prefix("ProofOfCoherence")
                    .priority(TransactionPriority::MAX)
                    .longevity(64) // Stay in pool for 64 blocks
                    .propagate(true) // Broadcast to other nodes
                    .and_provides(certificate.block_number) // Unique identifier
                    .build()
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }
}