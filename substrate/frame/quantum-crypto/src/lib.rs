//! # Quantum Crypto Pallet
//!
//! This pallet provides cryptographically verified quantum measurements using STARK proofs.
//! It ensures nodes cannot fake QBER (Quantum Bit Error Rate) values by requiring
//! zero-knowledge proofs of quantum measurements.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

// STARK proof components
#[cfg(feature = "std")]
pub mod qber_stark;
#[cfg(not(feature = "std"))]
mod qber_stark;
mod quantum_hasher;
mod quantum_merkle;
mod quantum_rng;
#[cfg(feature = "std")]
mod offchain;
mod quantum_rng_provider;
pub mod double_ratchet_lamport;
mod quantum_vrf;
#[cfg(feature = "std")]
mod quantum_event_submitter;
mod authorized_reporter;
pub mod pqc_signatures;
pub mod stark_proof;

use qber_stark::{QberStark, QberProof, QberPublicInputs};
pub use quantum_merkle::{QuantumMerkleTree, QuantumMerkleProof, QuantumStateTree};
pub use quantum_rng::{QuantumRng, QuantumRngSource, QuantumOsRng};
pub use quantum_rng_provider::{QuantumRngProvider, QuantumRngAdapter};
pub use double_ratchet_lamport::{
    LamportKeyPair, LamportSignature, DoubleRatchetState,
    RatchetMessage, MessageHeader, DoubleRatchetError,
    verify_lamport_signature, create_entropy_source
};
pub use authorized_reporter::{ReporterInfo, ReporterStatus};
pub use stark_proof::{
    QuantumEntropyProof, PublicInputs, ProofVerificationResult, AggregatedQuantumProof
};

#[cfg(test)]
mod stark_integration_test;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use sp_core::{H256, blake2_256};
    // use frame_system::offchain::SubmitTransaction; // Commented out until offchain worker is properly configured
    use sp_runtime::{
        transaction_validity::{
            TransactionSource, TransactionValidity,
        },
        SaturatedConversion,
    };
    use log::info;
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Source of randomness for VRF
        type MyRandomness: frame_support::traits::Randomness<Self::Hash, BlockNumberFor<Self>>;

        /// Maximum entropy pool size
        #[pallet::constant]
        type MaxEntropyPoolSize: Get<u32>;

        /// QKD endpoint configuration (for off-chain workers)
        type QkdEndpoint: Get<Option<Vec<u8>>>;

        /// Minimum QBER for secure key generation (as percentage * 100)
        #[pallet::constant]
        type MinSecureQber: Get<u32>; // e.g., 1100 = 11%

        /// Maximum measurements per proof
        #[pallet::constant]
        type MaxMeasurementsPerProof: Get<u32>;

        /// Maximum size of a STARK proof
        #[pallet::constant]
        type MaxProofSize: Get<u32>;

        /// Maximum size of hardware certificates
        #[pallet::constant]
        type MaxCertificateSize: Get<u32>;
    }
    
    /// Hardware attestation for quantum devices
    #[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    pub struct HardwareAttestation {
        pub device_id: H256,
        pub manufacturer: BoundedVec<u8, ConstU32<32>>,
        pub model: BoundedVec<u8, ConstU32<32>>,
        pub serial_number: BoundedVec<u8, ConstU32<64>>,
        pub certificate: BoundedVec<u8, ConstU32<4096>>,
        pub public_key: [u8; 32],
        pub max_key_rate: u32, // bits per second
        pub min_qber: u32,     // minimum achievable QBER * 10000
    }
    
    /// Quantum measurement data
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct QuantumMeasurement {
        pub timestamp: u64,
        pub photon_count: u64,
        pub error_count: u32,
        pub basis_matches: u32,
        pub temperature_mk: u32, // millikelvin
        pub channel_loss_db: u16,
        pub visibility: u8, // percentage
    }
    
    /// QBER measurement with STARK proof
    #[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq, MaxEncodedLen)]
    #[scale_info(skip_type_params(BlockNumber))]
    pub struct QberMeasurement<BlockNumber> {
        pub qber_value: u32, // QBER * 10000 (e.g., 230 = 2.3%)
        pub measurement_count: u32,
        pub timestamp: BlockNumber,
        pub device_attestation_hash: H256,
        pub environmental_hash: H256,
        pub stark_proof: BoundedVec<u8, ConstU32<65536>>, // Serialized STARK proof (64KB max)
    }
    
    /// Cross-node QBER agreement
    #[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq, MaxEncodedLen)]
    #[scale_info(skip_type_params(AccountId, BlockNumber))]
    pub struct QberAgreement<AccountId, BlockNumber> {
        pub alice: AccountId,
        pub bob: AccountId,
        pub alice_qber: u32,
        pub bob_qber: u32,
        pub agreed_qber: u32,
        pub channel_id: H256,
        pub timestamp: BlockNumber,
    }
    
    /// Quantum entropy pool
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(MaxSize))]
    pub struct EntropyPool<MaxSize: Get<u32>> {
        pub entropy: BoundedVec<u8, MaxSize>,
        pub source: EntropySource,
        pub quality_score: u8,
        pub last_refresh: u64,
    }
    
    impl<MaxSize: Get<u32>> Default for EntropyPool<MaxSize> {
        fn default() -> Self {
            Self {
                entropy: BoundedVec::default(),
                source: EntropySource::default(),
                quality_score: 0,
                last_refresh: 0,
            }
        }
    }
    
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Default, Debug, PartialEq, Eq)]
    pub enum EntropySource {
        #[default]
        QuantumRng,
        QkdSiftedKeys,
        VacuumFlucts,
        RadioactiveDecay,
    }
    
    /// Registered quantum hardware devices
    #[pallet::storage]
    #[pallet::getter(fn hardware_registry)]
    pub type HardwareRegistry<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Device ID
        HardwareAttestation,
        OptionQuery,
    >;
    
    /// Node to hardware mapping
    #[pallet::storage]
    #[pallet::getter(fn node_hardware)]
    pub type NodeHardware<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        H256, // Device ID
        OptionQuery,
    >;
    
    /// Verified QBER measurements
    #[pallet::storage]
    #[pallet::getter(fn qber_measurements)]
    pub type QberMeasurements<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        H256, // Channel ID
        QberMeasurement<BlockNumberFor<T>>,
        OptionQuery,
    >;
    
    /// Cross-node QBER agreements
    #[pallet::storage]
    #[pallet::getter(fn qber_agreements)]
    pub type QberAgreements<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Channel ID
        QberAgreement<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;
    
    /// Quantum entropy pool
    #[pallet::storage]
    #[pallet::getter(fn entropy_pool)]
    pub type EntropyPoolStorage<T: Config> = StorageValue<
        _,
        EntropyPool<T::MaxEntropyPoolSize>,
        ValueQuery,
    >;
    
    /// STARK proof verification keys
    #[pallet::storage]
    #[pallet::getter(fn stark_verification_keys)]
    pub type StarkVerificationKeys<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Proof system ID
        BoundedVec<u8, ConstU32<4096>>, // Verification key
        OptionQuery,
    >;
    
    /// Double Ratchet sessions between accounts
    #[pallet::storage]
    #[pallet::getter(fn ratchet_sessions)]
    pub type RatchetSessions<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        T::AccountId,
        double_ratchet_lamport::DoubleRatchetState,
        OptionQuery,
    >;
    
    /// Current committee selected by QVRF
    #[pallet::storage]
    #[pallet::getter(fn current_committee)]
    pub type CurrentCommittee<T: Config> = StorageValue<
        _,
        BoundedVec<T::AccountId, ConstU32<100>>,
        ValueQuery,
    >;
    
    /// Validators eligible for QVRF selection
    #[pallet::storage]
    #[pallet::getter(fn validators)]
    pub type Validators<T: Config> = StorageValue<
        _,
        BoundedVec<T::AccountId, ConstU32<1000>>,
        ValueQuery,
    >;
    
    /// Pending ratchet messages (for async delivery)
    #[pallet::storage]
    #[pallet::getter(fn pending_messages)]
    pub type PendingMessages<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // Recipient
        Blake2_128Concat,
        u32, // Message ID
        double_ratchet_lamport::RatchetMessage,
        OptionQuery,
    >;
    
    /// Message counter for each recipient
    #[pallet::storage]
    #[pallet::getter(fn message_counter)]
    pub type MessageCounter<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u32,
        ValueQuery,
    >;
    
    /// Secure storage for QKD keys (encrypted with commitment hash)
    #[pallet::storage]
    pub type SecureQkdKeys<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        H256, // Channel ID
        Blake2_128Concat,
        u64,  // Key index
        (H256, BlockNumberFor<T>), // (Key commitment, expiry block)
        OptionQuery,
    >;
    
    /// Storage for authorized reporters
    #[pallet::storage]
    #[pallet::getter(fn authorized_reporters)]
    pub type AuthorizedReporters<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        authorized_reporter::ReporterInfo<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;
    
    /// Machine ID to operator mapping (ensures one reporter per machine)
    #[pallet::storage]
    #[pallet::getter(fn machine_registry)]
    pub type MachineRegistry<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Machine ID
        T::AccountId,
        OptionQuery,
    >;
    
    /// Global rate limiting parameters
    #[pallet::storage]
    #[pallet::getter(fn rate_limit_config)]
    pub type RateLimitConfig<T: Config> = StorageValue<
        _,
        (u32, u64), // (max_events_per_window, window_duration_seconds)
        ValueQuery,
        DefaultRateLimit,
    >;
    
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Quantum hardware registered
        HardwareRegistered {
            device_id: H256,
            manufacturer: Vec<u8>,
            owner: T::AccountId,
        },
        
        /// QBER measurement verified and stored
        QberMeasurementVerified {
            node: T::AccountId,
            channel_id: H256,
            qber_value: u32,
            proof_valid: bool,
        },
        
        /// Cross-node QBER agreement reached
        QberAgreementReached {
            alice: T::AccountId,
            bob: T::AccountId,
            channel_id: H256,
            agreed_qber: u32,
        },
        
        /// QBER proof verification failed
        QberProofInvalid {
            node: T::AccountId,
            reason: Vec<u8>,
        },
        
        /// Entropy pool refreshed
        EntropyPoolRefreshed {
            source: u8, // EntropySource as u8
            entropy_bits: u32,
            quality_score: u8,
        },
        
        /// Committee selected using QVRF
        CommitteeSelected {
            epoch: u64,
            committee: Vec<T::AccountId>,
        },
        
        /// QVRF generated for validator
        QvrfGenerated {
            validator: T::AccountId,
            epoch: u64,
            slot: u64,
        },
        
        /// Reporter registered
        ReporterRegistered {
            operator: T::AccountId,
            machine_id: H256,
        },
        
        /// Reporter authorized
        ReporterAuthorized {
            operator: T::AccountId,
        },
        
        /// Reporter suspended
        ReporterSuspended {
            operator: T::AccountId,
        },
        
        /// Physical law violation detected
        PhysicalViolationDetected {
            node: T::AccountId,
            violation_type: Vec<u8>,
            expected_range: (u32, u32),
            actual_value: u32,
        },
        
        /// Double Ratchet session established
        RatchetSessionEstablished {
            alice: T::AccountId,
            bob: T::AccountId,
            session_id: H256,
        },
        
        /// Quantum secure message sent
        QuantumMessageSent {
            sender: T::AccountId,
            recipient: T::AccountId,
            message_id: u32,
        },
        
        /// Quantum secure message received
        QuantumMessageReceived {
            sender: T::AccountId,
            recipient: T::AccountId,
            message_id: u32,
        },
        
        /// Ratchet key rotation performed
        RatchetKeyRotated {
            account: T::AccountId,
            peer: T::AccountId,
            rotation_count: u32,
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// Hardware not registered
        HardwareNotRegistered,
        /// Invalid hardware certificate
        InvalidHardwareCertificate,
        /// STARK proof verification failed
        InvalidStarkProof,
        /// QBER value outside physical limits
        QberOutsidePhysicalLimits,
        /// Measurement count mismatch
        MeasurementCountMismatch,
        /// Environmental conditions invalid
        InvalidEnvironmentalConditions,
        /// Cross-node QBER disagreement
        QberDisagreement,
        /// Insufficient entropy
        InsufficientEntropy,
        /// Proof too large
        ProofTooLarge,
        /// Verification key not found
        VerificationKeyNotFound,
        /// Invalid entropy source
        InvalidEntropySource,
        /// Entropy pool full
        EntropyPoolFull,
        /// Invalid entropy data
        InvalidEntropy,
        /// Invalid QBER value
        InvalidQber,
        /// Quantum entropy unavailable
        QuantumEntropyUnavailable,
        /// Invalid VRF input
        InvalidVrfInput,
        /// Invalid validator key
        InvalidValidatorKey,
        /// Invalid VRF output
        InvalidVrfOutput,
        /// Invalid VRF proof
        InvalidVrfProof,
        /// No validators registered
        NoValidators,
        /// Too many validators for committee
        TooManyValidators,
        /// Reporter not found
        ReporterNotFound,
        /// Reporter already registered
        ReporterAlreadyRegistered,
        /// Reporter not authorized
        ReporterNotAuthorized,
        /// Invalid reporter status
        InvalidReporterStatus,
        /// Machine already registered
        MachineAlreadyRegistered,
        /// Certificate too large
        CertificateTooLarge,
        /// Invalid machine ID
        InvalidMachineId,
        /// Rate limit exceeded
        RateLimitExceeded,
        /// Queue submission failed
        QueueSubmissionFailed,
        /// Invalid proof
        InvalidProof,
        /// Ratchet session not found
        RatchetSessionNotFound,
        /// Ratchet session already exists
        RatchetSessionExists,
        /// Invalid ratchet message
        InvalidRatchetMessage,
        /// Message decryption failed
        MessageDecryptionFailed,
        /// Invalid Lamport signature
        InvalidLamportSignature,
        /// Message too large
        MessageTooLarge,
        /// Too many pending messages
        TooManyPendingMessages,
    }
    
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register quantum hardware with attestation
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn register_quantum_hardware(
            origin: OriginFor<T>,
            device_id: H256,
            manufacturer: BoundedVec<u8, ConstU32<32>>,
            model: BoundedVec<u8, ConstU32<32>>,
            serial_number: BoundedVec<u8, ConstU32<64>>,
            certificate: BoundedVec<u8, ConstU32<4096>>,
            public_key: [u8; 32],
            max_key_rate: u32,
            min_qber: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify hardware certificate
            ensure!(
                Self::verify_hardware_certificate(&certificate),
                Error::<T>::InvalidHardwareCertificate
            );
            
            // Create attestation
            let attestation = HardwareAttestation {
                device_id,
                manufacturer: manufacturer.clone(),
                model,
                serial_number,
                certificate,
                public_key,
                max_key_rate,
                min_qber,
            };
            
            // Store hardware attestation
            HardwareRegistry::<T>::insert(&device_id, &attestation);
            NodeHardware::<T>::insert(&who, &device_id);
            
            Self::deposit_event(Event::HardwareRegistered {
                device_id,
                manufacturer: manufacturer.to_vec(),
                owner: who,
            });
            
            Ok(())
        }
        
        /// Submit QBER measurement with STARK proof
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(500_000, 0))]
        pub fn submit_qber_with_proof(
            origin: OriginFor<T>,
            channel_id: H256,
            qber_value: u32,
            measurement_count: u32,
            environmental_hash: H256,
            stark_proof: BoundedVec<u8, ConstU32<65536>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify node has registered hardware
            let device_id = NodeHardware::<T>::get(&who)
                .ok_or(Error::<T>::HardwareNotRegistered)?;
            
            let hardware = HardwareRegistry::<T>::get(&device_id)
                .ok_or(Error::<T>::HardwareNotRegistered)?;
            
            // Verify QBER is within hardware physical limits
            ensure!(
                qber_value >= hardware.min_qber && qber_value <= 5000, // Max 50% QBER
                Error::<T>::QberOutsidePhysicalLimits
            );
            
            // Verify STARK proof
            ensure!(
                Self::verify_qber_stark_proof(
                    qber_value,
                    measurement_count,
                    device_id.0,
                    environmental_hash.0,
                    &stark_proof
                )?,
                Error::<T>::InvalidStarkProof
            );
            
            // Verify environmental correlation
            Self::verify_environmental_correlation(qber_value, environmental_hash)?;
            
            // Store verified measurement
            
            let measurement = QberMeasurement {
                qber_value,
                measurement_count,
                timestamp: frame_system::Pallet::<T>::block_number(),
                device_attestation_hash: device_id,
                environmental_hash,
                stark_proof,
            };
            
            QberMeasurements::<T>::insert(&who, &channel_id, measurement);
            
            Self::deposit_event(Event::QberMeasurementVerified {
                node: who,
                channel_id,
                qber_value,
                proof_valid: true,
            });
            
            Ok(())
        }
        
        /// Submit cross-node QBER agreement
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(200_000, 0))]
        pub fn submit_qber_agreement(
            origin: OriginFor<T>,
            channel_id: H256,
            counterparty: T::AccountId,
            _alice_qber: u32,
            _bob_qber: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify both measurements exist
            let alice_measurement = QberMeasurements::<T>::get(&who, &channel_id)
                .ok_or(Error::<T>::QberDisagreement)?;
            let bob_measurement = QberMeasurements::<T>::get(&counterparty, &channel_id)
                .ok_or(Error::<T>::QberDisagreement)?;
            
            // Verify QBER values match (within tolerance)
            let tolerance = 50; // 0.5% tolerance
            ensure!(
                (alice_measurement.qber_value as i32 - bob_measurement.qber_value as i32).abs() <= tolerance,
                Error::<T>::QberDisagreement
            );
            
            // Calculate agreed QBER (average)
            let agreed_qber = (alice_measurement.qber_value + bob_measurement.qber_value) / 2;
            
            let agreement = QberAgreement {
                alice: who.clone(),
                bob: counterparty.clone(),
                alice_qber: alice_measurement.qber_value,
                bob_qber: bob_measurement.qber_value,
                agreed_qber,
                channel_id,
                timestamp: frame_system::Pallet::<T>::block_number(),
            };
            
            QberAgreements::<T>::insert(&channel_id, agreement);
            
            Self::deposit_event(Event::QberAgreementReached {
                alice: who,
                bob: counterparty,
                channel_id,
                agreed_qber,
            });
            
            Ok(())
        }
        
        /// Store QKD key material
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(75_000, 0))]
        pub fn store_qkd_keys(
            origin: OriginFor<T>,
            channel_id: H256,
            key_material: Vec<u8>,
            qber: u32,
        ) -> DispatchResult {
            // This is called by offchain worker, so no signature check
            ensure_none(origin)?;
            
            // Validate QBER
            ensure!(qber < 1500, Error::<T>::QberOutsidePhysicalLimits); // Max 15%
            
            // Store key material securely
            Self::store_qkd_key_secure(channel_id, &key_material, qber)?;
            
            // Update entropy pool with QKD-derived randomness
            let bounded_entropy: BoundedVec<u8, T::MaxEntropyPoolSize> = 
                key_material.clone().try_into()
                    .map_err(|_| Error::<T>::EntropyPoolFull)?;
            
            let pool = EntropyPool {
                entropy: bounded_entropy,
                source: EntropySource::QkdSiftedKeys,
                quality_score: if qber < 500 { 100 } else { 90 }, // Perfect if QBER < 5%
                last_refresh: sp_io::offchain::timestamp().unix_millis(),
            };
            
            EntropyPoolStorage::<T>::put(pool);
            
            Self::deposit_event(Event::EntropyPoolRefreshed {
                source: 1, // QkdSiftedKeys
                entropy_bits: (key_material.len() * 8) as u32,
                quality_score: if qber < 500 { 100 } else { 90 },
            });
            
            Ok(())
        }
        
        /// Provide quantum entropy (requires hardware attestation)
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn provide_quantum_entropy(
            origin: OriginFor<T>,
            entropy: BoundedVec<u8, T::MaxEntropyPoolSize>,
            source: u8, // 0: QuantumRng, 1: QkdSiftedKeys, 2: VacuumFlucts, 3: RadioactiveDecay
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify provider has quantum hardware
            ensure!(
                NodeHardware::<T>::contains_key(&who),
                Error::<T>::HardwareNotRegistered
            );
            
            // Entropy is already bounded
            
            // Calculate quality score based on source
            let (quality_score, entropy_source) = match source {
                0 => (95, EntropySource::QuantumRng),
                1 => (100, EntropySource::QkdSiftedKeys),
                2 => (90, EntropySource::VacuumFlucts),
                3 => (85, EntropySource::RadioactiveDecay),
                _ => return Err(Error::<T>::InvalidEntropySource.into()),
            };
            
            let pool = EntropyPool {
                entropy: entropy.clone(),
                source: entropy_source.clone(),
                quality_score,
                last_refresh: sp_io::offchain::timestamp().unix_millis(),
            };
            
            EntropyPoolStorage::<T>::put(pool);
            
            Self::deposit_event(Event::EntropyPoolRefreshed {
                source,
                entropy_bits: (entropy.len() * 8) as u32,
                quality_score,
            });
            
            Ok(())
        }
        
        /// Register quantum event reporter (governance only)
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn register_reporter(
            origin: OriginFor<T>,
            operator: T::AccountId,
            kyc_hash: H256,
            hardware_cert: Vec<u8>,
            machine_id: H256,
        ) -> DispatchResult {
            // Only governance can register reporters
            ensure_root(origin)?;
            
            // Inline the register_reporter logic here
            use crate::authorized_reporter::*;
            
            // Check machine not already registered
            ensure!(
                !crate::MachineRegistry::<T>::contains_key(&machine_id),
                Error::<T>::MachineAlreadyRegistered
            );
            
            // Check operator not already registered
            ensure!(
                !crate::AuthorizedReporters::<T>::contains_key(&operator),
                Error::<T>::ReporterAlreadyRegistered
            );
            
            // Convert hardware cert to bounded vec
            let bounded_cert: BoundedVec<u8, ConstU32<1024>> = hardware_cert
                .try_into()
                .map_err(|_| Error::<T>::CertificateTooLarge)?;
            
            let current_block = frame_system::Pallet::<T>::block_number();
            let (rate_limit, _) = crate::RateLimitConfig::<T>::get();
            
            let reporter_info = ReporterInfo {
                operator: operator.clone(),
                status: ReporterStatus::Pending,
                kyc_hash,
                hardware_cert: bounded_cert,
                registered_at: current_block,
                last_active: current_block,
                rate_limit,
                events_submitted: 0,
                window_start: 0,
                machine_id,
            };
            
            // Store reporter info
            crate::AuthorizedReporters::<T>::insert(&operator, reporter_info);
            crate::MachineRegistry::<T>::insert(&machine_id, &operator);
            
            Self::deposit_event(Event::ReporterRegistered {
                operator,
                machine_id,
            });
            
            Ok(())
        }
        
        /// Authorize reporter after KYC verification (governance only)
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn authorize_reporter(
            origin: OriginFor<T>,
            operator: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            // Inline the authorize_reporter logic here
            use crate::authorized_reporter::ReporterStatus;
            
            crate::AuthorizedReporters::<T>::try_mutate(&operator, |maybe_info| {
                let info = maybe_info.as_mut().ok_or(Error::<T>::ReporterNotFound)?;
                
                // Only pending reporters can be authorized
                ensure!(
                    info.status == ReporterStatus::Pending,
                    Error::<T>::InvalidReporterStatus
                );
                
                info.status = ReporterStatus::Authorized;
                
                Self::deposit_event(Event::ReporterAuthorized {
                    operator: operator.clone(),
                });
                
                Ok(())
            })
        }
        
        /// Suspend reporter (governance only)
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn suspend_reporter(
            origin: OriginFor<T>,
            operator: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            // Inline the suspend_reporter logic here
            use crate::authorized_reporter::ReporterStatus;
            
            crate::AuthorizedReporters::<T>::try_mutate(&operator, |maybe_info| {
                let info = maybe_info.as_mut().ok_or(Error::<T>::ReporterNotFound)?;
                
                // Can only suspend authorized reporters
                ensure!(
                    info.status == ReporterStatus::Authorized,
                    Error::<T>::InvalidReporterStatus
                );
                
                info.status = ReporterStatus::Suspended;
                
                Self::deposit_event(Event::ReporterSuspended {
                    operator: operator.clone(),
                });
                
                Ok(())
            })
        }
        
        /// Update rate limit configuration (governance only)
        #[pallet::call_index(8)]
        #[pallet::weight(Weight::from_parts(25_000, 0))]
        pub fn update_rate_limit(
            origin: OriginFor<T>,
            max_events: u32,
            window_seconds: u64,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            crate::RateLimitConfig::<T>::put((max_events, window_seconds));
            
            Ok(())
        }
        
        /// Add entropy from offchain worker (unsigned)
        #[pallet::call_index(9)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn add_entropy(
            origin: OriginFor<T>,
            entropy: Vec<u8>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            
            // Validate entropy
            ensure!(!entropy.is_empty(), Error::<T>::InvalidEntropy);
            ensure!(entropy.len() >= 32, Error::<T>::InvalidEntropy);
            
            // Convert to bounded vec
            let bounded_entropy: BoundedVec<u8, T::MaxEntropyPoolSize> = entropy
                .try_into()
                .map_err(|_| Error::<T>::EntropyPoolFull)?;
            
            let pool = EntropyPool {
                entropy: bounded_entropy,
                source: EntropySource::QuantumRng,
                quality_score: 90,
                last_refresh: sp_io::offchain::timestamp().unix_millis(),
            };
            
            EntropyPoolStorage::<T>::put(pool);
            
            Ok(())
        }
        
        /// Update QBER from offchain measurement
        #[pallet::call_index(10)]
        #[pallet::weight(Weight::from_parts(75_000, 0))]
        pub fn update_qber(
            origin: OriginFor<T>,
            value: u32, // QBER * 10000 (e.g., 230 = 2.3%)
            proof: Vec<u8>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            
            // Validate QBER range (0 to 15%)
            ensure!(value <= 1500, Error::<T>::InvalidQber);
            
            // In production, verify the proof
            ensure!(!proof.is_empty(), Error::<T>::InvalidProof);
            
            // Store QBER update
            // This is simplified - real implementation would update specific channels
            
            Ok(())
        }
        
        /// Establish a Double Ratchet session with another account
        #[pallet::call_index(11)]
        #[pallet::weight(Weight::from_parts(200_000, 0))]
        pub fn establish_ratchet_session(
            origin: OriginFor<T>,
            peer: T::AccountId,
            shared_secret: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Ensure session doesn't already exist
            ensure!(
                !RatchetSessions::<T>::contains_key(&who, &peer),
                Error::<T>::RatchetSessionExists
            );
            
            // Ensure both parties have quantum hardware
            ensure!(
                NodeHardware::<T>::contains_key(&who),
                Error::<T>::HardwareNotRegistered
            );
            ensure!(
                NodeHardware::<T>::contains_key(&peer),
                Error::<T>::HardwareNotRegistered
            );
            
            // Create entropy source
            let mut entropy_source = double_ratchet_lamport::create_entropy_source::<T>();
            
            // Initialize session (initiator)
            let session = double_ratchet_lamport::DoubleRatchetState::initialize::<T>(
                &shared_secret,
                true,
                &mut entropy_source,
            ).map_err(|_| Error::<T>::InsufficientEntropy)?;
            
            // Store session for both parties
            RatchetSessions::<T>::insert(&who, &peer, session.clone());
            
            // Create reciprocal session for peer (non-initiator)
            let peer_session = double_ratchet_lamport::DoubleRatchetState::initialize::<T>(
                &shared_secret,
                false,
                &mut entropy_source,
            ).map_err(|_| Error::<T>::InsufficientEntropy)?;
            
            RatchetSessions::<T>::insert(&peer, &who, peer_session);
            
            let session_id = H256::from(blake2_256(&[&who.encode()[..], &peer.encode()[..]].concat()));
            
            Self::deposit_event(Event::RatchetSessionEstablished {
                alice: who,
                bob: peer,
                session_id,
            });
            
            Ok(())
        }
        
        /// Send a quantum-secure message using Double Ratchet
        #[pallet::call_index(12)]
        #[pallet::weight(Weight::from_parts(300_000, 0))]
        pub fn send_quantum_message(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            message: BoundedVec<u8, ConstU32<4096>>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Get session
            let mut session = RatchetSessions::<T>::get(&sender, &recipient)
                .ok_or(Error::<T>::RatchetSessionNotFound)?;
            
            // Create entropy source
            let mut entropy_source = double_ratchet_lamport::create_entropy_source::<T>();
            
            // Encrypt message
            let encrypted_message = session.encrypt_message::<T>(
                &message,
                &mut entropy_source,
            ).map_err(|_| Error::<T>::MessageTooLarge)?;
            
            // Update session
            RatchetSessions::<T>::insert(&sender, &recipient, session);
            
            // Store message for recipient
            let message_id = MessageCounter::<T>::mutate(&recipient, |counter| {
                let id = *counter;
                *counter = counter.saturating_add(1);
                id
            });
            
            PendingMessages::<T>::insert(&recipient, message_id, &encrypted_message);
            
            Self::deposit_event(Event::QuantumMessageSent {
                sender,
                recipient,
                message_id,
            });
            
            Ok(())
        }
        
        /// Receive and decrypt a quantum-secure message
        #[pallet::call_index(13)]
        #[pallet::weight(Weight::from_parts(300_000, 0))]
        pub fn receive_quantum_message(
            origin: OriginFor<T>,
            sender: T::AccountId,
            message_id: u32,
        ) -> DispatchResult {
            let recipient = ensure_signed(origin)?;
            
            // Get message
            let encrypted_message = PendingMessages::<T>::take(&recipient, message_id)
                .ok_or(Error::<T>::InvalidRatchetMessage)?;
            
            // Get session
            let mut session = RatchetSessions::<T>::get(&recipient, &sender)
                .ok_or(Error::<T>::RatchetSessionNotFound)?;
            
            // Create entropy source
            let mut entropy_source = double_ratchet_lamport::create_entropy_source::<T>();
            
            // Decrypt message
            let _decrypted = session.decrypt_message::<T>(
                &encrypted_message,
                &mut entropy_source,
            ).map_err(|e| match e {
                double_ratchet_lamport::DoubleRatchetError::InvalidSignature => Error::<T>::InvalidLamportSignature,
                _ => Error::<T>::MessageDecryptionFailed,
            })?;
            
            // Update session
            RatchetSessions::<T>::insert(&recipient, &sender, session);
            
            Self::deposit_event(Event::QuantumMessageReceived {
                sender,
                recipient,
                message_id,
            });
            
            Ok(())
        }
    }
    
    // Hooks for offchain worker
    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            // Only run offchain worker in native execution (not WASM)
            #[cfg(feature = "std")]
            {
                Self::offchain_worker_impl(block_number);
            }
        }
    }
    
    // Unsigned transaction validation
    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        
        fn validate_unsigned(
            source: TransactionSource,
            call: &Self::Call,
        ) -> TransactionValidity {
            // Validate unsigned transactions from offchain workers
            #[cfg(feature = "std")]
            return crate::offchain::validate_unsigned::<T>(source, call);
            
            #[cfg(not(feature = "std"))]
            Ok(sp_runtime::transaction_validity::ValidTransaction::default())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Offchain worker implementation wrapper
        #[cfg(feature = "std")]
        fn offchain_worker_impl(block_number: BlockNumberFor<T>) {
            Self::offchain_worker(block_number);
        }
        
        /// Get quantum random bytes
        pub fn quantum_random(length: usize) -> Option<Vec<u8>> {
            let pool = EntropyPoolStorage::<T>::get();
            if pool.entropy.len() >= length {
                Some(pool.entropy[..length].to_vec())
            } else {
                None
            }
        }
        
        /// Get quantum entropy from the pool
        pub fn get_quantum_entropy(num_bytes: usize) -> Result<Vec<u8>, Error<T>> {
            let mut entropy_pool = EntropyPoolStorage::<T>::get();
            
            if entropy_pool.entropy.len() < num_bytes {
                return Err(Error::<T>::InsufficientEntropy);
            }
            
            // Take the requested bytes from the pool
            let entropy: Vec<u8> = entropy_pool.entropy.drain(..num_bytes).collect();
            EntropyPoolStorage::<T>::put(entropy_pool);
            
            Ok(entropy)
        }
        
        /// Store QKD key material securely
        fn store_qkd_key_secure(
            channel_id: H256,
            key_material: &[u8],
            qber: u32,
        ) -> Result<(), Error<T>> {
            // Calculate key commitment (hash of the key for verification)
            let key_commitment = sp_io::hashing::blake2_256(key_material);
            
            // Calculate expiry based on QBER (lower QBER = longer validity)
            let current_block = <frame_system::Pallet<T>>::block_number();
            let validity_blocks = if qber < 200 { // < 2% QBER
                14400u32 // ~24 hours at 6s blocks
            } else if qber < 500 { // < 5% QBER
                7200u32  // ~12 hours
            } else {
                3600u32  // ~6 hours
            };
            let expiry_block = current_block + validity_blocks.into();
            
            // Get next key index for this channel (simple incrementing counter)
            // In production, this would be tracked separately for efficiency
            let mut key_index = 0u64;
            while SecureQkdKeys::<T>::contains_key(channel_id, key_index) {
                key_index += 1;
            }
            
            // Store commitment and expiry (actual key would be in HSM in production)
            SecureQkdKeys::<T>::insert(
                channel_id,
                key_index,
                (H256::from(key_commitment), expiry_block),
            );
            
            // In production: Send key_material to Hardware Security Module
            // For now, we only store the commitment on-chain
            info!("Stored QKD key {} for channel {:?} with commitment {:?}, expires at block {:?}", 
                key_index, channel_id, key_commitment, expiry_block);
            
            Ok(())
        }
        
        /// Retrieve QKD key commitment
        pub fn get_qkd_key_commitment(
            channel_id: H256,
            key_index: u64,
        ) -> Option<(H256, BlockNumberFor<T>)> {
            SecureQkdKeys::<T>::get(channel_id, key_index)
        }
        
        /// Clean expired QKD keys
        pub fn cleanup_expired_keys(current_block: BlockNumberFor<T>) {
            // Remove expired keys
            let mut expired_count = 0;
            SecureQkdKeys::<T>::iter().for_each(|(channel_id, key_index, (_, expiry))| {
                if expiry <= current_block {
                    SecureQkdKeys::<T>::remove(channel_id, key_index);
                    expired_count += 1;
                }
            });
            
            if expired_count > 0 {
                info!("Cleaned up {} expired QKD keys", expired_count);
            }
        }
        
        /// Verify hardware certificate (simplified)
        pub fn verify_hardware_certificate(certificate: &[u8]) -> bool {
            // In production: Verify against known quantum hardware CA
            // Check manufacturer signatures (Toshiba, IDQ, etc.)
            !certificate.is_empty() && certificate.len() >= 256
        }
        
        /// Verify STARK proof of QBER measurement
        fn verify_qber_stark_proof(
            qber_value: u32,
            measurement_count: u32,
            device_id_hash: [u8; 32],
            environmental_hash: [u8; 32],
            proof_bytes: &[u8],
        ) -> Result<bool, Error<T>> {
            // Create public inputs for verification
            let public_inputs = QberPublicInputs {
                qber_value,
                measurement_count,
                device_id_hash,
                environmental_hash,
            };
            
            // Deserialize proof
            let proof = QberProof::from_bytes(proof_bytes)
                .map_err(|_| Error::<T>::InvalidStarkProof)?;
            
            // Create verifier and verify the STARK proof
            let verifier = QberStark::new();
            match verifier.verify(public_inputs, proof) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        
        /// Verify environmental correlation with QBER
        fn verify_environmental_correlation(
            qber_value: u32,
            environmental_hash: H256,
        ) -> Result<(), Error<T>> {
            // Extract temperature from environmental hash (simplified)
            let temp_factor = environmental_hash.0[0] as u32;
            
            // Higher temperature = higher QBER (simplified correlation)
            if temp_factor > 100 && qber_value < 100 {
                // High temp but low QBER = suspicious
                return Err(Error::<T>::InvalidEnvironmentalConditions);
            }
            
            // Add more sophisticated checks in production:
            // - Distance vs QBER correlation
            // - Atmospheric conditions vs free-space QBER
            // - Fiber temperature vs fiber QBER
            
            Ok(())
        }
        
        /// Calculate network-wide average QBER
        pub fn calculate_network_qber() -> Option<u32> {
            let mut total_qber = 0u64;
            let mut count = 0u32;
            
            for (_, _, measurement) in QberMeasurements::<T>::iter() {
                total_qber += measurement.qber_value as u64;
                count += 1;
            }
            
            if count > 0 {
                Some((total_qber / count as u64) as u32)
            } else {
                None
            }
        }
    }
}

// Default implementation for RateLimitConfig
pub struct DefaultRateLimit;
impl frame_support::pallet_prelude::Get<(u32, u64)> for DefaultRateLimit {
    fn get() -> (u32, u64) {
        (100, 3600) // 100 events per hour default
    }
}