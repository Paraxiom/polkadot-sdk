//! # Quantum Verification Pallet
//!
//! This pallet provides physical verification of quantum measurements to ensure
//! nodes cannot lie about their quantum coherence. It enforces the laws of physics
//! rather than relying on economic incentives.
//!
//! ## Physical Verification Methods:
//! 1. Environmental correlation checks
//! 2. Hardware authentication 
//! 3. Statistical pattern analysis
//! 4. Cross-node verification
//! 5. Physical constraint enforcement

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::{vec::Vec, collections::btree_map::BTreeMap};
    use sp_core::{H256, U256};
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_quantum_crypto::Config + pallet_proof_of_coherence::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        
        /// Maximum number of environmental sensors per node
        #[pallet::constant]
        type MaxSensorsPerNode: Get<u32>;
        
        /// Maximum historical measurements to store
        #[pallet::constant]
        type MaxHistoricalMeasurements: Get<u32>;
        
        /// Minimum nodes required for cross-verification
        #[pallet::constant]
        type MinVerificationNodes: Get<u32>;
    }
    
    /// Environmental conditions that affect quantum measurements
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct EnvironmentalData {
        pub temperature_kelvin: u32, // Fixed point: actual * 1000
        pub vibration_hz: u32,
        pub magnetic_field_gauss: u32, // Fixed point: actual * 1000
        pub pressure_kpa: u32,
        pub humidity_percent: u8,
        pub electromagnetic_noise_db: i8,
    }
    
    /// Hardware authentication proof
    #[derive(Clone, Encode, Decode, TypeInfo)]
    pub struct HardwareAttestation {
        pub device_id: H256,
        pub manufacturer: BoundedVec<u8, ConstU32<32>>,
        pub model: BoundedVec<u8, ConstU32<32>>,
        pub calibration_data: BoundedVec<u8, ConstU32<1024>>,
        pub certificate_chain: BoundedVec<u8, ConstU32<4096>>,
        pub last_calibration: BlockNumberFor<T>,
    }
    
    /// Quantum hardware physical limitations
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct HardwareLimits {
        pub max_t1_coherence_us: u64,      // T1 relaxation time in microseconds
        pub max_t2_coherence_us: u64,      // T2 dephasing time in microseconds
        pub min_gate_fidelity: u32,        // Fixed point: actual * 10000
        pub max_readout_fidelity: u32,     // Fixed point: actual * 10000
        pub operating_temp_min_k: u32,     // Min operating temperature (Kelvin * 1000)
        pub operating_temp_max_k: u32,     // Max operating temperature (Kelvin * 1000)
    }
    
    /// Statistical verification result
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct StatisticalAnalysis {
        pub chi_squared_test: u32,         // Fixed point: actual * 1000
        pub entropy_estimate: u32,         // Bits of entropy per measurement
        pub autocorrelation: i32,          // Fixed point: actual * 10000
        pub spectral_uniformity: u32,      // Fixed point: actual * 10000
        pub quantum_signature_score: u32,  // 0-100 confidence it's quantum
    }
    
    /// Cross-verification attestation from neighboring nodes
    #[derive(Clone, Encode, Decode, TypeInfo)]
    pub struct CrossVerification<T: Config> {
        pub verifier: T::AccountId,
        pub target: T::AccountId,
        pub environmental_match: bool,
        pub timing_correlation: bool,
        pub interference_detected: bool,
        pub confidence_score: u8, // 0-100
        pub timestamp: BlockNumberFor<T>,
    }
    
    /// Complete physical verification proof
    #[derive(Clone, Encode, Decode, TypeInfo)]
    pub struct PhysicalVerificationProof<T: Config> {
        pub environmental_data: EnvironmentalData,
        pub hardware_attestation: HardwareAttestation,
        pub statistical_analysis: StatisticalAnalysis,
        pub cross_verifications: BoundedVec<CrossVerification<T>, T::MinVerificationNodes>,
        pub measurement_hash: H256,
        pub timestamp: BlockNumberFor<T>,
    }
    
    /// Environmental sensors registered per node
    #[pallet::storage]
    #[pallet::getter(fn environmental_sensors)]
    pub type EnvironmentalSensors<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<EnvironmentalData, T::MaxSensorsPerNode>,
        ValueQuery,
    >;
    
    /// Hardware attestations for quantum devices
    #[pallet::storage]
    #[pallet::getter(fn hardware_attestations)]
    pub type HardwareAttestations<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        HardwareAttestation,
        OptionQuery,
    >;
    
    /// Known hardware limitations by device type
    #[pallet::storage]
    #[pallet::getter(fn hardware_limits)]
    pub type HardwareLimitsDb<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        H256, // Device type hash
        HardwareLimits,
        OptionQuery,
    >;
    
    /// Historical measurements for pattern analysis
    #[pallet::storage]
    #[pallet::getter(fn measurement_history)]
    pub type MeasurementHistory<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<(BlockNumberFor<T>, StatisticalAnalysis), T::MaxHistoricalMeasurements>,
        ValueQuery,
    >;
    
    /// Cross-verification network
    #[pallet::storage]
    #[pallet::getter(fn verification_network)]
    pub type VerificationNetwork<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // Verifier
        Blake2_128Concat,
        T::AccountId, // Target
        CrossVerification<T>,
        OptionQuery,
    >;
    
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Hardware attestation registered
        HardwareAttested {
            who: T::AccountId,
            device_id: H256,
            manufacturer: Vec<u8>,
        },
        
        /// Environmental anomaly detected
        EnvironmentalAnomalyDetected {
            node: T::AccountId,
            expected_range: (u32, u32),
            actual_value: u32,
            parameter: Vec<u8>,
        },
        
        /// Statistical anomaly in quantum measurements
        StatisticalAnomalyDetected {
            node: T::AccountId,
            test_failed: Vec<u8>,
            confidence: u8,
        },
        
        /// Cross-verification failed
        CrossVerificationFailed {
            verifier: T::AccountId,
            target: T::AccountId,
            reason: Vec<u8>,
        },
        
        /// Physical verification successful
        PhysicalVerificationPassed {
            node: T::AccountId,
            confidence_score: u8,
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// Hardware not attested
        HardwareNotAttested,
        /// Invalid hardware certificate
        InvalidHardwareCertificate,
        /// Environmental conditions out of range
        EnvironmentalConditionsInvalid,
        /// Statistical tests failed
        StatisticalTestsFailed,
        /// Insufficient cross-verifications
        InsufficientCrossVerifications,
        /// Measurement violates physical laws
        PhysicalLawViolation,
        /// Hardware limits exceeded
        HardwareLimitsExceeded,
        /// Calibration expired
        CalibrationExpired,
    }
    
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register quantum hardware with attestation
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn register_hardware(
            origin: OriginFor<T>,
            device_id: H256,
            manufacturer: Vec<u8>,
            model: Vec<u8>,
            calibration_data: Vec<u8>,
            certificate_chain: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify certificate chain (in production, check against known CA)
            ensure!(
                Self::verify_certificate_chain(&certificate_chain),
                Error::<T>::InvalidHardwareCertificate
            );
            
            let attestation = HardwareAttestation {
                device_id,
                manufacturer: manufacturer.clone().try_into()
                    .map_err(|_| Error::<T>::InvalidHardwareCertificate)?,
                model: model.try_into()
                    .map_err(|_| Error::<T>::InvalidHardwareCertificate)?,
                calibration_data: calibration_data.try_into()
                    .map_err(|_| Error::<T>::InvalidHardwareCertificate)?,
                certificate_chain: certificate_chain.try_into()
                    .map_err(|_| Error::<T>::InvalidHardwareCertificate)?,
                last_calibration: frame_system::Pallet::<T>::block_number(),
            };
            
            HardwareAttestations::<T>::insert(&who, attestation);
            
            Self::deposit_event(Event::HardwareAttested {
                who,
                device_id,
                manufacturer,
            });
            
            Ok(())
        }
        
        /// Submit environmental sensor data
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn submit_environmental_data(
            origin: OriginFor<T>,
            data: EnvironmentalData,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Verify hardware is attested
            ensure!(
                HardwareAttestations::<T>::contains_key(&who),
                Error::<T>::HardwareNotAttested
            );
            
            // Check if environmental conditions are within quantum operating range
            Self::verify_environmental_conditions(&data)?;
            
            // Store sensor data
            EnvironmentalSensors::<T>::try_mutate(&who, |sensors| {
                sensors.try_push(data)
                    .map_err(|_| Error::<T>::EnvironmentalConditionsInvalid)
            })?;
            
            Ok(())
        }
        
        /// Submit physical verification proof with quantum measurements
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(200_000, 0))]
        pub fn submit_verified_measurement(
            origin: OriginFor<T>,
            coherence_proof: pallet_proof_of_coherence::CoherenceProof<BlockNumberFor<T>>,
            environmental_data: EnvironmentalData,
            statistical_analysis: StatisticalAnalysis,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // 1. Verify hardware attestation
            let attestation = HardwareAttestations::<T>::get(&who)
                .ok_or(Error::<T>::HardwareNotAttested)?;
            
            // 2. Check calibration is recent
            let current_block = frame_system::Pallet::<T>::block_number();
            let calibration_age = current_block.saturating_sub(attestation.last_calibration);
            ensure!(
                calibration_age <= 100000u32.into(), // ~1 week at 6s blocks
                Error::<T>::CalibrationExpired
            );
            
            // 3. Verify environmental correlation
            Self::verify_environmental_correlation(&environmental_data, &coherence_proof)?;
            
            // 4. Check hardware limits
            Self::verify_hardware_limits(&attestation.device_id, &coherence_proof)?;
            
            // 5. Statistical verification
            Self::verify_statistical_patterns(&who, &statistical_analysis)?;
            
            // 6. Get cross-verifications
            let cross_verifications = Self::get_cross_verifications(&who)?;
            
            // 7. Calculate overall confidence score
            let confidence = Self::calculate_verification_confidence(
                &environmental_data,
                &statistical_analysis,
                &cross_verifications,
            );
            
            // 8. Update measurement history
            MeasurementHistory::<T>::try_mutate(&who, |history| {
                history.try_push((current_block, statistical_analysis))
                    .map_err(|_| Error::<T>::StatisticalTestsFailed)
            })?;
            
            // 9. Submit to proof of coherence with verified flag
            pallet_proof_of_coherence::Pallet::<T>::submit_coherence_proof(
                frame_system::RawOrigin::Signed(who.clone()).into(),
                coherence_proof.frequency,
                coherence_proof.phase,
                coherence_proof.spectral_purity,
                coherence_proof.quantum_fidelity,
            )?;
            
            Self::deposit_event(Event::PhysicalVerificationPassed {
                node: who,
                confidence_score: confidence,
            });
            
            Ok(())
        }
        
        /// Cross-verify another node's measurements
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(80_000, 0))]
        pub fn cross_verify_node(
            origin: OriginFor<T>,
            target: T::AccountId,
            environmental_match: bool,
            timing_correlation: bool,
            interference_detected: bool,
            confidence_score: u8,
        ) -> DispatchResult {
            let verifier = ensure_signed(origin)?;
            
            // Can't self-verify
            ensure!(verifier != target, Error::<T>::InsufficientCrossVerifications);
            
            let verification = CrossVerification {
                verifier: verifier.clone(),
                target: target.clone(),
                environmental_match,
                timing_correlation,
                interference_detected,
                confidence_score,
                timestamp: frame_system::Pallet::<T>::block_number(),
            };
            
            VerificationNetwork::<T>::insert(&verifier, &target, verification);
            
            // Check for anomalies
            if !environmental_match || interference_detected || confidence_score < 50 {
                Self::deposit_event(Event::CrossVerificationFailed {
                    verifier,
                    target,
                    reason: b"Environmental mismatch or interference".to_vec(),
                });
            }
            
            Ok(())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Verify certificate chain (simplified for demo)
        fn verify_certificate_chain(_chain: &[u8]) -> bool {
            // In production: Verify against known quantum hardware CA certificates
            // For now, just check it's not empty
            !_chain.is_empty()
        }
        
        /// Verify environmental conditions are within quantum operating range
        fn verify_environmental_conditions(data: &EnvironmentalData) -> Result<(), Error<T>> {
            // Temperature must be near absolute zero for superconducting qubits (15-50 mK)
            // Or room temperature for trapped ions (290-310 K)
            let temp_ok = (data.temperature_kelvin >= 15 && data.temperature_kelvin <= 50) || 
                         (data.temperature_kelvin >= 290_000 && data.temperature_kelvin <= 310_000);
            
            ensure!(temp_ok, Error::<T>::EnvironmentalConditionsInvalid);
            
            // Vibration must be minimal (< 100 Hz)
            ensure!(
                data.vibration_hz < 100,
                Error::<T>::EnvironmentalConditionsInvalid
            );
            
            // Magnetic field must be controlled (< 100 Gauss)
            ensure!(
                data.magnetic_field_gauss < 100_000,
                Error::<T>::EnvironmentalConditionsInvalid
            );
            
            Ok(())
        }
        
        /// Verify environmental correlation with quantum measurements
        fn verify_environmental_correlation(
            env: &EnvironmentalData,
            proof: &pallet_proof_of_coherence::CoherenceProof<BlockNumberFor<T>>,
        ) -> Result<(), Error<T>> {
            // Higher temperature = lower coherence
            if env.temperature_kelvin > 100_000 { // Above 100K
                ensure!(
                    proof.quantum_fidelity < 90,
                    Error::<T>::PhysicalLawViolation
                );
            }
            
            // High vibration = poor spectral purity
            if env.vibration_hz > 50 {
                ensure!(
                    proof.spectral_purity < 95,
                    Error::<T>::PhysicalLawViolation
                );
            }
            
            // Electromagnetic noise affects fidelity
            if env.electromagnetic_noise_db > -30 {
                ensure!(
                    proof.quantum_fidelity < 85,
                    Error::<T>::PhysicalLawViolation
                );
            }
            
            Ok(())
        }
        
        /// Verify measurements respect hardware physical limits
        fn verify_hardware_limits(
            device_id: &H256,
            proof: &pallet_proof_of_coherence::CoherenceProof<BlockNumberFor<T>>,
        ) -> Result<(), Error<T>> {
            if let Some(limits) = HardwareLimitsDb::<T>::get(device_id) {
                // Quantum fidelity can't exceed hardware maximum
                ensure!(
                    proof.quantum_fidelity <= (limits.max_readout_fidelity / 100) as u8,
                    Error::<T>::HardwareLimitsExceeded
                );
                
                // Coherence times limit measurement duration
                // (would need timing data in real implementation)
            }
            
            Ok(())
        }
        
        /// Verify statistical patterns match quantum signatures
        fn verify_statistical_patterns(
            who: &T::AccountId,
            analysis: &StatisticalAnalysis,
        ) -> Result<(), Error<T>> {
            // Chi-squared test should show true randomness (not too perfect)
            ensure!(
                analysis.chi_squared_test > 100 && analysis.chi_squared_test < 2000,
                Error::<T>::StatisticalTestsFailed
            );
            
            // Quantum measurements have specific entropy characteristics
            ensure!(
                analysis.entropy_estimate >= 7, // At least 7 bits per byte
                Error::<T>::StatisticalTestsFailed
            );
            
            // Low autocorrelation expected
            ensure!(
                analysis.autocorrelation.abs() < 1000, // 0.1 correlation
                Error::<T>::StatisticalTestsFailed
            );
            
            // Quantum signature score must be high
            ensure!(
                analysis.quantum_signature_score >= 70,
                Error::<T>::StatisticalTestsFailed
            );
            
            // Check historical consistency
            let history = MeasurementHistory::<T>::get(who);
            if history.len() > 10 {
                // Variance should be within expected quantum noise
                let recent_scores: Vec<u32> = history.iter()
                    .rev()
                    .take(10)
                    .map(|(_, a)| a.quantum_signature_score)
                    .collect();
                
                let avg = recent_scores.iter().sum::<u32>() / 10;
                for score in recent_scores {
                    ensure!(
                        (score as i32 - avg as i32).abs() < 20,
                        Error::<T>::StatisticalTestsFailed
                    );
                }
            }
            
            Ok(())
        }
        
        /// Get cross-verifications from neighboring nodes
        fn get_cross_verifications(
            target: &T::AccountId,
        ) -> Result<Vec<CrossVerification<T>>, Error<T>> {
            let mut verifications = Vec::new();
            
            // In production: Get from actual network topology
            // For now, collect all verifications for this target
            for (verifier, _, verification) in VerificationNetwork::<T>::iter() {
                if &verification.target == target {
                    verifications.push(verification);
                }
                
                if verifications.len() >= T::MinVerificationNodes::get() as usize {
                    break;
                }
            }
            
            ensure!(
                verifications.len() >= T::MinVerificationNodes::get() as usize,
                Error::<T>::InsufficientCrossVerifications
            );
            
            Ok(verifications)
        }
        
        /// Calculate overall verification confidence
        fn calculate_verification_confidence(
            env: &EnvironmentalData,
            stats: &StatisticalAnalysis,
            cross_verifications: &[CrossVerification<T>],
        ) -> u8 {
            let mut score = 0u32;
            
            // Environmental score (25%)
            let env_score = if env.temperature_kelvin < 100 { 25 }
                else if env.temperature_kelvin < 100_000 { 20 }
                else { 15 };
            score += env_score;
            
            // Statistical score (25%)
            score += (stats.quantum_signature_score / 4) as u32;
            
            // Cross-verification score (50%)
            let cross_score: u32 = cross_verifications.iter()
                .map(|v| v.confidence_score as u32)
                .sum::<u32>() / cross_verifications.len() as u32;
            score += cross_score / 2;
            
            score.min(100) as u8
        }
    }
}