#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod sphincs;
pub mod offchain;

pub use sphincs::{QuantumPublic, QuantumSignature, SphincsPlusPublic, SphincsPlusSignature};

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use sp_core::ConstU32;
    use codec::MaxEncodedLen;
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        
        /// Maximum size of quantum entropy pool
        #[pallet::constant]
        type MaxEntropyPoolSize: Get<u32>;
        
        /// QKD endpoint for entropy fetching (set via chain spec)
        #[pallet::constant]
        type QkdEndpoint: Get<Vec<u8>>;
    }

    /// Quantum entropy pool
    #[pallet::storage]
    #[pallet::getter(fn entropy_pool)]
    pub type EntropyPool<T: Config> = StorageValue<_, BoundedVec<u8, T::MaxEntropyPoolSize>, ValueQuery>;

    /// Last quantum entropy update
    #[pallet::storage]
    #[pallet::getter(fn last_entropy_update)]
    pub type LastEntropyUpdate<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Quantum key registry for accounts
    #[pallet::storage]
    #[pallet::getter(fn quantum_keys)]
    pub type QuantumKeys<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, QuantumKeyInfo>;

    /// Quantum metrics from QKD hardware
    #[pallet::storage]
    #[pallet::getter(fn qkd_metrics)]
    pub type QkdMetrics<T> = StorageValue<_, QuantumMetrics, ValueQuery>;

    #[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, MaxEncodedLen)]
    pub struct QuantumKeyInfo {
        pub sphincs_public_key: BoundedVec<u8, ConstU32<64>>,
        pub key_type: QuantumKeyType,
        pub created_at_block: u32,
    }

    #[derive(Clone, Encode, Decode, TypeInfo, PartialEq, MaxEncodedLen, RuntimeDebugNoBound)]
    pub enum QuantumKeyType {
        Sphincs256,
        QkdDerived,
        Hybrid,
    }

    #[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Default, MaxEncodedLen)]
    pub struct QuantumMetrics {
        pub qber: u32, // Quantum Bit Error Rate (basis points)
        pub visibility: u32, // Visibility percentage
        pub key_rate: u32, // Keys per second
        pub last_update: u64,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Quantum entropy updated
        EntropyUpdated { entropy_size: u32 },
        
        /// Quantum key registered
        QuantumKeyRegistered { 
            who: T::AccountId,
        },
        
        /// QKD metrics updated
        QkdMetricsUpdated {
            qber: u32,
            visibility: u32,
            key_rate: u32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Entropy pool is full
        EntropyPoolFull,
        /// Invalid quantum key
        InvalidQuantumKey,
        /// QKD service unavailable
        QkdUnavailable,
        /// Quantum key already exists
        QuantumKeyExists,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit quantum entropy from off-chain worker
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn submit_entropy(
            origin: OriginFor<T>,
            entropy: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            let entropy_size = entropy.len() as u32;
            let bounded_entropy: BoundedVec<u8, T::MaxEntropyPoolSize> = entropy
                .try_into()
                .map_err(|_| Error::<T>::EntropyPoolFull)?;
            
            let mut pool = EntropyPool::<T>::get();
            
            // Check if adding would exceed limit
            let new_len = pool.len().saturating_add(bounded_entropy.len());
            ensure!(new_len <= T::MaxEntropyPoolSize::get() as usize, Error::<T>::EntropyPoolFull);
            
            // Append to pool
            pool.try_extend(bounded_entropy.into_iter())
                .map_err(|_| Error::<T>::EntropyPoolFull)?;
            
            EntropyPool::<T>::put(&pool);
            LastEntropyUpdate::<T>::put(frame_system::Pallet::<T>::block_number());
            
            Self::deposit_event(Event::EntropyUpdated { entropy_size });
            Ok(())
        }

        /// Register a quantum key for an account
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn register_quantum_key(
            origin: OriginFor<T>,
            sphincs_public_key: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            ensure!(!QuantumKeys::<T>::contains_key(&who), Error::<T>::QuantumKeyExists);
            ensure!(sphincs_public_key.len() == 64, Error::<T>::InvalidQuantumKey);
            
            let bounded_key: BoundedVec<u8, ConstU32<64>> = sphincs_public_key
                .try_into()
                .map_err(|_| Error::<T>::InvalidQuantumKey)?;
            
            let key_info = QuantumKeyInfo {
                sphincs_public_key: bounded_key,
                key_type: QuantumKeyType::Sphincs256,
                created_at_block: frame_system::Pallet::<T>::block_number()
                    .try_into()
                    .unwrap_or(0),
            };
            
            QuantumKeys::<T>::insert(&who, &key_info);
            
            Self::deposit_event(Event::QuantumKeyRegistered {
                who,
            });
            
            Ok(())
        }

        /// Update QKD metrics (called by off-chain worker)
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn update_qkd_metrics(
            origin: OriginFor<T>,
            qber: u32,
            visibility: u32,
            key_rate: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;
            
            let metrics = QuantumMetrics {
                qber,
                visibility,
                key_rate,
                last_update: sp_io::offchain::timestamp().unix_millis(),
            };
            
            QkdMetrics::<T>::put(&metrics);
            
            Self::deposit_event(Event::QkdMetricsUpdated {
                qber,
                visibility,
                key_rate,
            });
            
            Ok(())
        }
    }

    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Get quantum entropy for randomness
        pub fn get_quantum_entropy(num_bytes: usize) -> Option<Vec<u8>> {
            let mut pool = EntropyPool::<T>::get();
            
            if pool.len() >= num_bytes {
                // Take from the end
                let start = pool.len().saturating_sub(num_bytes);
                let entropy: Vec<u8> = pool.drain(start..).collect();
                EntropyPool::<T>::put(pool);
                Some(entropy)
            } else {
                None
            }
        }
        
        /// Check if QKD is healthy based on metrics
        pub fn is_qkd_healthy() -> bool {
            let metrics = QkdMetrics::<T>::get();
            let now = sp_io::offchain::timestamp().unix_millis();
            
            // Check if metrics are recent (within 5 minutes)
            if now.saturating_sub(metrics.last_update) > 300_000 {
                return false;
            }
            
            // QBER should be below 5%
            metrics.qber < 500 && metrics.visibility > 80 && metrics.key_rate > 0
        }
    }
}