#![cfg_attr(not(feature = "std"), no_std)]

//! # QKD Network Pallet
//!
//! Manages Quantum Key Distribution hardware devices and their network topology.
//! Implements the Hardware-Based Authority model where network participation
//! is based on physical infrastructure investment rather than token staking.

use frame_support::{
    dispatch::DispatchResult,
    pallet_prelude::*,
    traits::UnixTime,
};
use frame_system::pallet_prelude::*;
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
        
        /// Unix time provider
        type UnixTime: UnixTime;
        
        /// Minimum uptime percentage required (per mille)
        #[pallet::constant]
        type MinUptime: Get<u32>;
        
        /// Maximum QBER allowed (per mille)
        #[pallet::constant]
        type MaxQBER: Get<u32>;
        
        /// Minimum entropy contribution per epoch (bits)
        #[pallet::constant]
        type MinEntropyContribution: Get<u32>;
    }

    /// QKD device types
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub enum DeviceType {
        /// Toshiba QKD system
        Toshiba,
        /// ID Quantique system
        IDQ,
        /// Basejump QKD
        Basejump,
        /// Simulated for testing
        Simulated,
        /// Other vendor
        Other(Vec<u8>),
    }

    /// QKD device information
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct QKDDevice {
        /// Device owner/operator
        pub operator: T::AccountId,
        /// Device type
        pub device_type: DeviceType,
        /// MAC address
        pub mac_address: [u8; 6],
        /// IP endpoint
        pub endpoint: Vec<u8>,
        /// Certificate hash
        pub cert_hash: T::Hash,
        /// Registration timestamp
        pub registered_at: u64,
        /// Last seen timestamp
        pub last_seen: u64,
        /// Total keys generated
        pub keys_generated: u64,
        /// Average QBER (per mille)
        pub avg_qber: u32,
        /// Uptime percentage (per mille)
        pub uptime: u32,
        /// Total entropy contributed (bits)
        pub entropy_contributed: u128,
    }

    /// QKD link between two devices
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct QKDLink {
        /// Alice device MAC
        pub alice_mac: [u8; 6],
        /// Bob device MAC
        pub bob_mac: [u8; 6],
        /// Link distance (km)
        pub distance: u32,
        /// Current QBER (per mille)
        pub current_qber: u32,
        /// Link capacity (keys/sec)
        pub capacity: u32,
        /// Is link active?
        pub active: bool,
        /// Last key exchange
        pub last_key_exchange: u64,
    }

    /// Hardware operator metrics (replaces staking metrics)
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
    pub struct OperatorMetrics {
        /// Number of devices operated
        pub device_count: u32,
        /// Total uptime across all devices
        pub total_uptime: u32,
        /// Total entropy contributed
        pub total_entropy: u128,
        /// Network coverage score
        pub coverage_score: u32,
        /// Reliability score
        pub reliability_score: u32,
    }

    #[pallet::storage]
    #[pallet::getter(fn devices)]
    pub type Devices<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 6], QKDDevice<T>>;

    #[pallet::storage]
    #[pallet::getter(fn links)]
    pub type Links<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        [u8; 6],
        Blake2_128Concat,
        [u8; 6],
        QKDLink
    >;

    #[pallet::storage]
    #[pallet::getter(fn operator_metrics)]
    pub type OperatorMetrics<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        OperatorMetrics
    >;

    #[pallet::storage]
    #[pallet::getter(fn network_stats)]
    pub type NetworkStats<T: Config> = StorageValue<_, NetworkStatistics, ValueQuery>;

    /// Global network statistics
    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, Default)]
    pub struct NetworkStatistics {
        pub total_devices: u32,
        pub active_links: u32,
        pub total_keys_generated: u128,
        pub average_qber: u32,
        pub total_entropy_bits: u128,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New QKD device registered
        DeviceRegistered {
            operator: T::AccountId,
            mac_address: [u8; 6],
            device_type: DeviceType,
        },
        
        /// QKD link established
        LinkEstablished {
            alice_mac: [u8; 6],
            bob_mac: [u8; 6],
            distance: u32,
        },
        
        /// Device metrics updated
        DeviceMetricsUpdated {
            mac_address: [u8; 6],
            qber: u32,
            keys_generated: u64,
        },
        
        /// Low performance warning
        LowPerformanceWarning {
            mac_address: [u8; 6],
            metric: Vec<u8>,
            value: u32,
        },
        
        /// Operator promoted (based on hardware contribution)
        OperatorPromoted {
            operator: T::AccountId,
            new_score: u32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Device already registered
        DeviceAlreadyRegistered,
        /// Device not found
        DeviceNotFound,
        /// Invalid MAC address
        InvalidMacAddress,
        /// QBER too high
        QBERTooHigh,
        /// Insufficient uptime
        InsufficientUptime,
        /// Link already exists
        LinkAlreadyExists,
        /// Cannot link device to itself
        CannotLinkToSelf,
        /// Devices too far apart
        DistanceTooGreat,
        /// Insufficient hardware contribution
        InsufficientContribution,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new QKD device
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn register_device(
            origin: OriginFor<T>,
            device_type: DeviceType,
            mac_address: [u8; 6],
            endpoint: Vec<u8>,
            cert_hash: T::Hash,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            
            ensure!(
                !Devices::<T>::contains_key(&mac_address),
                Error::<T>::DeviceAlreadyRegistered
            );
            
            let now = T::UnixTime::now().as_secs();
            
            let device = QKDDevice {
                operator: operator.clone(),
                device_type: device_type.clone(),
                mac_address,
                endpoint,
                cert_hash,
                registered_at: now,
                last_seen: now,
                keys_generated: 0,
                avg_qber: 0,
                uptime: 1000, // Start at 100%
                entropy_contributed: 0,
            };
            
            Devices::<T>::insert(&mac_address, &device);
            
            // Update operator metrics
            OperatorMetrics::<T>::mutate(&operator, |metrics| {
                let m = metrics.get_or_insert(OperatorMetrics {
                    device_count: 0,
                    total_uptime: 0,
                    total_entropy: 0,
                    coverage_score: 0,
                    reliability_score: 1000,
                });
                m.device_count += 1;
            });
            
            // Update network stats
            NetworkStats::<T>::mutate(|stats| {
                stats.total_devices += 1;
            });
            
            Self::deposit_event(Event::DeviceRegistered {
                operator,
                mac_address,
                device_type,
            });
            
            Ok(())
        }
        
        /// Establish a QKD link between two devices
        #[pallet::call_index(1)]
        #[pallet::weight(15_000)]
        pub fn establish_link(
            origin: OriginFor<T>,
            alice_mac: [u8; 6],
            bob_mac: [u8; 6],
            distance: u32,
            capacity: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            ensure!(alice_mac != bob_mac, Error::<T>::CannotLinkToSelf);
            ensure!(
                Devices::<T>::contains_key(&alice_mac),
                Error::<T>::DeviceNotFound
            );
            ensure!(
                Devices::<T>::contains_key(&bob_mac),
                Error::<T>::DeviceNotFound
            );
            ensure!(
                !Links::<T>::contains_key(&alice_mac, &bob_mac),
                Error::<T>::LinkAlreadyExists
            );
            
            // Check distance feasibility (typical QKD limit ~100km)
            ensure!(distance <= 150, Error::<T>::DistanceTooGreat);
            
            let now = T::UnixTime::now().as_secs();
            
            let link = QKDLink {
                alice_mac,
                bob_mac,
                distance,
                current_qber: 0,
                capacity,
                active: true,
                last_key_exchange: now,
            };
            
            // Store bidirectionally
            Links::<T>::insert(&alice_mac, &bob_mac, &link);
            Links::<T>::insert(&bob_mac, &alice_mac, &link);
            
            NetworkStats::<T>::mutate(|stats| {
                stats.active_links += 1;
            });
            
            Self::deposit_event(Event::LinkEstablished {
                alice_mac,
                bob_mac,
                distance,
            });
            
            Ok(())
        }
        
        /// Update device metrics (called by off-chain worker or oracle)
        #[pallet::call_index(2)]
        #[pallet::weight(5_000)]
        pub fn update_device_metrics(
            origin: OriginFor<T>,
            mac_address: [u8; 6],
            qber: u32,
            keys_generated: u64,
            entropy_bits: u128,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            
            ensure!(qber <= T::MaxQBER::get(), Error::<T>::QBERTooHigh);
            
            let now = T::UnixTime::now().as_secs();
            
            Devices::<T>::mutate(&mac_address, |device| {
                if let Some(d) = device {
                    d.last_seen = now;
                    d.keys_generated += keys_generated;
                    d.entropy_contributed += entropy_bits;
                    
                    // Update average QBER
                    if d.avg_qber == 0 {
                        d.avg_qber = qber;
                    } else {
                        d.avg_qber = (d.avg_qber + qber) / 2;
                    }
                    
                    // Update operator metrics
                    OperatorMetrics::<T>::mutate(&d.operator, |metrics| {
                        if let Some(m) = metrics {
                            m.total_entropy += entropy_bits;
                        }
                    });
                    
                    // Update network stats
                    NetworkStats::<T>::mutate(|stats| {
                        stats.total_keys_generated += keys_generated as u128;
                        stats.total_entropy_bits += entropy_bits;
                    });
                }
            });
            
            Self::deposit_event(Event::DeviceMetricsUpdated {
                mac_address,
                qber,
                keys_generated,
            });
            
            Ok(())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        /// Calculate operator's authority weight based on hardware contribution
        pub fn calculate_authority_weight(operator: &T::AccountId) -> u32 {
            if let Some(metrics) = OperatorMetrics::<T>::get(operator) {
                // Weight based on:
                // - Number of devices (40%)
                // - Reliability score (30%)
                // - Entropy contribution (30%)
                let device_weight = metrics.device_count * 400;
                let reliability_weight = metrics.reliability_score * 3 / 10;
                let entropy_weight = (metrics.total_entropy.min(u128::MAX / 1000) / 1000) as u32 * 3 / 10;
                
                device_weight + reliability_weight + entropy_weight
            } else {
                0
            }
        }
        
        /// Check if operator meets minimum requirements
        pub fn is_qualified_operator(operator: &T::AccountId) -> bool {
            if let Some(metrics) = OperatorMetrics::<T>::get(operator) {
                metrics.device_count > 0 &&
                metrics.reliability_score >= 700 && // 70%
                metrics.total_entropy >= T::MinEntropyContribution::get() as u128
            } else {
                false
            }
        }
    }
}