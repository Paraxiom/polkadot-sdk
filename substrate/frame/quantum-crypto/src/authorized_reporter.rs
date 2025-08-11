//! Authorized Reporter System
//! 
//! This module implements KYC/KYE verification for quantum event reporters
//! ensuring only authorized node operators can submit to the priority queue.

use crate::{Config, Pallet, Error, Event};
use frame_support::{pallet_prelude::*, traits::Currency};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Saturating;
use sp_std::{vec, vec::Vec};
use sp_core::H256;

// Import the types from offchain module when available
#[cfg(feature = "std")]
use crate::offchain::{QuantumEventType, QuantumDataSource};

/// Reporter authorization status
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq)]
pub enum ReporterStatus {
    /// Pending KYC/KYE verification
    Pending,
    /// Authorized to submit quantum events
    Authorized,
    /// Temporarily suspended
    Suspended,
    /// Permanently revoked
    Revoked,
}

/// Reporter registration information
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct ReporterInfo<AccountId, BlockNumber> {
    /// Node operator account
    pub operator: AccountId,
    /// Reporter status
    pub status: ReporterStatus,
    /// KYC/KYE verification hash
    pub kyc_hash: H256,
    /// Hardware attestation certificate
    pub hardware_cert: BoundedVec<u8, ConstU32<1024>>,
    /// Registration block
    pub registered_at: BlockNumber,
    /// Last activity block
    pub last_active: BlockNumber,
    /// Rate limit: max events per hour
    pub rate_limit: u32,
    /// Events submitted in current window
    pub events_submitted: u32,
    /// Rate limit window start
    pub window_start: u64,
    /// Local machine identifier (hash of hardware fingerprint)
    pub machine_id: H256,
}

// Storage items are now defined in the main pallet module (lib.rs)
// We use them here through the main pallet

impl<T: crate::Config> crate::Pallet<T> {
    /// Register a new quantum event reporter (internal helper)
    pub fn do_register_reporter(
        operator: T::AccountId,
        kyc_hash: H256,
        hardware_cert: Vec<u8>,
        machine_id: H256,
    ) -> DispatchResult {
        // Check machine not already registered
        ensure!(
            !crate::MachineRegistry::<T>::contains_key(&machine_id),
            Error::<T>::MachineAlreadyRegistered
        );
        
        // Verify hardware certificate
        ensure!(
            Self::verify_hardware_certificate(&hardware_cert),
            Error::<T>::InvalidHardwareCertificate
        );
        
        let bounded_cert: BoundedVec<u8, ConstU32<1024>> = hardware_cert
            .try_into()
            .map_err(|_| Error::<T>::CertificateTooLarge)?;
        
        let current_block = frame_system::Pallet::<T>::block_number();
        let (rate_limit, _) = crate::RateLimitConfig::<T>::get();
        
        let reporter_info = ReporterInfo {
            operator: operator.clone(),
            status: ReporterStatus::Pending, // Starts as pending
            kyc_hash,
            hardware_cert: bounded_cert,
            registered_at: current_block,
            last_active: current_block,
            rate_limit,
            events_submitted: 0,
            window_start: sp_io::offchain::timestamp().unix_millis() / 1000,
            machine_id,
        };
        
        crate::AuthorizedReporters::<T>::insert(&operator, reporter_info);
        crate::MachineRegistry::<T>::insert(&machine_id, &operator);
        
        Self::deposit_event(Event::ReporterRegistered {
            operator,
            machine_id,
        });
        
        Ok(())
    }
    
    /// Authorize a reporter after KYC/KYE verification (internal helper)
    pub fn do_authorize_reporter(operator: &T::AccountId) -> DispatchResult {
        crate::AuthorizedReporters::<T>::try_mutate(operator, |maybe_reporter| {
            let reporter = maybe_reporter.as_mut()
                .ok_or(Error::<T>::ReporterNotFound)?;
            
            ensure!(
                reporter.status == ReporterStatus::Pending,
                Error::<T>::InvalidReporterStatus
            );
            
            reporter.status = ReporterStatus::Authorized;
            
            Self::deposit_event(Event::ReporterAuthorized {
                operator: operator.clone(),
            });
            
            Ok(())
        })
    }
    
    /// Check if reporter is authorized and not rate limited
    pub fn check_reporter_authorization(
        operator: &T::AccountId,
        machine_id: &H256,
    ) -> Result<(), DispatchError> {
        // Get reporter info
        let mut reporter = crate::AuthorizedReporters::<T>::get(operator)
            .ok_or(Error::<T>::ReporterNotFound)?;
        
        // Verify status
        ensure!(
            reporter.status == ReporterStatus::Authorized,
            Error::<T>::ReporterNotAuthorized
        );
        
        // Verify machine ID matches
        ensure!(
            &reporter.machine_id == machine_id,
            Error::<T>::InvalidMachineId
        );
        
        // Check rate limit
        let current_time = sp_io::offchain::timestamp().unix_millis() / 1000;
        let (max_events, window_duration) = crate::RateLimitConfig::<T>::get();
        
        // Reset window if expired
        if current_time >= reporter.window_start + window_duration {
            reporter.window_start = current_time;
            reporter.events_submitted = 0;
        }
        
        // Check if under rate limit
        ensure!(
            reporter.events_submitted < max_events,
            Error::<T>::RateLimitExceeded
        );
        
        // Update activity
        reporter.last_active = frame_system::Pallet::<T>::block_number();
        reporter.events_submitted = reporter.events_submitted.saturating_add(1);
        
        crate::AuthorizedReporters::<T>::insert(operator, reporter);
        
        Ok(())
    }
    
    /// Submit quantum event with authorization check
    #[cfg(feature = "std")]
    pub fn submit_authorized_event(
        operator: T::AccountId,
        machine_id: H256,
        event_type: QuantumEventType,
        data: Vec<u8>,
        source: QuantumDataSource,
        qber: Option<f32>,
    ) -> Result<(), DispatchError> {
        // Check authorization and rate limit
        Self::check_reporter_authorization(&operator, &machine_id)?;
        
        // Submit to priority queue
        #[cfg(feature = "std")]
        {
            // TODO: Implement priority queue submission
            // For now, just log the event
            use log::info;
            info!("Would submit event to priority queue: {:?}", event_type);
        }
        
        Ok(())
    }
    
    /// Suspend a reporter (internal helper)
    pub fn do_suspend_reporter(operator: &T::AccountId) -> DispatchResult {
        crate::AuthorizedReporters::<T>::try_mutate(operator, |maybe_reporter| {
            let reporter = maybe_reporter.as_mut()
                .ok_or(Error::<T>::ReporterNotFound)?;
            
            reporter.status = ReporterStatus::Suspended;
            
            Self::deposit_event(Event::ReporterSuspended {
                operator: operator.clone(),
            });
            
            Ok(())
        })
    }
    
    /// Get reporter metrics
    pub fn get_reporter_metrics(operator: &T::AccountId) -> Option<(u32, u32)> {
        crate::AuthorizedReporters::<T>::get(operator).map(|reporter| {
            (reporter.events_submitted, reporter.rate_limit)
        })
    }
    
    // verify_hardware_certificate is defined in the main pallet (lib.rs)
}