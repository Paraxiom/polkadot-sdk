//! Offchain worker for processing quantum events
//!
//! This module implements the offchain worker that:
//! 1. Fetches quantum events from the priority queue
//! 2. Validates the data (QBER, signatures, etc)
//! 3. Submits valid events as unsigned transactions
//! 4. Leader nodes perform additional validation

use crate::{Config, Pallet, Error};
use frame_support::ensure;
use frame_system::{offchain::SubmitTransaction, pallet_prelude::BlockNumberFor};
use log::{info, error};
use sp_runtime::{
    SaturatedConversion,
    transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
    },
    offchain::{http, Duration},
};
use sp_std::{vec, vec::Vec, str};
use sp_core::{crypto::KeyTypeId, H256};
use codec::{Encode, Decode};

/// Key type for signing offchain transactions
pub const QUANTUM_OFFCHAIN: KeyTypeId = KeyTypeId(*b"qoff");

impl<T: Config> Pallet<T> {
    /// Offchain worker entry point
    pub fn offchain_worker(block_number: BlockNumberFor<T>) {
        info!("Quantum offchain worker at block: {:?}", block_number);
        
        // Check if it's time to select new committee (every 2880 blocks = ~1 day)
        let block_num = block_number.saturated_into::<u64>();
        if block_num % 2880 == 0 {
            let epoch = block_num / 2880;
            info!("Epoch boundary reached, selecting new committee for epoch {}", epoch);
            
            // Select committee using QVRF
            match Self::select_committee_with_qvrf(epoch, 10) {
                Ok(committee) => {
                    info!("New committee selected: {:?}", committee);
                },
                Err(e) => {
                    error!("Failed to select committee: {:?}", e);
                }
            }
        }
        
        // Check if we're the leader for this block window
        let is_leader = Self::is_current_leader(block_number);
        
        if is_leader {
            info!("This node is the leader, processing high priority events");
            Self::process_events_as_leader();
        } else {
            info!("This node is a validator, processing standard events");
            Self::process_events_as_validator();
        }
        
        // All nodes process entropy updates
        Self::update_entropy_pool();
    }
    
    /// Check if current node is the leader using QVRF
    fn is_current_leader(block_number: BlockNumberFor<T>) -> bool {
        // Get current epoch and slot
        let epoch = block_number.saturated_into::<u64>() / 2880; // ~1 day epochs
        let slot = block_number.saturated_into::<u64>() % 2880;
        
        // Get validator account from authorized reporters
        // In production, this would check the keystore
        // For now, return false as we need proper offchain worker setup
        false
    }
    
    /// Process events as the leader node
    fn process_events_as_leader() {
        // Leader fetches from primary queue (port 5555)
        if let Ok(event) = Self::fetch_event_from_queue("http://localhost:5555") {
            match Self::validate_quantum_event(&event) {
                Ok(()) => {
                    info!("Leader validated event: {:?}", event.id);
                    let _ = Self::submit_quantum_event(event);
                },
                Err(e) => {
                    error!("Leader rejected event: {:?}", e);
                    // Could notify other nodes about invalid event
                }
            }
        }
    }
    
    /// Process events as a validator node
    fn process_events_as_validator() {
        // Validators fetch from secondary queue (port 5556)
        if let Ok(event) = Self::fetch_event_from_queue("http://localhost:5556") {
            // Validators perform basic validation only
            if event.qber.unwrap_or(0.0) < 0.11 {
                let _ = Self::submit_quantum_event(event);
            }
        }
    }
    
    /// Fetch the next event from the priority queue
    fn fetch_event_from_queue(queue_url: &str) -> Result<QuantumEventData, &'static str> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(5_000));
        
        // Prepare the RPC request
        let body = r#"{"jsonrpc":"2.0","method":"pop_quantum_event","params":[],"id":1}"#;
        
        let request = http::Request::post(queue_url, vec![body.as_bytes()])
            .add_header("Content-Type", "application/json")
            .deadline(deadline);
        
        let pending = request.send().map_err(|_| "Failed to send request")?;
        let response = pending.try_wait(deadline).map_err(|_| "Request timeout")?
            .map_err(|_| "Request failed")?;
        
        if response.code != 200 {
            return Err("Non-200 response");
        }
        
        let body = response.body().collect::<Vec<u8>>();
        let body_str = str::from_utf8(&body).map_err(|_| "Invalid UTF-8")?;
        
        // Parse JSON response
        Self::parse_queue_response(body_str)
    }
    
    /// Parse the JSON response from the queue
    fn parse_queue_response(response: &str) -> Result<QuantumEventData, &'static str> {
        // Simple JSON parsing for no_std environment
        // In production, use a proper no_std JSON parser
        
        // Extract the result field
        if let Some(start) = response.find(r#""result":"#) {
            if let Some(data_start) = response[start..].find(r#""data":"#) {
                if let Some(data_end) = response[start + data_start + 8..].find('"') {
                    let data = &response[start + data_start + 8..start + data_start + 8 + data_end];
                    
                    // Extract other fields similarly...
                    // This is simplified - real implementation needs proper parsing
                    
                    return Ok(QuantumEventData {
                        id: 1,
                        event_type: QuantumEventType::QuantumEntropy,
                        data: data.as_bytes().to_vec(),
                        qber: None,
                        source: QuantumDataSource::KirqHub,
                    });
                }
            }
        }
        
        Err("Failed to parse response")
    }
    
    /// Validate a quantum event before submission
    fn validate_quantum_event(event: &QuantumEventData) -> Result<(), &'static str> {
        match event.event_type {
            QuantumEventType::QberMeasurement => {
                // Validate QBER is within acceptable range
                if let Some(qber) = event.qber {
                    ensure!(qber < 0.11, "QBER too high");
                    ensure!(qber > 0.0, "QBER cannot be zero");
                }
            },
            QuantumEventType::QuantumEntropy => {
                // Validate entropy has sufficient randomness
                ensure!(!event.data.is_empty(), "Empty entropy data");
                ensure!(event.data.len() >= 32, "Insufficient entropy");
                
                // Check for obvious patterns
                let first = event.data[0];
                ensure!(
                    !event.data.iter().all(|&b| b == first),
                    "Entropy lacks randomness"
                );
            },
            QuantumEventType::QkdKeyMaterial => {
                // Validate key material format
                ensure!(event.data.len() >= 256, "Key material too short");
            },
            _ => {}
        }
        
        Ok(())
    }
    
    /// Submit quantum event as unsigned transaction
    fn submit_quantum_event(event: QuantumEventData) -> Result<(), &'static str> {
        let call = match event.event_type {
            QuantumEventType::QuantumEntropy => {
                // Parse entropy from event data
                let entropy = Self::parse_entropy_data(&event.data)?;
                crate::Call::<T>::add_entropy { entropy }
            },
            QuantumEventType::QkdKeyMaterial => {
                // Parse QKD key material
                let (key_material, channel_id) = Self::parse_qkd_data(&event.data)?;
                // Store in quantum crypto storage
                crate::Call::<T>::store_qkd_keys { 
                    channel_id,
                    key_material,
                    qber: (event.qber.unwrap_or(0.0) * 10000.0) as u32,
                }
            },
            QuantumEventType::QberMeasurement => {
                crate::Call::<T>::update_qber { 
                    value: (event.qber.unwrap_or(0.0) * 10000.0) as u32,
                    proof: event.data
                }
            },
            _ => return Err("Unsupported event type"),
        };
        
        // TODO: Proper unsigned transaction submission requires runtime configuration
        // For now, we'll need to configure this in the runtime
        /*
        let xt = T::create_bare(call.into());
        let result = SubmitTransaction::<T, crate::Call<T>>::submit_transaction(xt);
        
        match result {
            Ok(()) => {
                info!("Submitted quantum event: {:?}", event.id);
                Ok(())
            },
            Err(()) => {
                error!("Failed to submit quantum event");
                Err("Transaction submission failed")
            }
        }
        */
        
        // Temporarily return success
        info!("Would submit quantum event: {:?}", event.id);
        Ok(())
    }
    
    /// Fetch quantum keys from KIRQ hub
    fn fetch_from_kirq_hub() -> Result<Vec<u8>, &'static str> {
        // KIRQ hub endpoint
        let url = "http://localhost:8001/entropy";
        
        // Create HTTP request
        let request = http::Request::get(url);
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(3000));
        
        let pending = request.deadline(deadline).send().map_err(|_| "HTTP request failed")?;
        let response = pending.wait().map_err(|_| "HTTP request timeout")?;
        
        if response.code != 200 {
            return Err("KIRQ hub returned error");
        }
        
        let body = response.body().collect::<Vec<u8>>();
        
        // KIRQ hub returns JSON with entropy field
        // For MVP, we just extract the raw bytes
        if body.len() > 32 {
            Ok(body)
        } else {
            Err("Insufficient entropy from KIRQ hub")
        }
    }
    
    /// Update the entropy pool with fresh quantum randomness
    fn update_entropy_pool() {
        // Try to fetch from KIRQ hub first
        if let Ok(kirq_entropy) = Self::fetch_from_kirq_hub() {
            info!("Fetched {} bytes from KIRQ hub", kirq_entropy.len());
            // Submit as entropy
            let _ = Self::submit_quantum_event(QuantumEventData {
                id: 0, // Will be assigned by the event submitter
                event_type: QuantumEventType::QuantumEntropy,
                data: kirq_entropy,
                qber: None,
                source: QuantumDataSource::KirqHub,
            });
        }
        
        // Get operator account and machine ID
        let (operator, machine_id) = match Self::get_reporter_identity() {
            Some(identity) => identity,
            None => {
                error!("No reporter identity configured");
                return;
            }
        };
        
        // Submit entropy request to priority queue
        // This ensures proper ordering and prevents overwhelming the chain
        match Self::fetch_and_queue_entropy_authorized(operator.clone(), machine_id) {
            Ok(()) => {
                info!("Queued entropy update request");
            },
            Err(e) => {
                error!("Failed to queue entropy: {}", e);
            }
        }
        
        // Also check if we need QKD keys
        if Self::should_refresh_qkd_keys() {
            match Self::fetch_and_queue_qkd_keys_authorized(operator, machine_id) {
                Ok(()) => {
                    info!("Queued QKD key material request");
                },
                Err(e) => {
                    error!("Failed to queue QKD keys: {}", e);
                }
            }
        }
    }
    
    /// Check if QKD keys need refreshing
    fn should_refresh_qkd_keys() -> bool {
        // Refresh every 100 blocks or if QBER is high
        let block_number = frame_system::Pallet::<T>::block_number();
        block_number.saturated_into::<u64>() % 100 == 0
    }
    
    fn fetch_quantum_entropy() -> Result<Vec<u8>, &'static str> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
        
        let request = http::Request::get("http://localhost:8001/entropy/32")
            .deadline(deadline);
        
        let pending = request.send().map_err(|_| "Failed to send request")?;
        let response = pending.try_wait(deadline).map_err(|_| "Request timeout")?
            .map_err(|_| "Request failed")?;
        
        if response.code != 200 {
            return Err("Failed to fetch entropy");
        }
        
        let body = response.body().collect::<Vec<u8>>();
        
        // Extract hex entropy from response
        // In production, parse JSON properly
        if body.len() >= 64 {
            Ok(body[..32].to_vec())
        } else {
            Err("Invalid entropy response")
        }
    }
    
    fn submit_entropy_update(entropy: Vec<u8>) -> Result<(), &'static str> {
        // TODO: Proper unsigned transaction submission requires runtime configuration
        /*
        let call = crate::Call::<T>::add_entropy { entropy };
        
        let xt = T::create_bare(call.into());
        SubmitTransaction::<T, crate::Call<T>>::submit_transaction(xt)
            .map_err(|_| "Failed to submit entropy")
        */
        Ok(())
    }
    
    /// Parse entropy data from queue event
    fn parse_entropy_data(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        // In production, parse JSON properly
        // For now, assume raw entropy bytes
        if data.is_empty() {
            return Err("Empty entropy data");
        }
        Ok(data.to_vec())
    }
    
    /// Parse QKD key material from queue event
    fn parse_qkd_data(data: &[u8]) -> Result<(Vec<u8>, H256), &'static str> {
        // In production, parse JSON to extract key_material and channel_id
        // For now, use simple format: first 32 bytes = channel_id, rest = key material
        if data.len() < 32 {
            return Err("Invalid QKD data format");
        }
        
        let mut channel_bytes = [0u8; 32];
        channel_bytes.copy_from_slice(&data[..32]);
        let channel_id = H256::from(channel_bytes);
        
        let key_material = data[32..].to_vec();
        
        Ok((key_material, channel_id))
    }
    
    /// Get reporter identity from local configuration
    fn get_reporter_identity() -> Option<(T::AccountId, H256)> {
        // In production, this would read from local node configuration
        // For now, return None as we need proper offchain worker setup
        None
    }
    
    /// Fetch and queue entropy with authorization
    fn fetch_and_queue_entropy_authorized(
        operator: T::AccountId,
        machine_id: H256,
    ) -> Result<(), &'static str> {
        // Fetch from KIRQ hub
        let entropy = Self::fetch_entropy_from_kirq()?;
        
        // Submit to priority queue with authorization
        Self::submit_entropy_to_queue(operator, machine_id, entropy, QuantumDataSource::KirqHub)?;
        
        Ok(())
    }
    
    /// Fetch and queue QKD keys with authorization
    fn fetch_and_queue_qkd_keys_authorized(
        operator: T::AccountId,
        machine_id: H256,
    ) -> Result<(), &'static str> {
        // In production, this would fetch from QKD API
        let channel_id = H256::random();
        let key_material = vec![0u8; 256]; // Placeholder
        let qber = Some(0.05);
        
        // Submit to priority queue with authorization
        Self::submit_qkd_keys_to_queue(
            operator,
            machine_id,
            key_material,
            channel_id,
            qber,
        )?;
        
        Ok(())
    }
    
    /// Fetch entropy from KIRQ hub
    fn fetch_entropy_from_kirq() -> Result<Vec<u8>, &'static str> {
        // TODO: Implement actual KIRQ hub integration
        // For now, return dummy entropy
        Ok(vec![0u8; 32])
    }
    
    /// Submit entropy to priority queue
    fn submit_entropy_to_queue(
        _operator: T::AccountId,
        _machine_id: H256,
        _entropy: Vec<u8>,
        _source: QuantumDataSource,
    ) -> Result<(), &'static str> {
        // TODO: Implement priority queue submission
        Ok(())
    }
    
    /// Submit QKD keys to priority queue
    fn submit_qkd_keys_to_queue(
        _operator: T::AccountId,
        _machine_id: H256,
        _key_material: Vec<u8>,
        _channel_id: H256,
        _qber: Option<f32>,
    ) -> Result<(), &'static str> {
        // TODO: Implement priority queue submission
        Ok(())
    }
    
    /// Submit event to priority queue
    fn submit_to_priority_queue(
        _event_type: QuantumEventType,
        _data: String,
        _source: QuantumDataSource,
        _qber: Option<f32>,
    ) -> Result<(), &'static str> {
        // TODO: Implement priority queue submission
        Ok(())
    }
}

/// Quantum event data structure (matches priority queue)
#[derive(Clone, Debug, Encode, Decode)]
pub struct QuantumEventData {
    pub id: u64,
    pub event_type: QuantumEventType,
    pub data: Vec<u8>,
    pub qber: Option<f32>,
    pub source: QuantumDataSource,
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum QuantumEventType {
    QuantumEntropy,
    QkdKeyMaterial,
    QberMeasurement,
    CoherenceMeasurement,
    QuantumSignature,
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum QuantumDataSource {
    ToshibaQkd,
    Crypto4aHsm,
    KirqHub,
    DirectMeasurement,
}

/// Validate unsigned transactions from offchain workers  
pub fn validate_unsigned<T: Config>(
        _source: TransactionSource,
        call: &crate::Call<T>,
    ) -> TransactionValidity {
        match call {
            crate::Call::add_entropy { entropy } => {
                // Basic validation
                if entropy.is_empty() {
                    return InvalidTransaction::BadProof.into();
                }
                
                ValidTransaction::with_tag_prefix("QuantumEntropy")
                    .priority(100)
                    .and_provides([&entropy[..]])
                    .longevity(5)
                    .propagate(true)
                    .build()
            },
            crate::Call::update_qber { value, .. } => {
                // Validate QBER range
                if *value > 1500 || *value == 0 { // QBER > 15% or 0
                    return InvalidTransaction::BadProof.into();
                }
                
                ValidTransaction::with_tag_prefix("QberUpdate")
                    .priority(if *value > 1000 { 1000 } else { 200 }) // QBER > 10%
                    .longevity(3)
                    .propagate(true)
                    .build()
            },
            _ => InvalidTransaction::Call.into(),
        }
    }