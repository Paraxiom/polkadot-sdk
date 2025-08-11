//! Quantum Event Submitter
//! 
//! This module handles submission of quantum events (entropy, QKD keys) 
//! through the priority queue for proper ordering and verification.

use crate::{Config, Pallet, Error};
use sp_runtime::offchain::{http, Duration};
use sp_std::{vec, vec::Vec};
use sp_core::H256;
use codec::Encode;
use log::{info, error};

// Import types from offchain module
#[cfg(feature = "std")]
use crate::offchain::{QuantumEventType, QuantumDataSource};
#[cfg(feature = "std")]
use serde_json;

impl<T: crate::Config> crate::Pallet<T> {
    /// Submit quantum entropy to priority queue (with authorization)
    #[cfg(feature = "std")]
    pub fn submit_entropy_to_queue_with_auth(
        operator: T::AccountId,
        machine_id: H256,
        entropy: Vec<u8>,
        source: QuantumDataSource,
    ) -> Result<(), &'static str> {
        // Check reporter authorization
        Self::check_reporter_authorization(&operator, &machine_id)
            .map_err(|_| "Reporter not authorized")?;
        let event_data = serde_json::json!({
            "entropy": sp_core::bytes::to_hex(&entropy, false),
            "source": match source {
                QuantumDataSource::KirqHub => "KirqHub",
                QuantumDataSource::Crypto4aHsm => "Crypto4aHsm",
                QuantumDataSource::ToshibaQkd => "ToshibaQkd",
                QuantumDataSource::DirectMeasurement => "DirectMeasurement",
            },
            "timestamp": sp_io::offchain::timestamp().unix_millis(),
        });
        
        Self::submit_to_priority_queue_internal(
            QuantumEventType::QuantumEntropy,
            event_data.to_string(),
            source,
            None,
        )
    }
    
    /// Submit QKD key material to priority queue (with authorization)
    #[cfg(feature = "std")]
    pub fn submit_qkd_keys_to_queue_with_auth(
        operator: T::AccountId,
        machine_id: H256,
        key_material: Vec<u8>,
        channel_id: H256,
        qber: Option<f32>,
    ) -> Result<(), &'static str> {
        // Check reporter authorization
        Self::check_reporter_authorization(&operator, &machine_id)
            .map_err(|_| "Reporter not authorized")?;
        let event_data = serde_json::json!({
            "key_material": sp_core::bytes::to_hex(&key_material, false),
            "channel_id": sp_core::bytes::to_hex(channel_id.as_bytes(), false),
            "qber": qber,
            "timestamp": sp_io::offchain::timestamp().unix_millis(),
        });
        
        Self::submit_to_priority_queue_internal(
            QuantumEventType::QkdKeyMaterial,
            event_data.to_string(),
            QuantumDataSource::ToshibaQkd,
            qber,
        )
    }
    
    /// Submit event to priority queue RPC
    #[cfg(feature = "std")]
    fn submit_to_priority_queue_internal(
        event_type: QuantumEventType,
        data: String,
        source: QuantumDataSource,
        qber: Option<f32>,
    ) -> Result<(), &'static str> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(5_000));
        
        // Prepare RPC request
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "submit_quantum_event",
            "params": {
                "event_type": match event_type {
                    QuantumEventType::QuantumEntropy => "QuantumEntropy",
                    QuantumEventType::QkdKeyMaterial => "QkdKeyMaterial",
                    QuantumEventType::QberMeasurement => "QberMeasurement",
                    QuantumEventType::CoherenceMeasurement => "CoherenceMeasurement",
                    QuantumEventType::QuantumSignature => "QuantumSignature",
                },
                "data": data,
                "source": match source {
                    QuantumDataSource::KirqHub => "KirqHub",
                    QuantumDataSource::Crypto4aHsm => "Crypto4aHsm",
                    QuantumDataSource::ToshibaQkd => "ToshibaQkd",
                    QuantumDataSource::DirectMeasurement => "DirectMeasurement",
                },
                "qber": qber,
            },
            "id": 1
        });
        
        let body = request_body.to_string();
        
        // Submit to priority queue (port 5555 for high priority)
        let request = http::Request::post("http://localhost:5555", vec![body.as_bytes()])
            .add_header("Content-Type", "application/json")
            .deadline(deadline);
        
        let pending = request.send().map_err(|_| "Failed to send request")?;
        let response = pending.try_wait(deadline)
            .map_err(|_| "Request timeout")?
            .map_err(|_| "Request failed")?;
        
        if response.code != 200 {
            error!("Priority queue rejected event: {}", response.code);
            return Err("Priority queue submission failed");
        }
        
        info!("Submitted {:?} event to priority queue", event_type);
        Ok(())
    }
    
    // These functions are now implemented in offchain.rs with proper authorization
    
    // fetch_entropy_from_kirq is now defined in offchain.rs
}

// Helper module for no_std JSON handling
#[cfg(not(feature = "std"))]
mod serde_json {
    use sp_std::{vec::Vec, format};
    
    pub struct Value;
    
    impl Value {
        pub fn to_string(&self) -> String {
            // Simplified for no_std
            format!("{{}}")
        }
    }
    
    pub fn json(_: impl AsRef<str>) -> Value {
        Value
    }
}

#[cfg(not(feature = "std"))]
mod hex {
    use sp_std::vec::Vec;
    
    pub fn encode(data: &[u8]) -> String {
        // Simplified hex encoding for no_std
        data.iter()
            .map(|b| sp_std::format!("{:02x}", b))
            .collect()
    }
    
    pub fn decode(_: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(Vec::new())
    }
}