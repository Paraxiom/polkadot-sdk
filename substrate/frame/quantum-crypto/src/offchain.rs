use crate::{Config, Pallet};
use frame_support::traits::Get;
use sp_runtime::offchain::{http, Timestamp};
use sp_std::{vec::Vec, vec};

impl<T: Config> Pallet<T> {
    /// Fetch quantum entropy from KIRQ Hub service
    pub fn fetch_qkd_entropy() -> Result<Vec<u8>, &'static str> {
        let qkd_endpoint = T::QkdEndpoint::get();
        let endpoint_str = sp_std::str::from_utf8(&qkd_endpoint)
            .map_err(|_| "Invalid QKD endpoint")?;
        
        // Prepare KIRQ hub request body
        let request_body = r#"{
            "num_bytes": 32,
            "sources": ["quantum_vault", "crypto4a", "qrng"],
            "proof_required": false
        }"#;
        
        // Prepare the request
        let request = http::Request::post(endpoint_str, vec![request_body.as_bytes()])
            .add_header("Content-Type", "application/json")
            .deadline(Timestamp::from_unix_millis(
                sp_io::offchain::timestamp().unix_millis() + 3000
            ))
            .send()
            .map_err(|_| "Failed to send request")?;
        
        // Wait for response
        let response = request.wait()
            .map_err(|_| "Request timeout")?;
        
        if response.code != 200u16 {
            return Err("KIRQ service error");
        }
        
        // Parse response body - KIRQ returns JSON with entropy field
        let body = response.body().collect::<Vec<u8>>();
        let body_str = sp_std::str::from_utf8(&body)
            .map_err(|_| "Invalid response encoding")?;
        
        // Simple JSON parsing for entropy field
        // Response format: {"entropy": "hex_string", "sources_used": [...]}
        if let Some(start) = body_str.find("\"entropy\":\"") {
            let entropy_start = start + 11;
            if let Some(end) = body_str[entropy_start..].find("\"") {
                let hex_str = &body_str[entropy_start..entropy_start + end];
                // Convert hex to bytes
                let mut entropy = Vec::new();
                for i in (0..hex_str.len()).step_by(2) {
                    if let Ok(byte) = u8::from_str_radix(&hex_str[i..i+2], 16) {
                        entropy.push(byte);
                    }
                }
                if entropy.len() >= 32 {
                    return Ok(entropy[..32].to_vec());
                }
            }
        }
        
        Err("Failed to parse KIRQ entropy response")
    }
    
    /// Fetch QKD metrics from hardware
    pub fn fetch_qkd_metrics() -> Result<(u32, u32, u32), &'static str> {
        let qkd_endpoint = T::QkdEndpoint::get();
        let endpoint_str = sp_std::str::from_utf8(&qkd_endpoint)
            .map_err(|_| "Invalid QKD endpoint")?;
        
        // Construct metrics endpoint
        let metrics_url = [endpoint_str, "/metrics"].concat();
        
        let request = http::Request::get(&metrics_url)
            .deadline(Timestamp::from_unix_millis(
                sp_io::offchain::timestamp().unix_millis() + 3000
            ))
            .send()
            .map_err(|_| "Failed to send metrics request")?;
        
        let response = request.wait()
            .map_err(|_| "Metrics request timeout")?;
        
        if response.code != 200 {
            return Err("Metrics service error");
        }
        
        // In production, parse actual metrics
        // For now, return mock values
        Ok((250, 95, 1000)) // QBER: 2.5%, Visibility: 95%, Key rate: 1000/s
    }
}