// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! QKD integration with KIRQ Hub and Toshiba QKD systems.

use crate::quantum_transport::{QkdClient, QuantumKey, QuantumKeySource};
use futures::future::BoxFuture;
use libp2p::PeerId;
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	io,
	sync::{Arc, Mutex},
	time::Duration,
};

/// KIRQ Hub client for quantum entropy and key distribution
pub struct KirqHubClient {
	endpoint: String,
	client: reqwest::Client,
	/// Mapping from PeerId to QKD endpoint
	peer_endpoints: Arc<Mutex<HashMap<PeerId, String>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KirqEntropyRequest {
	num_bytes: usize,
	sources: Vec<String>,
	proof_required: bool,
}

#[derive(Debug, Deserialize)]
struct KirqEntropyResponse {
	entropy: String,
	proof: Option<String>,
	sources_used: Vec<String>,
	timestamp: u64,
}

impl KirqHubClient {
	pub fn new(endpoint: String) -> Self {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(10))
			.build()
			.expect("Failed to create HTTP client");
			
		Self {
			endpoint,
			client,
			peer_endpoints: Arc::new(Mutex::new(HashMap::new())),
		}
	}
	
	/// Register QKD endpoint for a peer
	pub fn register_peer_endpoint(&self, peer_id: PeerId, endpoint: String) {
		self.peer_endpoints.lock().unwrap().insert(peer_id, endpoint);
	}
	
	/// Get quantum entropy from KIRQ Hub
	async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>, io::Error> {
		let request = KirqEntropyRequest {
			num_bytes,
			sources: vec!["qrng".to_string(), "quantum_vault".to_string()],
			proof_required: false,
		};
		
		let response = self.client
			.post(format!("{}/api/entropy/mixed", self.endpoint))
			.json(&request)
			.send()
			.await
			.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
			
		if !response.status().is_success() {
			return Err(io::Error::new(
				io::ErrorKind::Other,
				format!("KIRQ Hub returned status: {}", response.status()),
			));
		}
		
		let entropy_resp: KirqEntropyResponse = response.json().await
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
			
		// Decode base64 entropy
		base64::decode(&entropy_resp.entropy)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
	}
}

impl QkdClient for KirqHubClient {
	fn get_key_for_peer(&self, peer_id: &PeerId) -> BoxFuture<'static, Result<QuantumKey, io::Error>> {
		let peer_id = *peer_id;
		let endpoint = self.endpoint.clone();
		let client = self.client.clone();
		let peer_endpoints = self.peer_endpoints.clone();
		
		Box::pin(async move {
			// Check if we have a direct QKD link with this peer
			let qkd_endpoint = peer_endpoints.lock().unwrap().get(&peer_id).cloned();
			
			if let Some(qkd_ep) = qkd_endpoint {
				debug!("Using direct QKD link with peer: {}", peer_id);
				// In real implementation, would negotiate with Toshiba QKD system
				// For now, simulate with KIRQ entropy
			}
			
			// Fall back to KIRQ Hub entropy
			let kirq_client = KirqHubClient::new(endpoint);
			let key_material = kirq_client.get_entropy(32).await?;
			
			Ok(QuantumKey {
				key_id: peer_id.to_bytes().to_vec(),
				key_material,
				timestamp: std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
				source: QuantumKeySource::QRNG,
			})
		})
	}
	
	fn has_qkd_link(&self, peer_id: &PeerId) -> bool {
		self.peer_endpoints.lock().unwrap().contains_key(peer_id)
	}
}

/// Toshiba QKD client for direct quantum key distribution
#[derive(Clone)]
pub struct ToshibaQkdClient {
	api_endpoint: String,
	api_key: String,
	client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct ToshibaKeyResponse {
	key_id: String,
	key_material: String,
	timestamp: u64,
	error_rate: f64,
}

impl ToshibaQkdClient {
	pub fn new(api_endpoint: String, api_key: String) -> Self {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(30))
			.build()
			.expect("Failed to create HTTP client");
			
		Self {
			api_endpoint,
			api_key,
			client,
		}
	}
	
	/// Get quantum key from Toshiba QKD system
	pub async fn get_quantum_key(&self, slave_sae_id: &str) -> Result<QuantumKey, io::Error> {
		let response = self.client
			.get(format!("{}/api/v1/keys/{}", self.api_endpoint, slave_sae_id))
			.header("Authorization", format!("Bearer {}", self.api_key))
			.send()
			.await
			.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
			
		if !response.status().is_success() {
			return Err(io::Error::new(
				io::ErrorKind::Other,
				format!("Toshiba QKD API returned status: {}", response.status()),
			));
		}
		
		let key_resp: ToshibaKeyResponse = response.json().await
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
			
		// Check QBER (Quantum Bit Error Rate)
		if key_resp.error_rate > 0.11 {
			warn!("High QBER detected: {}", key_resp.error_rate);
		}
		
		let key_material = base64::decode(&key_resp.key_material)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
			
		Ok(QuantumKey {
			key_id: key_resp.key_id.into_bytes(),
			key_material,
			timestamp: key_resp.timestamp,
			source: QuantumKeySource::QKD(self.api_endpoint.clone()),
		})
	}
}

/// Combined QKD client supporting both KIRQ Hub and direct Toshiba QKD
pub struct HybridQkdClient {
	kirq_client: Arc<KirqHubClient>,
	toshiba_clients: Arc<Mutex<HashMap<PeerId, ToshibaQkdClient>>>,
}

impl HybridQkdClient {
	pub fn new(kirq_endpoint: String) -> Self {
		Self {
			kirq_client: Arc::new(KirqHubClient::new(kirq_endpoint)),
			toshiba_clients: Arc::new(Mutex::new(HashMap::new())),
		}
	}
	
	/// Register Toshiba QKD client for a specific peer
	pub fn register_toshiba_qkd(&self, peer_id: PeerId, endpoint: String, api_key: String) {
		let client = ToshibaQkdClient::new(endpoint, api_key);
		self.toshiba_clients.lock().unwrap().insert(peer_id, client);
	}
}

impl QkdClient for HybridQkdClient {
	fn get_key_for_peer(&self, peer_id: &PeerId) -> BoxFuture<'static, Result<QuantumKey, io::Error>> {
		let peer_id = *peer_id;
		let toshiba_clients = self.toshiba_clients.clone();
		let kirq_client = self.kirq_client.clone();
		
		Box::pin(async move {
			// First try direct Toshiba QKD if available
			let toshiba_result = {
				let clients = toshiba_clients.lock().unwrap();
				clients.get(&peer_id).cloned()
			};
			
			if let Some(toshiba) = toshiba_result {
				match toshiba.get_quantum_key(&peer_id.to_string()).await {
					Ok(key) => {
						debug!("Got quantum key from Toshiba QKD for peer: {}", peer_id);
						return Ok(key);
					}
					Err(e) => {
						warn!("Toshiba QKD failed for peer {}: {}", peer_id, e);
					}
				}
			}
			
			// Fall back to KIRQ Hub
			kirq_client.get_key_for_peer(&peer_id).await
		})
	}
	
	fn has_qkd_link(&self, peer_id: &PeerId) -> bool {
		self.toshiba_clients.lock().unwrap().contains_key(peer_id) ||
		self.kirq_client.has_qkd_link(peer_id)
	}
}

/// Create QKD client based on configuration
pub fn create_qkd_client(config: &QkdConfig) -> Option<Arc<dyn QkdClient>> {
	match config {
		QkdConfig::None => None,
		QkdConfig::KirqHub { endpoint } => {
			Some(Arc::new(KirqHubClient::new(endpoint.clone())))
		}
		QkdConfig::Hybrid { kirq_endpoint, .. } => {
			Some(Arc::new(HybridQkdClient::new(kirq_endpoint.clone())))
		}
	}
}

/// QKD configuration
#[derive(Clone, Debug)]
pub enum QkdConfig {
	/// No QKD integration
	None,
	/// Use KIRQ Hub for quantum entropy
	KirqHub {
		endpoint: String,
	},
	/// Hybrid mode with both KIRQ Hub and direct Toshiba QKD
	Hybrid {
		kirq_endpoint: String,
		toshiba_endpoints: HashMap<PeerId, (String, String)>, // (endpoint, api_key)
	},
}

impl Default for QkdConfig {
	fn default() -> Self {
		QkdConfig::None
	}
}

// Add base64 dependency
use base64;

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_qkd_config_default() {
		let config = QkdConfig::default();
		assert!(matches!(config, QkdConfig::None));
	}
}