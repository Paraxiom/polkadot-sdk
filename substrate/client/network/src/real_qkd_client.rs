//! Real QKD client implementation using Toshiba QKD hardware

use crate::quantum_transport::{QkdClient, QuantumKey};
use futures::future::BoxFuture;
use libp2p::PeerId;
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    path::Path,
};
use reqwest::{Client, Certificate, Identity};
use serde::{Deserialize, Serialize};

/// Toshiba QKD key response
#[derive(Debug, Deserialize)]
struct ToshibaKeyResponse {
    keys: Vec<ToshibaKey>,
}

#[derive(Debug, Deserialize)]
struct ToshibaKey {
    key_id: String,
    key: String, // Base64 encoded
}

/// Real QKD client implementation using Toshiba ETSI 014 API
pub struct RealQkdClient {
    client: Client,
    alice_endpoint: String,
    bob_endpoint: String,
    is_alice: bool,
    // Cache for keys
    key_cache: Arc<Mutex<HashMap<PeerId, VecDeque<QuantumKey>>>>,
}

impl RealQkdClient {
    /// Create a new real QKD client
    pub fn new(is_alice: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Configuration - in production these would come from config file
        let alice_ip = std::env::var("TOSHIBA_ALICE_IP")
            .unwrap_or_else(|_| "192.168.0.152".to_string());
        let bob_ip = std::env::var("TOSHIBA_BOB_IP")
            .unwrap_or_else(|_| "192.168.0.153".to_string());
        let cert_path = std::env::var("TOSHIBA_CERT_PATH")
            .unwrap_or_else(|_| "/home/paraxiom/qkd_client/certificate/Toshiba/new_certs".to_string());
        
        // Build paths to certificates
        let ca_cert_path = Path::new(&cert_path).join("ca_crt.pem");
        let client_cert_path = if is_alice {
            Path::new(&cert_path).join("client_alice_crt.pem")
        } else {
            Path::new(&cert_path).join("client_bob_crt.pem")
        };
        let client_key_path = if is_alice {
            Path::new(&cert_path).join("client_alice_key.pem")
        } else {
            Path::new(&cert_path).join("client_bob_key.pem")
        };
        
        // Load certificates
        let ca_cert = std::fs::read(&ca_cert_path)?;
        let client_cert = std::fs::read(&client_cert_path)?;
        let client_key = std::fs::read(&client_key_path)?;
        
        // Create HTTPS client with mutual TLS
        let identity = Identity::from_pem(&[&client_cert[..], &client_key[..]].concat())?;
        let ca = Certificate::from_pem(&ca_cert)?;
        
        let client = Client::builder()
            .use_rustls_tls()
            .identity(identity)
            .add_root_certificate(ca)
            .danger_accept_invalid_certs(false)
            .build()?;
        
        Ok(Self {
            client,
            alice_endpoint: format!("https://{}:443/api/v1/keys", alice_ip),
            bob_endpoint: format!("https://{}:443/api/v1/keys", bob_ip),
            is_alice,
            key_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    /// Fetch a key from the QKD system
    async fn fetch_key(&self, slave_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = if self.is_alice {
            &self.alice_endpoint
        } else {
            &self.bob_endpoint
        };
        
        // Request key from QKD system
        let response = self.client
            .get(endpoint)
            .query(&[
                ("slave_SAE_ID", slave_id),
                ("size", "256"), // 256 bits
                ("number", "1"),
            ])
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("QKD request failed: {}", response.status()).into());
        }
        
        let key_response: ToshibaKeyResponse = response.json().await?;
        
        if let Some(key_data) = key_response.keys.first() {
            // Decode base64 key
            use base64::{Engine as _, engine::general_purpose};
            let key_bytes = general_purpose::STANDARD.decode(&key_data.key)?;
            Ok(key_bytes)
        } else {
            Err("No key received from QKD system".into())
        }
    }
    
    /// Convert PeerId to slave ID for QKD system
    fn peer_to_slave_id(peer_id: &PeerId) -> String {
        // In production, this would map to registered QKD endpoints
        format!("substrate_peer_{}", hex::encode(&peer_id.to_bytes()[..8]))
    }
}

impl QkdClient for RealQkdClient {
    fn get_key_for_peer(&self, peer_id: &PeerId) -> BoxFuture<'static, Result<QuantumKey, io::Error>> {
        let slave_id = Self::peer_to_slave_id(peer_id);
        let self_clone = self.clone();
        let peer_id = *peer_id;
        
        Box::pin(async move {
            // First check cache
            {
                let mut cache = self_clone.key_cache.lock().unwrap();
                if let Some(queue) = cache.get_mut(&peer_id) {
                    if let Some(key) = queue.pop_front() {
                        return Ok(key);
                    }
                }
            }
            
            // Fetch new key from QKD system
            match self_clone.fetch_key(&slave_id).await {
                Ok(key_bytes) => {
                    let quantum_key = QuantumKey {
                        id: uuid::Uuid::new_v4().to_string(),
                        key: key_bytes,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    Ok(quantum_key)
                }
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("QKD key fetch failed: {}", e)
                ))
            }
        })
    }
    
    fn has_qkd_link(&self, _peer_id: &PeerId) -> bool {
        // In production, check if peer is registered in QKD network
        // For now, assume QKD available for all peers
        true
    }
}

impl Clone for RealQkdClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            alice_endpoint: self.alice_endpoint.clone(),
            bob_endpoint: self.bob_endpoint.clone(),
            is_alice: self.is_alice,
            key_cache: self.key_cache.clone(),
        }
    }
}