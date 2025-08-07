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

//! Quantum-enhanced transport layer with QKD integration.

use futures::future::BoxFuture;
use libp2p::{
	core::{
		multiaddr::{Multiaddr, Protocol},
		transport::{DialOpts, ListenerId, TransportError, TransportEvent},
		Transport,
	},
	PeerId,
};
// use log::debug; // Will be used when quantum key exchange is implemented
use std::{
	collections::{HashMap, VecDeque},
	io,
	pin::Pin,
	sync::{Arc, Mutex},
	task::{Context, Poll},
};

// Import real QKD client
use crate::real_qkd_client::RealQkdClient;

/// Quantum key material from QKD system
#[derive(Clone)]
pub struct QuantumKey {
	pub id: String,
	pub key: Vec<u8>,
	pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub enum QuantumKeySource {
	QKD(String),      // QKD endpoint
	QRNG,            // Quantum RNG
	PreShared,       // Pre-shared quantum key
}

/// QKD client interface
pub trait QkdClient: Send + Sync {
	/// Get quantum key for peer
	fn get_key_for_peer(&self, peer_id: &PeerId) -> BoxFuture<'static, Result<QuantumKey, io::Error>>;
	
	/// Check if QKD link is available with peer
	fn has_qkd_link(&self, peer_id: &PeerId) -> bool;
}

/// Mock QKD client for testing
pub struct MockQkdClient {
	keys: Arc<Mutex<HashMap<PeerId, VecDeque<QuantumKey>>>>,
}

impl MockQkdClient {
	pub fn new() -> Self {
		Self {
			keys: Arc::new(Mutex::new(HashMap::new())),
		}
	}
	
	pub fn add_key(&self, peer_id: PeerId, key: QuantumKey) {
		self.keys.lock().unwrap()
			.entry(peer_id)
			.or_insert_with(VecDeque::new)
			.push_back(key);
	}
}

impl QkdClient for MockQkdClient {
	fn get_key_for_peer(&self, peer_id: &PeerId) -> BoxFuture<'static, Result<QuantumKey, io::Error>> {
		let keys = self.keys.clone();
		let peer_id = *peer_id;
		
		Box::pin(async move {
			keys.lock().unwrap()
				.get_mut(&peer_id)
				.and_then(|queue| queue.pop_front())
				.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No quantum key available"))
				.map(|mut key| {
					// Update old key format to new format if needed
					if key.id.is_empty() {
						key.id = uuid::Uuid::new_v4().to_string();
					}
					key
				})
		})
	}
	
	fn has_qkd_link(&self, peer_id: &PeerId) -> bool {
		self.keys.lock().unwrap()
			.get(peer_id)
			.map(|queue| !queue.is_empty())
			.unwrap_or(false)
	}
}

/// Quantum-enhanced transport wrapper
pub struct QuantumTransport<T> {
	inner: T,
	qkd_client: Arc<dyn QkdClient>,
	quantum_keys: Arc<Mutex<HashMap<PeerId, QuantumKey>>>,
}

impl<T> QuantumTransport<T> {
	pub fn new(inner: T, qkd_client: Arc<dyn QkdClient>) -> Self {
		Self {
			inner,
			qkd_client,
			quantum_keys: Arc::new(Mutex::new(HashMap::new())),
		}
	}
	
	/// Get cached quantum key for peer
	pub fn get_quantum_key(&self, peer_id: &PeerId) -> Option<QuantumKey> {
		self.quantum_keys.lock().unwrap().get(peer_id).cloned()
	}
}

/// Create QKD client based on configuration
pub fn create_qkd_client(use_real_qkd: bool, is_alice: bool) -> Arc<dyn QkdClient> {
	if use_real_qkd {
		match RealQkdClient::new(is_alice) {
			Ok(client) => Arc::new(client),
			Err(e) => {
				log::warn!("Failed to create real QKD client: {}, falling back to mock", e);
				Arc::new(MockQkdClient::new())
			}
		}
	} else {
		Arc::new(MockQkdClient::new())
	}
}

impl<T> Transport for QuantumTransport<T>
where
	T: Transport + Send + Unpin + 'static,
	T::Error: Send + 'static,
	T::Dial: Send + 'static,
	T::ListenerUpgrade: Send + 'static,
	T::Output: Send + 'static,
{
	type Output = (T::Output, Option<QuantumKey>);
	type Error = T::Error;
	type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;
	type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

	fn listen_on(
		&mut self,
		id: ListenerId,
		addr: Multiaddr,
	) -> Result<(), TransportError<Self::Error>> {
		self.inner.listen_on(id, addr)
	}

	fn remove_listener(&mut self, id: ListenerId) -> bool {
		self.inner.remove_listener(id)
	}

	fn dial(&mut self, addr: Multiaddr, opts: libp2p::core::transport::DialOpts) -> Result<Self::Dial, TransportError<Self::Error>> {
		let dial = self.inner.dial(addr, opts)?;
		let qkd_client = self.qkd_client.clone();
		let quantum_keys = self.quantum_keys.clone();
		
		Ok(Box::pin(async move {
			let output = dial.await?;
			
			// Try to get quantum key if peer ID is known
			// In real implementation, we'd extract peer ID from the handshake
			let quantum_key = None; // Placeholder
			
			Ok((output, quantum_key))
		}))
	}

	// dial_as_listener removed in newer libp2p versions
	// Quantum key exchange happens during handshake instead

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
		let this = self.get_mut();
		match Pin::new(&mut this.inner).poll(cx) {
			Poll::Ready(event) => {
				let event = event.map_upgrade(|upgrade| {
					let _qkd_client = this.qkd_client.clone();
					Box::pin(async move {
						let output = upgrade.await?;
						let quantum_key = None; // Placeholder
						Ok((output, quantum_key))
					}) as Self::ListenerUpgrade
				});
				Poll::Ready(event)
			}
			Poll::Pending => Poll::Pending,
		}
	}

	// address_translation removed in newer libp2p versions
}

/// Check if address supports QKD
pub fn supports_qkd(addr: &Multiaddr) -> bool {
	addr.iter().any(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))
}

/// Enhanced BB84 protocol implementation
pub mod bb84 {
	use super::*;
	use rand::{thread_rng, Rng};
	
	pub struct BB84Protocol {
		pub key_size: usize,
		pub error_threshold: f64,
	}
	
	impl BB84Protocol {
		pub fn new(key_size: usize) -> Self {
			Self {
				key_size,
				error_threshold: 0.11, // Standard QBER threshold
			}
		}
		
		/// Simulate BB84 key generation (placeholder)
		pub fn generate_key(&self) -> QuantumKey {
			let mut rng = thread_rng();
			let key_material: Vec<u8> = (0..self.key_size)
				.map(|_| rng.gen())
				.collect();
			
			QuantumKey {
				id: uuid::Uuid::new_v4().to_string(),
				key: key_material,
				timestamp: std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use libp2p::core::transport::MemoryTransport;
	
	#[test]
	fn test_quantum_transport_creation() {
		let transport = MemoryTransport::default();
		let qkd_client = Arc::new(MockQkdClient::new());
		let _quantum_transport = QuantumTransport::new(transport, qkd_client);
	}
	
	#[test]
	fn test_bb84_key_generation() {
		let bb84 = bb84::BB84Protocol::new(32);
		let key = bb84.generate_key();
		assert_eq!(key.key.len(), 32);
	}
}