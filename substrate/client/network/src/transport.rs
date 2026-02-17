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

//! Transport that serves as a common ground for all connections.

use either::Either;
use libp2p::{
	core::{
		muxing::StreamMuxerBox,
		transport::{Boxed, OptionalTransport},
		upgrade,
	},
	dns, identity, noise, tcp, websocket, PeerId, Transport, TransportExt,
};
use std::{sync::Arc, time::Duration};

use crate::quantum_transport::{QuantumTransport, QkdClient, MockQkdClient};
use log;

// TODO: Create a wrapper similar to upstream `BandwidthTransport` that tracks sent/received bytes
#[allow(deprecated)]
pub use libp2p::bandwidth::BandwidthSinks;

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
#[allow(deprecated)]
pub fn build_transport(
	keypair: identity::Keypair,
	memory_only: bool,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	// Build the base layer of the transport.
	let transport = if !memory_only {
		// Main transport: DNS(TCP)
		let tcp_config = tcp::Config::new().nodelay(true);
		let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
		let dns_init = dns::tokio::Transport::system(tcp_trans);

		Either::Left(if let Ok(dns) = dns_init {
			// WS + WSS transport
			//
			// Main transport can't be used for `/wss` addresses because WSS transport needs
			// unresolved addresses (BUT WSS transport itself needs an instance of DNS transport to
			// resolve and dial addresses).
			let tcp_trans = tcp::tokio::Transport::new(tcp_config);
			let dns_for_wss = dns::tokio::Transport::system(tcp_trans)
				.expect("same system_conf & resolver to work");
			Either::Left(websocket::WsConfig::new(dns_for_wss).or_transport(dns))
		} else {
			// In case DNS can't be constructed, fallback to TCP + WS (WSS won't work)
			let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(tcp_trans)
				.or_transport(tcp::tokio::Transport::new(tcp_config));
			Either::Right(desktop_trans)
		})
	} else {
		Either::Right(OptionalTransport::some(libp2p::core::transport::MemoryTransport::default()))
	};

	let authentication_config = noise::Config::new(&keypair).expect("Can create noise config. qed");
	let multiplexing_config = libp2p::yamux::Config::default();

	let transport = transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(authentication_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(20))
		.boxed();

	transport.with_bandwidth_logging()
}

/// Builds quantum-enhanced transport with QKD integration
#[allow(deprecated)]
pub fn build_quantum_transport(
	keypair: identity::Keypair,
	memory_only: bool,
	qkd_client: Option<Arc<dyn QkdClient>>,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	let (base_transport, bandwidth) = build_transport(keypair.clone(), memory_only);
	
	if let Some(qkd) = qkd_client {
		// Create quantum transport wrapper
		log::info!("Initializing quantum-enhanced transport layer");
		
		// The quantum transport wraps the base transport and adds quantum key exchange
		// For bandwidth tracking, we share the same bandwidth sinks
		let quantum_transport = QuantumTransport::new(base_transport, qkd);
		
		// Box the quantum transport to match the expected type
		// The quantum transport outputs ((PeerId, StreamMuxerBox), Option<QuantumKey>)
		// We need to map it back to just (PeerId, StreamMuxerBox)
		let boxed_transport: Boxed<(PeerId, StreamMuxerBox)> = quantum_transport
			.map(|((peer_id, muxer), quantum_key), _| {
				if quantum_key.is_some() {
					log::debug!("Quantum key established for peer {}", peer_id);
				}
				(peer_id, muxer)
			})
			.boxed();
		
		(boxed_transport, bandwidth)
	} else {
		// No QKD client provided, use standard transport
		log::info!("Using standard transport (no quantum enhancement)");
		(base_transport, bandwidth)
	}
}

/// Builds a fully post-quantum secure transport using Kyber-1024 + Falcon-1024
///
/// This replaces the Noise protocol's Ed25519 authentication with:
/// - **Kyber-1024**: NIST-standardized ML-KEM for key encapsulation
/// - **Falcon-1024**: NIST finalist for digital signatures
///
/// # Security Properties
/// - IND-CCA2 security from Kyber
/// - EUF-CMA security from Falcon
/// - Forward secrecy via ephemeral Kyber keys
/// - Full quantum resistance (no classical crypto in critical path)
#[cfg(feature = "pqc-transport")]
#[allow(deprecated)]
pub fn build_pqc_transport(
	pqc_identity: crate::pqc_authenticator::PqcIdentity,
	local_peer_id: PeerId,
	memory_only: bool,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	use crate::pqc_authenticator::PqcConfig;

	log::info!("🔐 Building post-quantum secure transport (Kyber-1024 + Falcon-1024)");
	log::info!("🔑 Node PeerId (Ed25519-compatible): {}", local_peer_id);
	log::info!("🔑 Falcon-1024 identity hash: {}", pqc_identity.peer_id());

	// Build the base layer of the transport (TCP/DNS/WS)
	let transport = if !memory_only {
		let tcp_config = tcp::Config::new().nodelay(true);
		let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
		let dns_init = dns::tokio::Transport::system(tcp_trans);

		Either::Left(if let Ok(dns) = dns_init {
			let tcp_trans = tcp::tokio::Transport::new(tcp_config);
			let dns_for_wss = dns::tokio::Transport::system(tcp_trans)
				.expect("same system_conf & resolver to work");
			Either::Left(websocket::WsConfig::new(dns_for_wss).or_transport(dns))
		} else {
			let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(tcp_trans)
				.or_transport(tcp::tokio::Transport::new(tcp_config));
			Either::Right(desktop_trans)
		})
	} else {
		Either::Right(OptionalTransport::some(libp2p::core::transport::MemoryTransport::default()))
	};

	// Use PQC authenticator instead of Noise.
	// Pass the Ed25519-derived PeerId so the handshake returns PeerIds that
	// are compatible with the Swarm, DHT, and bootnode configs.
	let pqc_config = PqcConfig::new(pqc_identity.clone(), local_peer_id);
	let multiplexing_config = libp2p::yamux::Config::default();

	let transport = transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(pqc_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(30)) // Longer timeout for PQC handshake
		.boxed();

	log::info!(
		"✅ PQC transport initialized — Falcon-1024 auth, Kyber-1024 KEM, Ed25519-compatible PeerId: {}",
		local_peer_id
	);

	transport.with_bandwidth_logging()
}
