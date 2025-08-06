// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitives for Aura.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Codec, Decode, Encode};
use sp_runtime::ConsensusEngineId;

pub mod digests;
pub mod inherents;

pub mod sphincs {
	mod app_sphincs {
		use sp_application_crypto::{app_crypto, key_types::AURA, sphincs};
		app_crypto!(sphincs, AURA);
	}

	sp_application_crypto::with_pair! {
		/// An Aura authority keypair using SPHINCS+ as its crypto.
		pub type AuthorityPair = app_sphincs::Pair;
	}

	/// An Aura authority signature using SPHINCS+ as its crypto.
	pub type AuthoritySignature = app_sphincs::Signature;

	/// An Aura authority identifier using SPHINCS+ as its crypto.
	pub type AuthorityId = app_sphincs::Public;
}

// Quantum-vulnerable ed25519 removed - use sphincs module instead

pub use sp_consensus_slots::{Slot, SlotDuration};

/// The `ConsensusEngineId` of AuRa.
pub const AURA_ENGINE_ID: ConsensusEngineId = [b'a', b'u', b'r', b'a'];

/// The index of an authority.
pub type AuthorityIndex = u32;

/// An consensus log item for Aura.
#[derive(Decode, Encode)]
pub enum ConsensusLog<AuthorityId: Codec> {
	/// The authorities have changed.
	#[codec(index = 1)]
	AuthoritiesChange(Vec<AuthorityId>),
	/// Disable the authority with given index.
	#[codec(index = 2)]
	OnDisabled(AuthorityIndex),
}

sp_api::decl_runtime_apis! {
	/// API necessary for block authorship with aura.
	pub trait AuraApi<AuthorityId: Codec> {
		/// Returns the slot duration for Aura.
		///
		/// Currently, only the value provided by this type at genesis will be used.
		fn slot_duration() -> SlotDuration;

		/// Return the current set of authorities.
		fn authorities() -> Vec<AuthorityId>;
	}
}
