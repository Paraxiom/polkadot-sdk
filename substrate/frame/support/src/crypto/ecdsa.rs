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

//! QUANTUM-SAFETY: This module is deprecated - ECDSA is quantum-vulnerable
//! 
//! This module previously provided ECDSA secp256k1 support but has been
//! stubbed out for quantum safety. All functionality returns errors or false.

#![deprecated(since = "31.0.0", note = "ECDSA is quantum-vulnerable. Use quantum-safe alternatives.")]

use sp_runtime::quantum_stubs::ecdsa::Public;

/// Extension trait for [`Public`] - DEPRECATED: All methods return errors
#[deprecated(since = "31.0.0", note = "ECDSA is quantum-vulnerable")]
pub trait ECDSAExt {
	/// Verify a signature - ALWAYS RETURNS FALSE
	fn verify_from_utf8<V>(&self, msg: V, signature: &[u8; 65]) -> bool
	where
		V: AsRef<[u8]>;
}

impl ECDSAExt for Public {
	fn verify_from_utf8<V>(&self, _msg: V, _signature: &[u8; 65]) -> bool
	where
		V: AsRef<[u8]>,
	{
		log::warn!("QUANTUM-SAFETY: ECDSA verification attempted - returning false");
		false
	}
}