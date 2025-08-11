//! Quantum-safe stub for GRANDPA - not used in quantum-only chains

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Codec, Decode, Encode};
use sp_runtime::ConsensusEngineId;

pub const GRANDPA_ENGINE_ID: ConsensusEngineId = *b"FRNK";

// Stub types to maintain API compatibility
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AuthorityId;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AuthoritySignature;

// Stub functions that panic if called
pub fn verify_finality_proof<Header>(_: u32, _: Vec<u8>, _: u64) -> Result<(), ()> 
where Header: codec::Encode + codec::Decode 
{
    panic!("GRANDPA not supported in quantum-only mode")
}

#[cfg(feature = "std")]
pub fn sign_message<H, N>(_: sp_keystore::KeystorePtr, _: H, _: N, _: u64, _: u64) -> Option<()>
where H: Encode, N: Encode
{
    panic!("GRANDPA not supported in quantum-only mode")
}