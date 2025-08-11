//! Types for Proof of Coherence consensus

use codec::{Encode, Decode};
use scale_info::TypeInfo;
use sp_core::H256;
use frame_support::pallet_prelude::*;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// Coherence proof structure
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(BlockNumber))]
pub struct CoherenceProof<BlockNumber> {
    pub frequency: u32,
    pub phase: u32,
    pub spectral_purity: u8,
    pub quantum_fidelity: u8,
    pub timestamp: BlockNumber,
    pub merkle_root: H256,
}

/// Harmonic state of the network
#[derive(Clone, Encode, Decode, TypeInfo, Default, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct HarmonicState {
    pub fundamental_frequency: u32,
    pub phase_offset: u32,
    pub coherence_level: u8,
    pub resonance_nodes: u8,
}