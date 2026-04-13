//! Types for Proof of Coherence consensus
//!
//! This module contains two sets of types:
//! 1. Original coherence proof types (frequency-based)
//! 2. Quantum coherence voting types (STARK proof-based finality)

use codec::{Encode, Decode};
#[cfg(not(feature = "std"))]
use codec::DecodeWithMemTracking;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_std::vec::Vec;
use frame_support::{
	pallet_prelude::*,
	BoundedVec,
};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants for BoundedVec sizes
// ============================================================================

/// Maximum size of vote signature (in bytes).
///
/// Phase 7 (2026-04-13): switched from Falcon-1024 (~1,280 bytes) to
/// SPHINCS+-SHAKE-256f-simple (49,856 bytes) so the on-chain Aura authority
/// keys can be reused for vote verification via `sp_io::crypto::sphincs_verify`.
/// Falcon had no on-chain pubkey registry and no WASM-compatible verify path.
pub const MAX_SIGNATURE_SIZE: u32 = 50_000;

/// Maximum number of votes in a finality certificate
/// Should accommodate largest expected validator set
pub const MAX_VOTES_PER_CERTIFICATE: u32 = 100;

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

// ============================================================================
// Quantum Coherence Finality Types (GRANDPA Equivalent)
// ============================================================================

/// A vote in the quantum coherence consensus protocol (GRANDPA equivalent)
///
/// This is the quantum equivalent of a GRANDPA vote. Each validator:
/// 1. Verifies STARK proofs from reporters
/// 2. Calculates coherence score based on QBER measurements
/// 3. Signs the vote with Falcon1024
/// 4. Broadcasts to other validators
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
#[scale_info(skip_type_params(AccountId, BlockNumber, Hash))]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct CoherenceVote<AccountId, BlockNumber, Hash> {
    /// The validator casting this vote
    pub validator: AccountId,

    /// Block being voted on
    pub block_hash: Hash,
    pub block_number: BlockNumber,

    /// Validator's calculated coherence score for this block
    ///
    /// Score = Σ(1000 / (1 + QBER_i)) for all valid proofs in this block
    ///
    /// Higher score = better quantum quality
    /// Minimum threshold: Set by governance (typically 5000 for 6+ reporters)
    pub coherence_score: u64,

    /// Validator's view of the quantum state at this block
    pub quantum_state: QuantumState,

    /// Falcon1024 signature over:
    /// hash(validator || block_hash || block_number || coherence_score || quantum_state)
    pub signature: BoundedVec<u8, ConstU32<MAX_SIGNATURE_SIZE>>,

    /// Vote type (Prevote or Precommit)
    pub vote_type: VoteType,
}

/// Type of vote in the two-round protocol (like GRANDPA)
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub enum VoteType {
    /// First round: "I have verified the STARK proofs"
    Prevote,

    /// Second round: "I commit to finalizing this block"
    Precommit,
}

/// Validator's view of quantum state at a specific block
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct QuantumState {
    /// Number of valid STARK proofs seen by this validator
    pub valid_proofs: u32,

    /// Number of proofs rejected (invalid STARK, high QBER, etc.)
    pub rejected_proofs: u32,

    /// Average QBER across all valid proofs (scaled by 10,000)
    pub average_qber: u32,

    /// Hash of the entropy pool after applying this block's quantum measurements
    pub entropy_pool_hash: H256,

    /// Number of unique reporters who submitted proofs
    pub reporter_count: u32,

    /// Minimum QBER seen across all proofs (scaled by 10,000)
    pub min_qber: u32,

    /// Maximum QBER seen across all proofs (scaled by 10,000)
    pub max_qber: u32,
}

/// Finality certificate issued when >2/3 validators agree (GRANDPA equivalent)
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
#[scale_info(skip_type_params(AccountId, BlockNumber, Hash))]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct FinalityCertificate<AccountId, BlockNumber, Hash> {
    /// Block being finalized
    pub block_hash: Hash,
    pub block_number: BlockNumber,

    /// All precommit votes from validators (must be >2/3 of total)
    pub precommit_votes: BoundedVec<CoherenceVote<AccountId, BlockNumber, Hash>, ConstU32<MAX_VOTES_PER_CERTIFICATE>>,

    /// Aggregated quantum state (consensus view)
    pub consensus_quantum_state: QuantumState,

    /// Total coherence score (sum of all validator scores)
    pub total_coherence_score: u64,

    /// Number of validators who signed (must be >2/3)
    pub validator_count: u32,

    /// Timestamp when certificate was created (Unix milliseconds)
    pub timestamp: u64,
}

/// Result of vote verification
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum VoteVerificationResult {
    /// Vote is valid
    Valid,

    /// Falcon1024 signature verification failed
    InvalidSignature,

    /// Validator is not in the validator set
    UnknownValidator,

    /// Vote is for a block that doesn't exist
    UnknownBlock,

    /// Coherence score doesn't match validator's quantum state
    InconsistentState,

    /// Vote type is wrong for current round
    WrongVoteType,

    /// Duplicate vote from same validator
    DuplicateVote,
}

/// Set of validators authorized to vote (GRANDPA VoterSet equivalent)
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[scale_info(skip_type_params(AccountId))]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct ValidatorSet<AccountId> {
    /// Validators and their Falcon1024 public keys
    pub validators: Vec<(AccountId, Vec<u8>)>,

    /// Set ID (incremented each time validator set changes)
    pub set_id: u64,

    /// Minimum number of validators required for supermajority
    ///
    /// supermajority_threshold = (validators.len() * 2) / 3 + 1
    pub supermajority_threshold: u32,
}

impl<AccountId> ValidatorSet<AccountId> {
    /// Check if we have >2/3 validators
    pub fn has_supermajority(&self, vote_count: u32) -> bool {
        vote_count >= self.supermajority_threshold
    }

    /// Get total number of validators
    pub fn total_validators(&self) -> u32 {
        self.validators.len() as u32
    }
}

// ============================================================================
// Note on DecodeWithMemTracking
// ============================================================================
//
// DecodeWithMemTracking is required for types used as extrinsic parameters in the
// runtime Call enum. Following Substrate's pattern (see per_things.rs), we derive
// it directly alongside Decode:
//
// #[derive(Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, ...)]
//
// This is the same approach used by Percent, Perbill, etc. Our quantum finality
// types (QuantumState, CoherenceVote, FinalityCertificate) all derive this trait.