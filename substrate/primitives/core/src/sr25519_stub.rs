//! Quantum-safe stub implementation of sr25519 (Schnorrkel)
//! 
//! This module provides a stub implementation that maintains API compatibility
//! while ensuring quantum safety by rejecting all operations.

use crate::crypto::{
    ByteArray, CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction,
    Pair as TraitPair, Public as TraitPublic, SecretStringError, Signature as TraitSignature,
    UncheckedFrom,
};
use alloc::{vec::Vec, string::String, format};
use codec::{Decode, Encode, MaxEncodedLen, DecodeWithMemTracking};
use scale_info::TypeInfo;
use sp_std::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};
#[cfg(feature = "std")]
use crate::crypto::Ss58Codec;

/// Sr25519 crypto type (quantum-vulnerable, stubbed for safety)
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sr25");

/// Sr25519 public key (stubbed)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Public(pub [u8; 32]);

impl Public {
    /// Create a quantum-safe warning public key
    pub fn quantum_warning() -> Self {
        // Special marker that indicates quantum-vulnerable crypto was attempted
        Self([0xFE; 32])
    }
    
    /// Create a dummy public key (for compatibility)
    pub fn dummy() -> Self {
        Self([0u8; 32])
    }
}

impl ByteArray for Public {
    const LEN: usize = 32;
}

impl TraitPublic for Public {}

impl CryptoType for Public {
    type Pair = Pair;
}

impl Derive for Public {
    fn derive<Iter: Iterator<Item = DeriveJunction>>(&self, _path: Iter) -> Option<Self> {
        log::warn!("Attempted to derive sr25519 key - returning None for quantum safety");
        None
    }
}

impl From<[u8; 32]> for Public {
    fn from(data: [u8; 32]) -> Self {
        log::warn!("Creating sr25519 public key - this is quantum-vulnerable!");
        Public(data)
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = ();
    
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 32 {
            return Err(());
        }
        let mut inner = [0u8; 32];
        inner.copy_from_slice(data);
        Ok(Public(inner))
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl sp_std::fmt::Debug for Public {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "sr25519::Public(QUANTUM_VULNERABLE)")
    }
}

impl UncheckedFrom<[u8; 32]> for Public {
    fn unchecked_from(data: [u8; 32]) -> Self {
        Public(data)
    }
}

impl From<Public> for [u8; 32] {
    fn from(p: Public) -> [u8; 32] {
        p.0
    }
}

#[cfg(feature = "std")]
impl sp_std::fmt::Display for Public {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "{}", self.to_ss58check())
    }
}

#[cfg(feature = "std")]
impl sp_std::str::FromStr for Public {
    type Err = crate::crypto::PublicError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ss58check(s)
    }
}

impl crate::crypto::FromEntropy for Public {
    fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
        let mut bytes = [0u8; 32];
        input.read(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// Sr25519 signature (stubbed)
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub struct Signature(pub [u8; 64]);

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let hex_str = hex_str.trim_start_matches("0x");
            array_bytes::hex2bytes(hex_str).map_err(|e| serde::de::Error::custom(format!("Hex decode error: {:?}", e)))?
        } else {
            Vec::<u8>::deserialize(deserializer)?
        };
        
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl Signature {
    /// Create a signature that always fails verification
    pub fn quantum_safe_failure() -> Self {
        // Special signature that always fails
        Self([0xBA; 64])  // Bad signature pattern
    }
}

impl ByteArray for Signature {
    const LEN: usize = 64;
}

impl TraitSignature for Signature {}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl From<[u8; 64]> for Signature {
    fn from(data: [u8; 64]) -> Self {
        Signature(data)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();
    
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 64 {
            return Err(());
        }
        let mut inner = [0u8; 64];
        inner.copy_from_slice(data);
        Ok(Signature(inner))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl sp_std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "sr25519::Signature(QUANTUM_VULNERABLE)")
    }
}

impl From<Signature> for [u8; 64] {
    fn from(s: Signature) -> [u8; 64] {
        s.0
    }
}

impl From<Signature> for crate::H512 {
    fn from(s: Signature) -> crate::H512 {
        s.0.into()
    }
}

/// Sr25519 key pair (stubbed)
#[derive(Clone)]
pub struct Pair {
    secret: [u8; 64],
    public: Public,
}

impl Pair {
    /// Create a dummy pair that cannot sign
    pub fn quantum_safe_dummy() -> Self {
        Self {
            secret: [0; 64],
            public: Public::quantum_warning(),
        }
    }
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = [u8; 32];
    type Signature = Signature;

    fn from_seed(_seed: &Self::Seed) -> Self {
        log::error!("Attempted to create sr25519 keypair - returning dummy for quantum safety");
        Self::quantum_safe_dummy()
    }

    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
        if seed.len() != 32 {
            return Err(SecretStringError::InvalidSeedLength);
        }
        Ok(Self::from_seed(seed.try_into().expect("32 bytes")))
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        _path: Iter,
        _seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), DeriveError> {
        log::error!("Attempted to derive sr25519 key - failing for quantum safety");
        Err(DeriveError::SoftKeyInPath)
    }

    fn public(&self) -> Self::Public {
        self.public.clone()
    }

    #[cfg(feature = "full_crypto")]
    fn sign(&self, _message: &[u8]) -> Self::Signature {
        log::error!("Attempted to sign with sr25519 - returning failure signature for quantum safety");
        Signature::quantum_safe_failure()
    }

    fn verify<M: AsRef<[u8]>>(_sig: &Self::Signature, _message: M, _pubkey: &Self::Public) -> bool {
        // Always return false for quantum safety
        log::warn!("sr25519 verification attempted - returning false");
        false
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    #[cfg(feature = "std")]
    fn generate_with_phrase(_password: Option<&str>) -> (Self, String, Self::Seed) {
        log::error!("Attempted to generate sr25519 keypair - failing for quantum safety");
        (Self::quantum_safe_dummy(), String::from("QUANTUM_VULNERABLE"), [0; 32])
    }

    fn from_phrase(_phrase: &str, _password: Option<&str>) -> Result<(Self, Self::Seed), SecretStringError> {
        log::error!("Attempted to restore sr25519 from phrase - failing for quantum safety");
        Err(SecretStringError::InvalidPhrase)
    }
}

impl CryptoType for Pair {
    type Pair = Pair;
}

// VRF functionality (stubbed out)
impl Pair {
    /// VRF sign - always fails for quantum safety
    pub fn vrf_sign(&self, _data: &[u8]) -> Option<VrfSignature> {
        log::error!("VRF signing not supported in quantum-safe mode");
        None
    }
}

/// VRF signature (stubbed)
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct VrfSignature {
    /// VRF output
    pub output: [u8; 32],
    /// VRF proof
    pub proof: [u8; 64],
}

// The types already have Decode derive, which automatically implements DecodeWithMemTracking

// Re-export for compatibility
pub use self::{Public as Sr25519Public, Signature as Sr25519Signature, Pair as Sr25519Pair};