//! Quantum-safe stub implementation of ECDSA
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

/// ECDSA crypto type (quantum-vulnerable, stubbed for safety)
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"ecds");

/// ECDSA public key (compressed, stubbed)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub struct Public(pub [u8; 33]);

#[cfg(feature = "serde")]
impl Serialize for Public {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Public {
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
        
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom("Invalid public key length"));
        }
        
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(Public(arr))
    }
}

impl Public {
    /// Create a quantum-safe warning public key
    pub fn quantum_warning() -> Self {
        // Special marker that indicates quantum-vulnerable crypto was attempted
        Self([0xFD; 33])
    }
    
    /// Create a dummy public key (for compatibility)
    pub fn dummy() -> Self {
        Self([0u8; 33])
    }
}

impl ByteArray for Public {
    const LEN: usize = 33;
}

impl TraitPublic for Public {}

impl CryptoType for Public {
    type Pair = Pair;
}

impl Derive for Public {
    fn derive<Iter: Iterator<Item = DeriveJunction>>(&self, _path: Iter) -> Option<Self> {
        log::warn!("Attempted to derive ECDSA key - returning None for quantum safety");
        None
    }
}

impl From<[u8; 33]> for Public {
    fn from(data: [u8; 33]) -> Self {
        log::warn!("Creating ECDSA public key - this is quantum-vulnerable!");
        Public(data)
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = ();
    
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 33 {
            return Err(());
        }
        let mut inner = [0u8; 33];
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
        write!(f, "ecdsa::Public(QUANTUM_VULNERABLE)")
    }
}

impl UncheckedFrom<[u8; 33]> for Public {
    fn unchecked_from(data: [u8; 33]) -> Self {
        Public(data)
    }
}

impl From<Public> for [u8; 33] {
    fn from(p: Public) -> [u8; 33] {
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
        let mut bytes = [0u8; 33];
        input.read(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// ECDSA signature (65 bytes with recovery ID, stubbed)
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
pub struct Signature(pub [u8; 65]);

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
        
        if bytes.len() != 65 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        
        let mut arr = [0u8; 65];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl Signature {
    /// Create a signature that always fails verification
    pub fn quantum_safe_failure() -> Self {
        // Special signature that always fails
        Self([0xCA; 65])  // Cafe signature pattern
    }
}

impl ByteArray for Signature {
    const LEN: usize = 65;
}

impl TraitSignature for Signature {}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl From<[u8; 65]> for Signature {
    fn from(data: [u8; 65]) -> Self {
        Signature(data)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();
    
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != 65 {
            return Err(());
        }
        let mut inner = [0u8; 65];
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
        write!(f, "ecdsa::Signature(QUANTUM_VULNERABLE)")
    }
}

/// ECDSA key pair (stubbed)
#[derive(Clone)]
pub struct Pair {
    secret: [u8; 32],
    public: Public,
}

impl Pair {
    /// Create a dummy pair that cannot sign
    pub fn quantum_safe_dummy() -> Self {
        Self {
            secret: [0; 32],
            public: Public::quantum_warning(),
        }
    }
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = [u8; 32];
    type Signature = Signature;

    fn from_seed(_seed: &Self::Seed) -> Self {
        log::error!("Attempted to create ECDSA keypair - returning dummy for quantum safety");
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
        log::error!("Attempted to derive ECDSA key - failing for quantum safety");
        Err(DeriveError::SoftKeyInPath)
    }

    fn public(&self) -> Self::Public {
        self.public.clone()
    }

    #[cfg(feature = "full_crypto")]
    fn sign(&self, _message: &[u8]) -> Self::Signature {
        log::error!("Attempted to sign with ECDSA - returning failure signature for quantum safety");
        Signature::quantum_safe_failure()
    }

    fn verify<M: AsRef<[u8]>>(_sig: &Self::Signature, _message: M, _pubkey: &Self::Public) -> bool {
        // Always return false for quantum safety
        log::warn!("ECDSA verification attempted - returning false");
        false
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    #[cfg(feature = "std")]
    fn generate_with_phrase(_password: Option<&str>) -> (Self, String, Self::Seed) {
        log::error!("Attempted to generate ECDSA keypair - failing for quantum safety");
        (Self::quantum_safe_dummy(), String::from("QUANTUM_VULNERABLE"), [0; 32])
    }

    fn from_phrase(_phrase: &str, _password: Option<&str>) -> Result<(Self, Self::Seed), SecretStringError> {
        log::error!("Attempted to restore ECDSA from phrase - failing for quantum safety");
        Err(SecretStringError::InvalidPhrase)
    }
}

impl CryptoType for Pair {
    type Pair = Pair;
}

// The types already have Decode derive, which automatically implements DecodeWithMemTracking

impl crate::crypto::FromEntropy for Signature {
    fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
        let mut bytes = [0u8; 65];
        input.read(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<Signature> for [u8; 65] {
    fn from(s: Signature) -> [u8; 65] {
        s.0
    }
}

// Re-export for compatibility
pub use self::{Public as EcdsaPublic, Signature as EcdsaSignature};
pub use self::Pair as EcdsaPair;