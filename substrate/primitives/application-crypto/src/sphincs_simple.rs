//! Simplified SPHINCS+ implementation for quantum-safe blockchain
//! Bypasses app_crypto! macro issues with large signatures

use crate::RuntimePublic;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::{crypto::{KeyTypeId, ByteArray}, sphincs};
use core::convert::TryFrom;

/// SPHINCS+ public key for application crypto
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, TypeInfo, Debug)]
pub struct Public(pub sphincs::Public);

impl RuntimePublic for Public {
    type Signature = Signature;

    fn all(key_type: KeyTypeId) -> Vec<Self> {
        sp_io::crypto::sphincs_public_keys(key_type)
            .into_iter()
            .map(|k| Self(k))
            .collect()
    }

    fn generate_pair(key_type: KeyTypeId, seed: Option<Vec<u8>>) -> Self {
        let k = sp_io::crypto::sphincs_generate(key_type, seed);
        Self(k)
    }

    fn sign<M: AsRef<[u8]>>(&self, key_type: KeyTypeId, msg: &M) -> Option<Self::Signature> {
        sp_io::crypto::sphincs_sign(key_type, &self.0, msg.as_ref())
            .map(|s| Signature(s))
    }

    fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
        sp_io::crypto::sphincs_verify(signature.0.to_raw_vec(), msg.as_ref(), &self.0)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.0.to_raw_vec()
    }

    fn generate_proof_of_possession(&mut self, _key_type: KeyTypeId) -> Option<Self::Signature> {
        // SPHINCS+ doesn't have a specific PoP mechanism
        None
    }

    fn verify_proof_of_possession(&self, _pop: &Self::Signature) -> bool {
        // SPHINCS+ doesn't have a specific PoP mechanism
        false
    }
}

/// SPHINCS+ signature for application crypto
#[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo, Debug)]
pub struct Signature(pub sphincs::Signature);

impl TryFrom<Vec<u8>> for Signature {
    type Error = ();

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        sphincs::Signature::try_from(data.as_slice())
            .map(|s| Self(s))
            .map_err(|_| ())
    }
}

/// SPHINCS+ key pair (not used in runtime, only for testing)
#[cfg(feature = "full_crypto")]
pub struct Pair(sphincs::Pair);

#[cfg(feature = "full_crypto")]
impl From<sphincs::Pair> for Pair {
    fn from(x: sphincs::Pair) -> Self {
        Pair(x)
    }
}
