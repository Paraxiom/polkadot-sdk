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

//! SPHINCS+ (post-quantum) cryptographic types and functionality.
//! 
//! This implementation avoids the recursive type issues with large signatures
//! by using Box allocation for the signature data.

use crate::{KeyTypeId, RuntimePublic, AppCrypto, AppPublic, AppSignature, AppPair};
use alloc::{vec::Vec, boxed::Box};
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{
    crypto::{ByteArray, CryptoType, CryptoTypeId, Public as PublicTrait, 
            Signature as SignatureTrait, Pair as PairTrait, UncheckedFrom, Wraps,
            IsWrappedBy, DeriveError, SecretStringError, DeriveJunction},
    sphincs,
};
use sp_std::convert::TryFrom;

/// SPHINCS+ public key wrapper for application crypto
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Public(pub sphincs::Public);

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<sphincs::Public> for Public {
    fn from(x: sphincs::Public) -> Self {
        Public(x)
    }
}

impl From<Public> for sphincs::Public {
    fn from(x: Public) -> Self {
        x.0
    }
}

impl AsRef<sphincs::Public> for Public {
    fn as_ref(&self) -> &sphincs::Public {
        &self.0
    }
}

impl AsMut<sphincs::Public> for Public {
    fn as_mut(&mut self) -> &mut sphincs::Public {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        sphincs::Public::try_from(data).map(Public)
    }
}

impl ByteArray for Public {
    const LEN: usize = sphincs::PUBLIC_KEY_SERIALIZED_SIZE;
}

impl PublicTrait for Public {}

impl CryptoType for Public {
    type Pair = Pair;
}

impl AppPublic for Public {
    type Generic = sphincs::Public;
}

impl Wraps for Public {
    type Inner = sphincs::Public;
}

impl RuntimePublic for Public {
    type Signature = Signature;

    fn all(key_type: KeyTypeId) -> Vec<Self> {
        sp_io::crypto::sphincs_public_keys(key_type)
            .into_iter()
            .map(Public)
            .collect()
    }

    fn generate_pair(key_type: KeyTypeId, seed: Option<Vec<u8>>) -> Self {
        Public(sp_io::crypto::sphincs_generate(key_type, seed))
    }

    fn sign<M: AsRef<[u8]>>(&self, key_type: KeyTypeId, msg: &M) -> Option<Self::Signature> {
        sp_io::crypto::sphincs_sign(key_type, &self.0, msg.as_ref())
            .map(Signature::from)
    }

    fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
        sp_io::crypto::sphincs_verify(&signature.0, msg.as_ref(), &self.0)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        ByteArray::to_raw_vec(&self.0)
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

/// SPHINCS+ signature wrapper that uses Box to avoid stack overflow
#[derive(Clone, Eq, PartialEq)]
pub struct Signature(Box<sphincs::Signature>);

impl Encode for Signature {
    fn encode(&self) -> Vec<u8> {
        self.0.as_ref().encode()
    }
}

impl Decode for Signature {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let sig_bytes = <[u8; sphincs::SIGNATURE_SERIALIZED_SIZE]>::decode(input)?;
        Ok(Signature(Box::new(sphincs::Signature::unchecked_from(sig_bytes))))
    }
}

impl TypeInfo for Signature {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("Signature", module_path!()))
            .composite(scale_info::build::Fields::unnamed()
                .field(|f| f.ty::<[u8; sphincs::SIGNATURE_SERIALIZED_SIZE]>()
                    .type_name("sphincs::Signature")))
    }
}

impl sp_std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "SphincsSignature({} bytes)", sphincs::SIGNATURE_SERIALIZED_SIZE)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        // This requires getting a mutable reference through the Box
        // We need to use a workaround since we can't directly get &mut [u8] from Box<Signature>
        // This is a limitation but shouldn't be needed in practice
        panic!("Cannot get mutable reference to signature data")
    }
}

impl From<sphincs::Signature> for Signature {
    fn from(x: sphincs::Signature) -> Self {
        Signature(Box::new(x))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        sphincs::Signature::try_from(data)
            .map(|s| Signature(Box::new(s)))
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = ();

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&data[..])
    }
}

impl ByteArray for Signature {
    const LEN: usize = sphincs::SIGNATURE_SERIALIZED_SIZE;
}

impl SignatureTrait for Signature {}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl AppSignature for Signature {
    type Generic = sphincs::Signature;
}

impl Wraps for Signature {
    type Inner = sphincs::Signature;
}

impl sp_core::RuntimeDebug for Signature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "SphincsSignature")
    }
}

/// SPHINCS+ key pair wrapper
#[cfg(feature = "full_crypto")]
#[derive(Clone)]
pub struct Pair(sphincs::Pair);

#[cfg(feature = "full_crypto")]
impl From<sphincs::Pair> for Pair {
    fn from(x: sphincs::Pair) -> Self {
        Pair(x)
    }
}

#[cfg(feature = "full_crypto")]
impl From<Pair> for sphincs::Pair {
    fn from(x: Pair) -> Self {
        x.0
    }
}

#[cfg(feature = "full_crypto")]
impl AsRef<sphincs::Pair> for Pair {
    fn as_ref(&self) -> &sphincs::Pair {
        &self.0
    }
}

#[cfg(feature = "full_crypto")]
impl PairTrait for Pair {
    type Public = Public;
    type Seed = sphincs::Seed;
    type Signature = Signature;

    fn from_seed(seed: &Self::Seed) -> Self {
        Pair(sphincs::Pair::from_seed(seed))
    }

    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
        sphincs::Pair::from_seed_slice(seed).map(Pair)
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), DeriveError> {
        self.0.derive(path, seed).map(|(p, s)| (Pair(p), s))
    }

    fn public(&self) -> Self::Public {
        Public(self.0.public())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        Signature::from(self.0.sign(message))
    }

    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, public: &Self::Public) -> bool {
        sphincs::Pair::verify(&*sig.0, message, &public.0)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.0.to_raw_vec()
    }

    #[cfg(feature = "std")]
    fn generate_with_phrase(password: Option<&str>) -> (Self, String, Self::Seed) {
        let (pair, phrase, seed) = sphincs::Pair::generate_with_phrase(password);
        (Pair(pair), phrase, seed)
    }

    fn from_phrase(phrase: &str, password: Option<&str>) -> Result<(Self, Self::Seed), SecretStringError> {
        sphincs::Pair::from_phrase(phrase, password).map(|(p, s)| (Pair(p), s))
    }
}

#[cfg(feature = "full_crypto")]
impl CryptoType for Pair {
    type Pair = Pair;
}

#[cfg(feature = "full_crypto")]
impl AppPair for Pair {
    type Generic = sphincs::Pair;
}

#[cfg(feature = "full_crypto")]
impl Wraps for Pair {
    type Inner = sphincs::Pair;
}

// Define the app crypto types
impl AppCrypto for Public {
    type Public = Public;
    type Pair = Pair;
    type Signature = Signature;
    const ID: KeyTypeId = sp_core::testing::SPHINCS;
    const CRYPTO_ID: CryptoTypeId = sphincs::CRYPTO_ID;
}

impl AppCrypto for Signature {
    type Public = Public;
    type Pair = Pair;
    type Signature = Signature;
    const ID: KeyTypeId = sp_core::testing::SPHINCS;
    const CRYPTO_ID: CryptoTypeId = sphincs::CRYPTO_ID;
}

#[cfg(feature = "full_crypto")]
impl AppCrypto for Pair {
    type Public = Public;
    type Pair = Pair;
    type Signature = Signature;
    const ID: KeyTypeId = sp_core::testing::SPHINCS;
    const CRYPTO_ID: CryptoTypeId = sphincs::CRYPTO_ID;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::crypto::Pair as TraitPair;

    #[test]
    #[cfg(feature = "full_crypto")]
    fn generate_account_id() {
        let seed = sphincs::Seed::from([0u8; 48]);
        let pair = Pair::from_seed(&seed);
        let public = pair.public();
        
        // Test signing and verification
        let message = b"test message";
        let signature = pair.sign(message);
        assert!(Pair::verify(&signature, message, &public));
    }
}