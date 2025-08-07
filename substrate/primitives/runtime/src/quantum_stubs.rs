// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! QUANTUM-SAFETY: Stub types for backward compatibility
//! These types exist only to maintain API compatibility while the system
//! transitions to quantum-safe cryptography. They should not be used.

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::crypto::{ByteArray, CryptoType, FromEntropy};
use core::convert::TryFrom;
use crate::traits::IdentifyAccount;
use crate::AccountId32;
use sp_core::H512;

/// Stub module for ed25519 - DO NOT USE
pub mod ed25519 {
    use super::*;
    
    /// Stub signature type - always invalid
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Signature([u8; 64]);
    
    impl Signature {
        /// Verify always returns false
        pub fn verify<M: AsRef<[u8]>>(&self, _msg: M, _pubkey: &Public) -> bool {
            log::warn!("QUANTUM-SAFETY: ed25519 signature verification attempted - returning false");
            false
        }
    }
    
    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    impl TryFrom<&[u8]> for Signature {
        type Error = ();
        
        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(data);
                Ok(Signature(arr))
            } else {
                Err(())
            }
        }
    }
    
    /// Stub public key type
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Public([u8; 32]);
    
    impl FromEntropy for Public {
        fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
            let mut arr = [0u8; 32];
            input.read(&mut arr)?;
            Ok(Public(arr))
        }
    }
    
    impl sp_core::crypto::UncheckedFrom<[u8; 32]> for Public {
        fn unchecked_from(x: [u8; 32]) -> Self {
            Public(x)
        }
    }
    
    impl From<[u8; 32]> for Public {
        fn from(data: [u8; 32]) -> Self {
            Public(data)
        }
    }
    
    impl AsRef<[u8]> for Public {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    impl From<Public> for [u8; 32] {
        fn from(p: Public) -> [u8; 32] {
            p.0
        }
    }
    
    impl Public {
        pub fn from_slice(data: &[u8]) -> Result<Self, ()> {
            if data.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(data);
                Ok(Public(arr))
            } else {
                Err(())
            }
        }
    }
    
    /// Stub pair type
    pub struct Pair;
    
    impl Pair {
        pub fn verify(sig: &Signature, msg: &[u8], pubkey: &Public) -> bool {
            sig.verify(msg, pubkey)
        }
    }
    
    impl IdentifyAccount for Public {
        type AccountId = AccountId32;
        fn into_account(self) -> AccountId32 {
            self.0.into()
        }
    }
    
    impl From<Signature> for H512 {
        fn from(sig: Signature) -> H512 {
            H512::from_slice(&sig.0)
        }
    }
}

/// Stub module for sr25519 - DO NOT USE
pub mod sr25519 {
    use super::*;
    
    /// Stub signature type - always invalid
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Signature([u8; 64]);
    
    impl Signature {
        /// Verify always returns false
        pub fn verify<M: AsRef<[u8]>>(&self, _msg: M, _pubkey: &Public) -> bool {
            log::warn!("QUANTUM-SAFETY: sr25519 signature verification attempted - returning false");
            false
        }
    }
    
    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    impl TryFrom<&[u8]> for Signature {
        type Error = ();
        
        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(data);
                Ok(Signature(arr))
            } else {
                Err(())
            }
        }
    }
    
    /// Stub public key type
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Public([u8; 32]);
    
    impl FromEntropy for Public {
        fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
            let mut arr = [0u8; 32];
            input.read(&mut arr)?;
            Ok(Public(arr))
        }
    }
    
    impl sp_core::crypto::UncheckedFrom<[u8; 32]> for Public {
        fn unchecked_from(x: [u8; 32]) -> Self {
            Public(x)
        }
    }
    
    impl From<[u8; 32]> for Public {
        fn from(data: [u8; 32]) -> Self {
            Public(data)
        }
    }
    
    impl TryFrom<&[u8]> for Public {
        type Error = ();
        
        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(data);
                Ok(Public(arr))
            } else {
                Err(())
            }
        }
    }
    
    impl AsRef<[u8]> for Public {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    impl From<Public> for [u8; 32] {
        fn from(p: Public) -> [u8; 32] {
            p.0
        }
    }
    
    /// Stub pair type
    pub struct Pair;
    
    impl Pair {
        pub fn verify(sig: &Signature, msg: &[u8], pubkey: &Public) -> bool {
            sig.verify(msg, pubkey)
        }
    }
    
    impl IdentifyAccount for Public {
        type AccountId = AccountId32;
        fn into_account(self) -> AccountId32 {
            self.0.into()
        }
    }
    
    impl From<Signature> for H512 {
        fn from(sig: Signature) -> H512 {
            H512::from_slice(&sig.0)
        }
    }
}

/// Stub module for ecdsa - DO NOT USE
pub mod ecdsa {
    use super::*;
    
    /// Stub signature type - always invalid
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Signature([u8; 65]);
    
    impl Signature {
        /// Verify always returns false
        pub fn verify<M: AsRef<[u8]>>(&self, _msg: M, _pubkey: &Public) -> bool {
            log::warn!("QUANTUM-SAFETY: ecdsa signature verification attempted - returning false");
            false
        }
    }
    
    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    impl TryFrom<&[u8]> for Signature {
        type Error = ();
        
        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() == 65 {
                let mut arr = [0u8; 65];
                arr.copy_from_slice(data);
                Ok(Signature(arr))
            } else {
                Err(())
            }
        }
    }
    
    /// Stub public key type
    #[derive(Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    pub struct Public(pub [u8; 33]);
    
    impl FromEntropy for Public {
        fn from_entropy(input: &mut impl codec::Input) -> Result<Self, codec::Error> {
            let mut arr = [0u8; 33];
            input.read(&mut arr)?;
            Ok(Public(arr))
        }
    }
    
    impl AsRef<[u8]> for Public {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    
    /// Stub pair type
    pub struct Pair;
    
    impl Pair {
        pub fn verify(sig: &Signature, msg: &[u8], pubkey: &Public) -> bool {
            sig.verify(msg, pubkey)
        }
    }
}