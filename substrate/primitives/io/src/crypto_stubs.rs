//! Quantum-safe stub implementations for crypto host functions

use crate::{PassPointerAndReadCopy, PassPointerAndRead, AllocateAndReturnByCodec, PassByCodec, PassBy};
use sp_core::{crypto::KeyTypeId, ed25519, sr25519, ecdsa};
use alloc::vec::Vec;

/// Ed25519 stub implementations
impl crate::SubstrateHostFunctions {
    /// Generate stub - always returns quantum warning key
    pub fn ed25519_generate_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _seed: AllocateAndReturnByCodec<Option<Vec<u8>>>,
    ) -> PassByCodec<ed25519::Public> {
        log::warn!("ed25519_generate called - returning quantum warning key");
        ed25519::Public::quantum_warning()
    }

    /// Sign stub - always returns failure signature
    pub fn ed25519_sign_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _pub_key: PassPointerAndRead<&ed25519::Public, 32>,
        _msg: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnByCodec<Option<ed25519::Signature>> {
        log::warn!("ed25519_sign called - returning None for quantum safety");
        None
    }

    /// Verify stub - always returns false
    pub fn ed25519_verify_stub(
        &self,
        _sig: PassPointerAndRead<&ed25519::Signature, 64>,
        _msg: PassFatPointerAndRead<&[u8]>,
        _pub_key: PassPointerAndRead<&ed25519::Public, 32>,
    ) -> bool {
        log::warn!("ed25519_verify called - returning false for quantum safety");
        false
    }
}

/// Sr25519 stub implementations
impl crate::SubstrateHostFunctions {
    /// Public keys stub - returns empty list
    pub fn sr25519_public_keys_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
    ) -> AllocateAndReturnByCodec<Vec<sr25519::Public>> {
        log::warn!("sr25519_public_keys called - returning empty list for quantum safety");
        Vec::new()
    }

    /// Generate stub - returns quantum warning key
    pub fn sr25519_generate_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _seed: AllocateAndReturnByCodec<Option<Vec<u8>>>,
    ) -> PassByCodec<sr25519::Public> {
        log::warn!("sr25519_generate called - returning quantum warning key");
        sr25519::Public::quantum_warning()
    }

    /// Sign stub - returns None
    pub fn sr25519_sign_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _pub_key: PassPointerAndRead<&sr25519::Public, 32>,
        _msg: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnByCodec<Option<sr25519::Signature>> {
        log::warn!("sr25519_sign called - returning None for quantum safety");
        None
    }

    /// Verify stub - always returns false
    pub fn sr25519_verify_stub(
        &self,
        _sig: PassPointerAndRead<&sr25519::Signature, 64>,
        _msg: PassFatPointerAndRead<&[u8]>,
        _pub_key: PassPointerAndRead<&sr25519::Public, 32>,
    ) -> bool {
        log::warn!("sr25519_verify called - returning false for quantum safety");
        false
    }
}

/// ECDSA stub implementations
impl crate::SubstrateHostFunctions {
    /// Public keys stub - returns empty list
    pub fn ecdsa_public_keys_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
    ) -> AllocateAndReturnByCodec<Vec<ecdsa::Public>> {
        log::warn!("ecdsa_public_keys called - returning empty list for quantum safety");
        Vec::new()
    }

    /// Generate stub - returns quantum warning key
    pub fn ecdsa_generate_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _seed: AllocateAndReturnByCodec<Option<Vec<u8>>>,
    ) -> PassByCodec<ecdsa::Public> {
        log::warn!("ecdsa_generate called - returning quantum warning key");
        ecdsa::Public::quantum_warning()
    }

    /// Sign stub - returns None
    pub fn ecdsa_sign_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
        _msg: PassFatPointerAndRead<&[u8]>,
    ) -> AllocateAndReturnByCodec<Option<ecdsa::Signature>> {
        log::warn!("ecdsa_sign called - returning None for quantum safety");
        None
    }

    /// Sign prehashed stub - returns None
    pub fn ecdsa_sign_prehashed_stub(
        &mut self,
        _id: PassPointerAndReadCopy<KeyTypeId, 4>,
        _pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
        _msg: PassPointerAndRead<&[u8; 32], 32>,
    ) -> AllocateAndReturnByCodec<Option<ecdsa::Signature>> {
        log::warn!("ecdsa_sign_prehashed called - returning None for quantum safety");
        None
    }

    /// Verify stub - always returns false
    pub fn ecdsa_verify_stub(
        &self,
        _sig: PassPointerAndRead<&ecdsa::Signature, 65>,
        _msg: PassFatPointerAndRead<&[u8]>,
        _pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
    ) -> bool {
        log::warn!("ecdsa_verify called - returning false for quantum safety");
        false
    }

    /// Verify prehashed stub - always returns false
    pub fn ecdsa_verify_prehashed_stub(
        &self,
        _sig: PassPointerAndRead<&ecdsa::Signature, 65>,
        _msg: PassPointerAndRead<&[u8; 32], 32>,
        _pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
    ) -> bool {
        log::warn!("ecdsa_verify_prehashed called - returning false for quantum safety");
        false
    }

    /// Recover compressed stub - returns None
    pub fn secp256k1_ecdsa_recover_compressed_stub(
        &self,
        _sig: PassPointerAndRead<&[u8; 65], 65>,
        _msg: PassPointerAndRead<&[u8; 32], 32>,
    ) -> AllocateAndReturnByCodec<Result<[u8; 33], EcdsaVerifyError>> {
        log::warn!("secp256k1_ecdsa_recover_compressed called - returning error for quantum safety");
        Err(EcdsaVerifyError::BadSignature)
    }
}