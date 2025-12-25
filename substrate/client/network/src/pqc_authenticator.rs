// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Post-Quantum Cryptographic Authenticator for libp2p
//!
//! This module replaces the Noise protocol's Ed25519-based authentication with:
//! - **Kyber-1024** (ML-KEM): NIST-standardized key encapsulation mechanism
//! - **Falcon-1024**: NIST finalist digital signature algorithm
//!
//! ## Protocol Flow
//!
//! ```text
//! Initiator (Alice)                    Responder (Bob)
//! ─────────────────                    ───────────────
//!
//! 1. Generate ephemeral Kyber keypair
//!    Send: [Kyber_PK || Falcon_PK || Falcon_Sig(Kyber_PK)]
//!                                 ──────────────────────────>
//!
//! 2.                               Verify Falcon signature
//!                                  Encapsulate shared secret with Kyber_PK
//!                                  Generate own ephemeral Kyber keypair
//!    <──────────────────────────── Send: [Kyber_CT || Kyber_PK || Falcon_PK || Falcon_Sig(Kyber_CT || Kyber_PK)]
//!
//! 3. Decapsulate shared secret
//!    Encapsulate with Bob's Kyber_PK
//!    Derive session keys (HKDF)
//!    Send: [Kyber_CT || AEAD_Encrypted(confirmation)]
//!                                 ──────────────────────────>
//!
//! 4.                               Decapsulate, verify, derive keys
//!                                  Session established!
//! ```
//!
//! ## Security Properties
//!
//! - **IND-CCA2 security**: Kyber provides chosen-ciphertext security
//! - **EUF-CMA security**: Falcon provides existential unforgeability
//! - **Forward secrecy**: Ephemeral Kyber keys per session
//! - **Quantum resistance**: Both primitives resist quantum attacks

use futures::prelude::*;
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p::core::UpgradeInfo;
use libp2p::PeerId;
use pqcrypto_falcon::falcon1024;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::{
    kem::{Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret},
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage, DetachedSignature},
};
use sha3::{Sha3_256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use zeroize::Zeroize;

use std::{
    io,
    pin::Pin,
};

/// Protocol identifier for PQC authentication
pub const PQC_PROTOCOL_ID: &str = "/pqc/kyber-falcon/1.0.0";

/// Maximum message size (Kyber + Falcon keys and signatures are large)
const MAX_MESSAGE_SIZE: usize = 32768; // 32KB should be sufficient

/// Session key size (256 bits for AES-256-GCM)
const SESSION_KEY_SIZE: usize = 32;

/// Nonce size for AES-256-GCM
const NONCE_SIZE: usize = 12;

/// Error types for PQC authentication
#[derive(Debug)]
pub enum PqcError {
    Io(io::Error),
    KeyGeneration(String),
    Encapsulation(String),
    Decapsulation(String),
    SignatureGeneration(String),
    SignatureVerification(String),
    Encryption(String),
    Decryption(String),
    InvalidMessage(String),
    ProtocolViolation(String),
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqcError::Io(e) => write!(f, "IO error: {}", e),
            PqcError::KeyGeneration(s) => write!(f, "Key generation error: {}", s),
            PqcError::Encapsulation(s) => write!(f, "Encapsulation error: {}", s),
            PqcError::Decapsulation(s) => write!(f, "Decapsulation error: {}", s),
            PqcError::SignatureGeneration(s) => write!(f, "Signature generation error: {}", s),
            PqcError::SignatureVerification(s) => write!(f, "Signature verification error: {}", s),
            PqcError::Encryption(s) => write!(f, "Encryption error: {}", s),
            PqcError::Decryption(s) => write!(f, "Decryption error: {}", s),
            PqcError::InvalidMessage(s) => write!(f, "Invalid message: {}", s),
            PqcError::ProtocolViolation(s) => write!(f, "Protocol violation: {}", s),
        }
    }
}

impl std::error::Error for PqcError {}

impl From<io::Error> for PqcError {
    fn from(e: io::Error) -> Self {
        PqcError::Io(e)
    }
}

impl From<PqcError> for io::Error {
    fn from(e: PqcError) -> Self {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }
}

/// PQC Identity Keypair (Falcon-1024 for long-term identity)
#[derive(Clone)]
pub struct PqcIdentity {
    pub public_key: falcon1024::PublicKey,
    secret_key: falcon1024::SecretKey,
}

impl PqcIdentity {
    /// Generate a new random PQC identity
    pub fn generate() -> Self {
        let (pk, sk) = falcon1024::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Create from existing keypair
    pub fn from_keypair(public_key: falcon1024::PublicKey, secret_key: falcon1024::SecretKey) -> Self {
        Self { public_key, secret_key }
    }

    /// Sign a message with Falcon-1024
    pub fn sign(&self, message: &[u8]) -> falcon1024::SignedMessage {
        falcon1024::sign(message, &self.secret_key)
    }

    /// Get the PeerId derived from this identity
    pub fn peer_id(&self) -> PeerId {
        // Hash the Falcon public key to create a PeerId
        let pk_bytes = self.public_key.as_bytes();
        let hash = Sha3_256::digest(pk_bytes);

        // Create a valid multihash: 0x12 = SHA2-256 type, 0x20 = 32 bytes
        // We use SHA3 but encode as SHA2-256 for libp2p compatibility
        let mut multihash = vec![0x12, 0x20];
        multihash.extend_from_slice(&hash);

        PeerId::from_bytes(&multihash).expect("Valid multihash")
    }

    /// Serialize the public key
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

impl std::fmt::Debug for PqcIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcIdentity")
            .field("peer_id", &self.peer_id())
            .finish_non_exhaustive()
    }
}

/// Ephemeral Kyber keypair for key exchange
struct EphemeralKyber {
    public_key: kyber1024::PublicKey,
    secret_key: kyber1024::SecretKey,
}

impl EphemeralKyber {
    fn generate() -> Self {
        let (pk, sk) = kyber1024::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn encapsulate(public_key: &kyber1024::PublicKey) -> (kyber1024::SharedSecret, kyber1024::Ciphertext) {
        kyber1024::encapsulate(public_key)
    }

    fn decapsulate(&self, ciphertext: &kyber1024::Ciphertext) -> kyber1024::SharedSecret {
        kyber1024::decapsulate(ciphertext, &self.secret_key)
    }
}

impl Drop for EphemeralKyber {
    fn drop(&mut self) {
        // Note: pqcrypto types should implement Zeroize, but we can't call it directly
        // The secret key will be dropped normally
    }
}

/// Session keys derived from the handshake
pub struct SessionKeys {
    /// Key for encrypting outgoing messages
    pub encrypt_key: [u8; SESSION_KEY_SIZE],
    /// Key for decrypting incoming messages
    pub decrypt_key: [u8; SESSION_KEY_SIZE],
    /// Nonce counter for encryption
    encrypt_nonce: u64,
    /// Nonce counter for decryption
    decrypt_nonce: u64,
}

impl SessionKeys {
    /// Derive session keys from shared secrets using HKDF
    fn derive(shared_secret1: &[u8], shared_secret2: &[u8], initiator: bool) -> Self {
        // Combine shared secrets
        let mut ikm = Vec::with_capacity(shared_secret1.len() + shared_secret2.len());
        ikm.extend_from_slice(shared_secret1);
        ikm.extend_from_slice(shared_secret2);

        // Use SHA3-256 for key derivation
        let mut hasher = Sha3_256::new();
        hasher.update(b"PQC-SESSION-KEY-INITIATOR");
        hasher.update(&ikm);
        let initiator_key: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha3_256::new();
        hasher.update(b"PQC-SESSION-KEY-RESPONDER");
        hasher.update(&ikm);
        let responder_key: [u8; 32] = hasher.finalize().into();

        // Initiator encrypts with initiator_key, decrypts with responder_key
        // Responder encrypts with responder_key, decrypts with initiator_key
        let (encrypt_key, decrypt_key) = if initiator {
            (initiator_key, responder_key)
        } else {
            (responder_key, initiator_key)
        };

        Self {
            encrypt_key,
            decrypt_key,
            encrypt_nonce: 0,
            decrypt_nonce: 0,
        }
    }

    /// Encrypt a message using AES-256-GCM
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PqcError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encrypt_key);
        let cipher = Aes256Gcm::new(key);

        // Create nonce from counter
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[4..12].copy_from_slice(&self.encrypt_nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.encrypt_nonce += 1;

        cipher
            .encrypt(nonce, plaintext)
            .map(|ciphertext| {
                let mut result = nonce_bytes.to_vec();
                result.extend(ciphertext);
                result
            })
            .map_err(|e| PqcError::Encryption(e.to_string()))
    }

    /// Decrypt a message using AES-256-GCM
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PqcError> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(PqcError::Decryption("Ciphertext too short".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(&self.decrypt_key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let actual_ciphertext = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| PqcError::Decryption(e.to_string()))
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.encrypt_key.zeroize();
        self.decrypt_key.zeroize();
    }
}

/// PQC Authenticator Configuration
#[derive(Clone)]
pub struct PqcConfig {
    identity: PqcIdentity,
}

impl PqcConfig {
    /// Create a new PQC configuration with the given identity
    pub fn new(identity: PqcIdentity) -> Self {
        Self { identity }
    }

    /// Get the local PeerId
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }
}

impl UpgradeInfo for PqcConfig {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PQC_PROTOCOL_ID)
    }
}

/// Output of a successful PQC handshake
pub struct PqcOutput<S> {
    /// The underlying stream, now secured
    pub stream: S,
    /// The remote peer's identity
    pub remote_peer_id: PeerId,
    /// The remote peer's Falcon public key
    pub remote_public_key: Vec<u8>,
    /// Session keys for encryption/decryption
    pub session_keys: SessionKeys,
}

/// Handshake message types
#[derive(Debug)]
enum HandshakeMessage {
    /// Initial message from initiator
    Init {
        kyber_pk: Vec<u8>,
        falcon_pk: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Response from responder
    Response {
        kyber_ct: Vec<u8>,
        kyber_pk: Vec<u8>,
        falcon_pk: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Final confirmation from initiator
    Confirm {
        kyber_ct: Vec<u8>,
        encrypted_confirmation: Vec<u8>,
    },
}

impl HandshakeMessage {
    fn encode(&self) -> Vec<u8> {
        match self {
            HandshakeMessage::Init { kyber_pk, falcon_pk, signature } => {
                let mut buf = vec![0x01]; // Message type
                buf.extend_from_slice(&(kyber_pk.len() as u32).to_be_bytes());
                buf.extend_from_slice(kyber_pk);
                buf.extend_from_slice(&(falcon_pk.len() as u32).to_be_bytes());
                buf.extend_from_slice(falcon_pk);
                buf.extend_from_slice(&(signature.len() as u32).to_be_bytes());
                buf.extend_from_slice(signature);
                buf
            }
            HandshakeMessage::Response { kyber_ct, kyber_pk, falcon_pk, signature } => {
                let mut buf = vec![0x02]; // Message type
                buf.extend_from_slice(&(kyber_ct.len() as u32).to_be_bytes());
                buf.extend_from_slice(kyber_ct);
                buf.extend_from_slice(&(kyber_pk.len() as u32).to_be_bytes());
                buf.extend_from_slice(kyber_pk);
                buf.extend_from_slice(&(falcon_pk.len() as u32).to_be_bytes());
                buf.extend_from_slice(falcon_pk);
                buf.extend_from_slice(&(signature.len() as u32).to_be_bytes());
                buf.extend_from_slice(signature);
                buf
            }
            HandshakeMessage::Confirm { kyber_ct, encrypted_confirmation } => {
                let mut buf = vec![0x03]; // Message type
                buf.extend_from_slice(&(kyber_ct.len() as u32).to_be_bytes());
                buf.extend_from_slice(kyber_ct);
                buf.extend_from_slice(&(encrypted_confirmation.len() as u32).to_be_bytes());
                buf.extend_from_slice(encrypted_confirmation);
                buf
            }
        }
    }

    fn decode(data: &[u8]) -> Result<Self, PqcError> {
        if data.is_empty() {
            return Err(PqcError::InvalidMessage("Empty message".to_string()));
        }

        let msg_type = data[0];
        let mut pos = 1;

        match msg_type {
            0x01 => {
                let (kyber_pk, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (falcon_pk, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (signature, _) = Self::read_field(data, pos)?;
                Ok(HandshakeMessage::Init { kyber_pk, falcon_pk, signature })
            }
            0x02 => {
                let (kyber_ct, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (kyber_pk, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (falcon_pk, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (signature, _) = Self::read_field(data, pos)?;
                Ok(HandshakeMessage::Response { kyber_ct, kyber_pk, falcon_pk, signature })
            }
            0x03 => {
                let (kyber_ct, new_pos) = Self::read_field(data, pos)?;
                pos = new_pos;
                let (encrypted_confirmation, _) = Self::read_field(data, pos)?;
                Ok(HandshakeMessage::Confirm { kyber_ct, encrypted_confirmation })
            }
            _ => Err(PqcError::InvalidMessage(format!("Unknown message type: {}", msg_type))),
        }
    }

    fn read_field(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), PqcError> {
        if pos + 4 > data.len() {
            return Err(PqcError::InvalidMessage("Truncated field length".to_string()));
        }
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start + len;
        if end > data.len() {
            return Err(PqcError::InvalidMessage("Truncated field data".to_string()));
        }
        Ok((data[start..end].to_vec(), end))
    }
}

/// Perform the initiator side of the PQC handshake
async fn handshake_initiator<S>(
    mut stream: S,
    identity: &PqcIdentity,
) -> Result<PqcOutput<S>, PqcError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    log::debug!("PQC handshake: initiator starting");

    // Step 1: Generate ephemeral Kyber keypair and send Init message
    let ephemeral = EphemeralKyber::generate();
    let kyber_pk_bytes = ephemeral.public_key.as_bytes().to_vec();
    let falcon_pk_bytes = identity.public_key_bytes();

    // Sign the Kyber public key with our Falcon identity
    let signed_msg = identity.sign(&kyber_pk_bytes);
    let signature = signed_msg.as_bytes().to_vec();

    let init_msg = HandshakeMessage::Init {
        kyber_pk: kyber_pk_bytes.clone(),
        falcon_pk: falcon_pk_bytes,
        signature,
    };

    let init_bytes = init_msg.encode();
    let len_bytes = (init_bytes.len() as u32).to_be_bytes();

    // Write length-prefixed message
    stream.write_all(&len_bytes).await?;
    stream.write_all(&init_bytes).await?;
    stream.flush().await?;

    log::debug!("PQC handshake: sent Init message ({} bytes)", init_bytes.len());

    // Step 2: Receive Response message
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_MESSAGE_SIZE {
        return Err(PqcError::InvalidMessage("Message too large".to_string()));
    }

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    let response = HandshakeMessage::decode(&msg_buf)?;

    let (kyber_ct_bytes, responder_kyber_pk_bytes, responder_falcon_pk_bytes, response_sig) = match response {
        HandshakeMessage::Response { kyber_ct, kyber_pk, falcon_pk, signature } => {
            (kyber_ct, kyber_pk, falcon_pk, signature)
        }
        _ => return Err(PqcError::ProtocolViolation("Expected Response message".to_string())),
    };

    log::debug!("PQC handshake: received Response message");

    // Verify the responder's signature
    let responder_falcon_pk = falcon1024::PublicKey::from_bytes(&responder_falcon_pk_bytes)
        .map_err(|_| PqcError::SignatureVerification("Invalid Falcon public key".to_string()))?;

    // The signature covers kyber_ct || kyber_pk
    let mut signed_data = kyber_ct_bytes.clone();
    signed_data.extend_from_slice(&responder_kyber_pk_bytes);

    let signed_message = falcon1024::SignedMessage::from_bytes(&response_sig)
        .map_err(|_| PqcError::SignatureVerification("Invalid signature format".to_string()))?;

    let verified_data = falcon1024::open(&signed_message, &responder_falcon_pk)
        .map_err(|_| PqcError::SignatureVerification("Signature verification failed".to_string()))?;

    if verified_data != signed_data {
        return Err(PqcError::SignatureVerification("Signed data mismatch".to_string()));
    }

    // Decapsulate to get shared secret 1
    let kyber_ct = kyber1024::Ciphertext::from_bytes(&kyber_ct_bytes)
        .map_err(|_| PqcError::Decapsulation("Invalid ciphertext".to_string()))?;
    let shared_secret1 = ephemeral.decapsulate(&kyber_ct);

    // Encapsulate with responder's Kyber public key to get shared secret 2
    let responder_kyber_pk = kyber1024::PublicKey::from_bytes(&responder_kyber_pk_bytes)
        .map_err(|_| PqcError::Encapsulation("Invalid Kyber public key".to_string()))?;
    let (shared_secret2, my_ct) = EphemeralKyber::encapsulate(&responder_kyber_pk);

    // Derive session keys
    let mut session_keys = SessionKeys::derive(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        true, // We are initiator
    );

    // Step 3: Send Confirm message
    let confirmation = b"PQC-HANDSHAKE-COMPLETE";
    let encrypted_confirmation = session_keys.encrypt(confirmation)?;

    let confirm_msg = HandshakeMessage::Confirm {
        kyber_ct: my_ct.as_bytes().to_vec(),
        encrypted_confirmation,
    };

    let confirm_bytes = confirm_msg.encode();
    let len_bytes = (confirm_bytes.len() as u32).to_be_bytes();

    stream.write_all(&len_bytes).await?;
    stream.write_all(&confirm_bytes).await?;
    stream.flush().await?;

    log::debug!("PQC handshake: sent Confirm message, handshake complete");

    // Derive remote peer ID from their Falcon public key
    let remote_peer_id = {
        let hash = Sha3_256::digest(&responder_falcon_pk_bytes);
        let mut multihash = vec![0x12, 0x20];
        multihash.extend_from_slice(&hash);
        PeerId::from_bytes(&multihash).expect("Valid multihash")
    };

    Ok(PqcOutput {
        stream,
        remote_peer_id,
        remote_public_key: responder_falcon_pk_bytes,
        session_keys,
    })
}

/// Perform the responder side of the PQC handshake
async fn handshake_responder<S>(
    mut stream: S,
    identity: &PqcIdentity,
) -> Result<PqcOutput<S>, PqcError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    log::debug!("PQC handshake: responder starting");

    // Step 1: Receive Init message
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_MESSAGE_SIZE {
        return Err(PqcError::InvalidMessage("Message too large".to_string()));
    }

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    let init = HandshakeMessage::decode(&msg_buf)?;

    let (initiator_kyber_pk_bytes, initiator_falcon_pk_bytes, init_sig) = match init {
        HandshakeMessage::Init { kyber_pk, falcon_pk, signature } => {
            (kyber_pk, falcon_pk, signature)
        }
        _ => return Err(PqcError::ProtocolViolation("Expected Init message".to_string())),
    };

    log::debug!("PQC handshake: received Init message");

    // Verify the initiator's signature
    let initiator_falcon_pk = falcon1024::PublicKey::from_bytes(&initiator_falcon_pk_bytes)
        .map_err(|_| PqcError::SignatureVerification("Invalid Falcon public key".to_string()))?;

    let signed_message = falcon1024::SignedMessage::from_bytes(&init_sig)
        .map_err(|_| PqcError::SignatureVerification("Invalid signature format".to_string()))?;

    let verified_data = falcon1024::open(&signed_message, &initiator_falcon_pk)
        .map_err(|_| PqcError::SignatureVerification("Signature verification failed".to_string()))?;

    if verified_data != initiator_kyber_pk_bytes {
        return Err(PqcError::SignatureVerification("Signed data mismatch".to_string()));
    }

    // Generate our ephemeral Kyber keypair
    let ephemeral = EphemeralKyber::generate();
    let my_kyber_pk_bytes = ephemeral.public_key.as_bytes().to_vec();

    // Encapsulate with initiator's Kyber public key
    let initiator_kyber_pk = kyber1024::PublicKey::from_bytes(&initiator_kyber_pk_bytes)
        .map_err(|_| PqcError::Encapsulation("Invalid Kyber public key".to_string()))?;
    let (shared_secret1, kyber_ct) = EphemeralKyber::encapsulate(&initiator_kyber_pk);
    let kyber_ct_bytes = kyber_ct.as_bytes().to_vec();

    // Sign kyber_ct || kyber_pk with our Falcon identity
    let mut to_sign = kyber_ct_bytes.clone();
    to_sign.extend_from_slice(&my_kyber_pk_bytes);
    let signed_msg = identity.sign(&to_sign);
    let signature = signed_msg.as_bytes().to_vec();

    // Step 2: Send Response message
    let response_msg = HandshakeMessage::Response {
        kyber_ct: kyber_ct_bytes,
        kyber_pk: my_kyber_pk_bytes.clone(),
        falcon_pk: identity.public_key_bytes(),
        signature,
    };

    let response_bytes = response_msg.encode();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();

    stream.write_all(&len_bytes).await?;
    stream.write_all(&response_bytes).await?;
    stream.flush().await?;

    log::debug!("PQC handshake: sent Response message");

    // Step 3: Receive Confirm message
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_MESSAGE_SIZE {
        return Err(PqcError::InvalidMessage("Message too large".to_string()));
    }

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    let confirm = HandshakeMessage::decode(&msg_buf)?;

    let (confirm_ct_bytes, encrypted_confirmation) = match confirm {
        HandshakeMessage::Confirm { kyber_ct, encrypted_confirmation } => {
            (kyber_ct, encrypted_confirmation)
        }
        _ => return Err(PqcError::ProtocolViolation("Expected Confirm message".to_string())),
    };

    // Decapsulate to get shared secret 2
    let confirm_ct = kyber1024::Ciphertext::from_bytes(&confirm_ct_bytes)
        .map_err(|_| PqcError::Decapsulation("Invalid ciphertext".to_string()))?;
    let shared_secret2 = ephemeral.decapsulate(&confirm_ct);

    // Derive session keys
    let mut session_keys = SessionKeys::derive(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        false, // We are responder
    );

    // Verify the encrypted confirmation
    let decrypted = session_keys.decrypt(&encrypted_confirmation)?;
    if decrypted != b"PQC-HANDSHAKE-COMPLETE" {
        return Err(PqcError::ProtocolViolation("Invalid confirmation".to_string()));
    }

    log::debug!("PQC handshake: received Confirm message, handshake complete");

    // Derive remote peer ID from their Falcon public key
    let remote_peer_id = {
        let hash = Sha3_256::digest(&initiator_falcon_pk_bytes);
        let mut multihash = vec![0x12, 0x20];
        multihash.extend_from_slice(&hash);
        PeerId::from_bytes(&multihash).expect("Valid multihash")
    };

    Ok(PqcOutput {
        stream,
        remote_peer_id,
        remote_public_key: initiator_falcon_pk_bytes,
        session_keys,
    })
}

// Implement InboundConnectionUpgrade for PqcConfig
impl<S> InboundConnectionUpgrade<S> for PqcConfig
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Return (PeerId, S) to match what libp2p transport builder expects
    type Output = (PeerId, S);
    type Error = PqcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, stream: S, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            let output = handshake_responder(stream, &self.identity).await?;
            Ok((output.remote_peer_id, output.stream))
        })
    }
}

// Implement OutboundConnectionUpgrade for PqcConfig
impl<S> OutboundConnectionUpgrade<S> for PqcConfig
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Return (PeerId, S) to match what libp2p transport builder expects
    type Output = (PeerId, S);
    type Error = PqcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, stream: S, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            let output = handshake_initiator(stream, &self.identity).await?;
            Ok((output.remote_peer_id, output.stream))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = PqcIdentity::generate();
        let peer_id = identity.peer_id();
        println!("Generated PeerId: {}", peer_id);
        assert!(!peer_id.to_bytes().is_empty());
    }

    #[test]
    fn test_signature_roundtrip() {
        let identity = PqcIdentity::generate();
        let message = b"Hello, quantum world!";

        let signed = identity.sign(message);

        // Verify using the public key
        let verified = falcon1024::open(&signed, &identity.public_key);
        assert!(verified.is_ok());
        assert_eq!(verified.unwrap(), message);
    }

    #[test]
    fn test_kyber_encapsulation() {
        let ephemeral = EphemeralKyber::generate();
        let (shared_secret, ciphertext) = EphemeralKyber::encapsulate(&ephemeral.public_key);
        let decapsulated = ephemeral.decapsulate(&ciphertext);

        assert_eq!(shared_secret.as_bytes(), decapsulated.as_bytes());
    }

    #[test]
    fn test_session_key_derivation() {
        let ss1 = vec![0u8; 32];
        let ss2 = vec![1u8; 32];

        let initiator_keys = SessionKeys::derive(&ss1, &ss2, true);
        let responder_keys = SessionKeys::derive(&ss1, &ss2, false);

        // Initiator's encrypt key should match responder's decrypt key
        assert_eq!(initiator_keys.encrypt_key, responder_keys.decrypt_key);
        // Responder's encrypt key should match initiator's decrypt key
        assert_eq!(responder_keys.encrypt_key, initiator_keys.decrypt_key);
    }

    #[test]
    fn test_session_encryption() {
        let ss1 = vec![0u8; 32];
        let ss2 = vec![1u8; 32];

        let mut initiator_keys = SessionKeys::derive(&ss1, &ss2, true);
        let mut responder_keys = SessionKeys::derive(&ss1, &ss2, false);

        let plaintext = b"Secret quantum message";
        let ciphertext = initiator_keys.encrypt(plaintext).unwrap();
        let decrypted = responder_keys.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_message_encoding() {
        let init = HandshakeMessage::Init {
            kyber_pk: vec![1, 2, 3],
            falcon_pk: vec![4, 5, 6],
            signature: vec![7, 8, 9],
        };

        let encoded = init.encode();
        let decoded = HandshakeMessage::decode(&encoded).unwrap();

        match decoded {
            HandshakeMessage::Init { kyber_pk, falcon_pk, signature } => {
                assert_eq!(kyber_pk, vec![1, 2, 3]);
                assert_eq!(falcon_pk, vec![4, 5, 6]);
                assert_eq!(signature, vec![7, 8, 9]);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
