//! # Double Ratchet Lamport Signatures
//!
//! This module implements a post-quantum secure messaging system using:
//! - Lamport one-time signatures for authentication
//! - Double ratchet algorithm for forward secrecy
//! - Integration with quantum entropy sources
//!
//! ## Overview
//! 
//! The double ratchet provides forward secrecy by continuously updating keys,
//! while Lamport signatures provide post-quantum security. Each message uses
//! a fresh Lamport key pair that is never reused.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::{vec::Vec, vec};
use sp_core::H256;
use sha3::{Sha3_256, Digest};
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use frame_support::pallet_prelude::*;

/// Size of each Lamport signature component (256 bits = 32 bytes)
const LAMPORT_CHUNK_SIZE: usize = 32;
/// Number of chunks in a Lamport key (256 bits requires 256 pairs)
const LAMPORT_KEY_CHUNKS: usize = 256;
/// Total size of a Lamport public key in bytes
const LAMPORT_PUBLIC_KEY_SIZE: usize = LAMPORT_KEY_CHUNKS * 2 * LAMPORT_CHUNK_SIZE;
/// Total size of a Lamport private key in bytes
const LAMPORT_PRIVATE_KEY_SIZE: usize = LAMPORT_KEY_CHUNKS * 2 * LAMPORT_CHUNK_SIZE;
/// Size of a Lamport signature in bytes
const LAMPORT_SIGNATURE_SIZE: usize = LAMPORT_KEY_CHUNKS * LAMPORT_CHUNK_SIZE;

/// Lamport one-time signature key pair
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct LamportKeyPair {
    /// Private key: 256 pairs of 32-byte values
    private_key: BoundedVec<u8, ConstU32<{ LAMPORT_PRIVATE_KEY_SIZE as u32 }>>,
    /// Public key: Hash of private key pairs
    public_key: BoundedVec<u8, ConstU32<{ LAMPORT_PUBLIC_KEY_SIZE as u32 }>>,
}

/// Lamport signature
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct LamportSignature {
    /// Signature: 256 chunks of 32 bytes each
    pub signature: BoundedVec<u8, ConstU32<{ LAMPORT_SIGNATURE_SIZE as u32 }>>,
}

impl LamportSignature {
    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() != LAMPORT_SIGNATURE_SIZE {
            return Err("Invalid signature size");
        }
        Ok(Self {
            signature: bytes.try_into().map_err(|_| "Signature conversion failed")?,
        })
    }
}

/// Double Ratchet state for a communication session
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct DoubleRatchetState {
    /// Root key for deriving chain keys
    root_key: [u8; 32],
    /// Sending chain key
    sending_chain_key: [u8; 32],
    /// Receiving chain key
    receiving_chain_key: [u8; 32],
    /// Current sending Lamport key pair
    sending_lamport: LamportKeyPair,
    /// Next receiving Lamport public key
    receiving_lamport_public: BoundedVec<u8, ConstU32<{ LAMPORT_PUBLIC_KEY_SIZE as u32 }>>,
    /// Message counter for sending chain
    sending_counter: u32,
    /// Message counter for receiving chain
    receiving_counter: u32,
    /// Previous chain keys for handling out-of-order messages
    skipped_keys: BoundedVec<([u8; 32], u32), ConstU32<100>>,
}

/// Message with Lamport signature and ratchet metadata
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct RatchetMessage {
    /// Message header (includes new public key for ratchet)
    pub header: MessageHeader,
    /// Encrypted message content
    pub ciphertext: BoundedVec<u8, ConstU32<4096>>,
    /// Lamport signature over header + ciphertext
    pub signature: LamportSignature,
}

/// Message header for double ratchet
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct MessageHeader {
    /// New Lamport public key for next ratchet
    pub next_lamport_public: BoundedVec<u8, ConstU32<{ LAMPORT_PUBLIC_KEY_SIZE as u32 }>>,
    /// Message number in current chain
    pub message_number: u32,
    /// Previous chain message count (for synchronization)
    pub previous_chain_length: u32,
}

/// Errors that can occur in double ratchet operations
#[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq)]
pub enum DoubleRatchetError {
    /// Invalid signature
    InvalidSignature,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Message out of order beyond skip limit
    MessageTooOld,
    /// Invalid message format
    InvalidMessage,
    /// Entropy source unavailable
    NoEntropy,
}

/// Implementation of Lamport signatures
impl LamportKeyPair {
    /// Generate a new Lamport key pair using quantum entropy
    pub fn generate<T: crate::Config>(
        entropy_source: &mut impl FnMut(usize) -> Result<Vec<u8>, DispatchError>
    ) -> Result<Self, DispatchError> {
        // Generate private key from quantum entropy
        let private_key_bytes = entropy_source(LAMPORT_PRIVATE_KEY_SIZE)?;
        let private_key: BoundedVec<u8, ConstU32<{ LAMPORT_PRIVATE_KEY_SIZE as u32 }>> = 
            private_key_bytes.try_into()
                .map_err(|_| DispatchError::Other("Invalid key size"))?;
        
        // Generate public key by hashing private key chunks
        let mut public_key_vec = Vec::with_capacity(LAMPORT_PUBLIC_KEY_SIZE);
        
        for i in 0..LAMPORT_KEY_CHUNKS * 2 {
            let start = i * LAMPORT_CHUNK_SIZE;
            let end = start + LAMPORT_CHUNK_SIZE;
            let hash = sha3_256(&private_key[start..end]);
            public_key_vec.extend_from_slice(&hash);
        }
        
        let public_key: BoundedVec<u8, ConstU32<{ LAMPORT_PUBLIC_KEY_SIZE as u32 }>> = 
            public_key_vec.try_into()
                .map_err(|_| DispatchError::Other("Invalid public key size"))?;
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Sign a message using the Lamport private key
    pub fn sign(&self, message: &[u8]) -> LamportSignature {
        let hash = sha3_256(message);
        let mut signature_vec = Vec::with_capacity(LAMPORT_SIGNATURE_SIZE);
        
        // For each bit in the hash
        for (byte_idx, byte) in hash.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let chunk_idx = byte_idx * 8 + bit_idx;
                
                // Select private key chunk based on bit value
                let key_offset = if bit == 0 {
                    chunk_idx * LAMPORT_CHUNK_SIZE
                } else {
                    (chunk_idx + LAMPORT_KEY_CHUNKS) * LAMPORT_CHUNK_SIZE
                };
                
                let chunk_end = key_offset + LAMPORT_CHUNK_SIZE;
                signature_vec.extend_from_slice(&self.private_key[key_offset..chunk_end]);
            }
        }
        
        LamportSignature {
            signature: signature_vec.try_into().expect("Signature size mismatch"),
        }
    }
    
    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Verify a Lamport signature
pub fn verify_lamport_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &LamportSignature,
) -> bool {
    if public_key.len() != LAMPORT_PUBLIC_KEY_SIZE {
        return false;
    }
    
    let hash = sha3_256(message);
    
    // Verify each chunk of the signature
    for (byte_idx, byte) in hash.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit = (byte >> (7 - bit_idx)) & 1;
            let chunk_idx = byte_idx * 8 + bit_idx;
            
            // Get signature chunk
            let sig_start = chunk_idx * LAMPORT_CHUNK_SIZE;
            let sig_end = sig_start + LAMPORT_CHUNK_SIZE;
            let sig_chunk = &signature.signature[sig_start..sig_end];
            
            // Hash the signature chunk
            let sig_hash = sha3_256(sig_chunk);
            
            // Get corresponding public key chunk
            let pub_offset = if bit == 0 {
                chunk_idx * LAMPORT_CHUNK_SIZE
            } else {
                (chunk_idx + LAMPORT_KEY_CHUNKS) * LAMPORT_CHUNK_SIZE
            };
            let pub_end = pub_offset + LAMPORT_CHUNK_SIZE;
            let pub_chunk = &public_key[pub_offset..pub_end];
            
            // Compare hashes
            if sig_hash != pub_chunk[..32] {
                return false;
            }
        }
    }
    
    true
}

/// Implementation of Double Ratchet algorithm
impl DoubleRatchetState {
    /// Initialize a new double ratchet session
    pub fn initialize<T: crate::Config>(
        shared_secret: &[u8; 32],
        is_initiator: bool,
        entropy_source: &mut impl FnMut(usize) -> Result<Vec<u8>, DispatchError>,
    ) -> Result<Self, DispatchError> {
        // Derive initial keys from shared secret
        let mut root_input = Vec::new();
        root_input.extend_from_slice(shared_secret);
        root_input.extend_from_slice(b"root");
        let root_key = sha3_256(&root_input);
        
        let mut chain_input = Vec::new();
        chain_input.extend_from_slice(shared_secret);
        chain_input.extend_from_slice(b"chain");
        let chain_key = sha3_256(&chain_input);
        
        // Generate initial Lamport key pair
        let sending_lamport = LamportKeyPair::generate::<T>(entropy_source)?;
        
        // Initialize with empty receiving key (will be set on first message)
        let empty_public = vec![0u8; LAMPORT_PUBLIC_KEY_SIZE];
        let receiving_lamport_public = empty_public.try_into()
            .map_err(|_| DispatchError::Other("Invalid key size"))?;
        
        Ok(Self {
            root_key,
            sending_chain_key: if is_initiator { chain_key } else { [0u8; 32] },
            receiving_chain_key: if !is_initiator { chain_key } else { [0u8; 32] },
            sending_lamport,
            receiving_lamport_public,
            sending_counter: 0,
            receiving_counter: 0,
            skipped_keys: BoundedVec::default(),
        })
    }
    
    /// Encrypt and sign a message
    pub fn encrypt_message<T: crate::Config>(
        &mut self,
        plaintext: &[u8],
        entropy_source: &mut impl FnMut(usize) -> Result<Vec<u8>, DispatchError>,
    ) -> Result<RatchetMessage, DispatchError> {
        // Generate new Lamport key pair for next message
        let next_lamport = LamportKeyPair::generate::<T>(entropy_source)?;
        
        // Create message header
        let header = MessageHeader {
            next_lamport_public: next_lamport.public_key.clone(),
            message_number: self.sending_counter,
            previous_chain_length: self.receiving_counter,
        };
        
        // Derive message key from chain key
        let message_key = self.derive_message_key(self.sending_chain_key);
        
        // Encrypt message (simplified - in production use ChaCha20Poly1305)
        let ciphertext = self.simple_encrypt(plaintext, &message_key)?;
        
        // Sign header + ciphertext
        let mut to_sign = header.encode();
        to_sign.extend_from_slice(&ciphertext);
        let signature = self.sending_lamport.sign(&to_sign);
        
        // Update state
        self.sending_chain_key = self.ratchet_chain_key(self.sending_chain_key);
        self.sending_counter += 1;
        self.sending_lamport = next_lamport;
        
        Ok(RatchetMessage {
            header,
            ciphertext,
            signature,
        })
    }
    
    /// Decrypt and verify a message
    pub fn decrypt_message<T: crate::Config>(
        &mut self,
        message: &RatchetMessage,
        entropy_source: &mut impl FnMut(usize) -> Result<Vec<u8>, DispatchError>,
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        // Verify signature
        let mut to_verify = message.header.encode();
        to_verify.extend_from_slice(&message.ciphertext);
        
        if !verify_lamport_signature(
            &self.receiving_lamport_public,
            &to_verify,
            &message.signature,
        ) {
            return Err(DoubleRatchetError::InvalidSignature);
        }
        
        // Handle ratchet update if new public key
        if message.header.next_lamport_public != self.receiving_lamport_public {
            self.perform_ratchet::<T>(&message.header.next_lamport_public, entropy_source)
                .map_err(|_| DoubleRatchetError::KeyDerivationFailed)?;
        }
        
        // Derive message key
        let message_key = self.derive_message_key(self.receiving_chain_key);
        
        // Decrypt message
        let plaintext = self.simple_decrypt(&message.ciphertext, &message_key)
            .map_err(|_| DoubleRatchetError::InvalidMessage)?;
        
        // Update state
        self.receiving_chain_key = self.ratchet_chain_key(self.receiving_chain_key);
        self.receiving_counter += 1;
        
        Ok(plaintext)
    }
    
    /// Perform a ratchet step when receiving new public key
    fn perform_ratchet<T: crate::Config>(
        &mut self,
        new_public_key: &BoundedVec<u8, ConstU32<{ LAMPORT_PUBLIC_KEY_SIZE as u32 }>>,
        entropy_source: &mut impl FnMut(usize) -> Result<Vec<u8>, DispatchError>,
    ) -> Result<(), DispatchError> {
        // Update receiving public key
        self.receiving_lamport_public = new_public_key.clone();
        
        // Derive new root key and chain keys
        let shared_secret = self.derive_shared_secret(new_public_key);
        self.root_key = self.kdf_root_key(self.root_key, shared_secret);
        self.receiving_chain_key = self.kdf_chain_key(self.root_key);
        
        // Generate new sending key pair
        self.sending_lamport = LamportKeyPair::generate::<T>(entropy_source)?;
        self.sending_chain_key = self.kdf_chain_key(self.root_key);
        self.sending_counter = 0;
        
        Ok(())
    }
    
    /// Key derivation functions
    fn derive_message_key(&self, chain_key: [u8; 32]) -> [u8; 32] {
        sha3_256(&[&chain_key[..], b"message"].concat())
    }
    
    fn ratchet_chain_key(&self, chain_key: [u8; 32]) -> [u8; 32] {
        sha3_256(&[&chain_key[..], b"chain"].concat())
    }
    
    fn kdf_root_key(&self, root_key: [u8; 32], shared_secret: [u8; 32]) -> [u8; 32] {
        sha3_256(&[&root_key[..], &shared_secret[..], b"root"].concat())
    }
    
    fn kdf_chain_key(&self, root_key: [u8; 32]) -> [u8; 32] {
        sha3_256(&[&root_key[..], b"chain"].concat())
    }
    
    fn derive_shared_secret(&self, public_key: &[u8]) -> [u8; 32] {
        // Derive shared secret using quantum-safe KDF
        // This combines the current chain key with the public key
        // In production, this would use a quantum-safe key exchange like Kyber
        let mut input = Vec::new();
        input.extend_from_slice(&self.sending_chain_key);
        input.extend_from_slice(&self.receiving_chain_key);
        input.extend_from_slice(public_key);
        // Add counter for uniqueness
        input.extend_from_slice(&self.sending_counter.to_le_bytes());
        sha3_256(&input)
    }
    
    /// Simple encryption (XOR with key stream)
    fn simple_encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<BoundedVec<u8, ConstU32<4096>>, DispatchError> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let keystream = self.generate_keystream(key, plaintext.len());
        
        for (i, byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }
        
        ciphertext.try_into()
            .map_err(|_| DispatchError::Other("Message too large"))
    }
    
    /// Simple decryption (XOR with key stream)
    fn simple_decrypt(&self, ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, DispatchError> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let keystream = self.generate_keystream(key, ciphertext.len());
        
        for (i, byte) in ciphertext.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }
        
        Ok(plaintext)
    }
    
    /// Generate keystream for encryption/decryption
    fn generate_keystream(&self, key: &[u8; 32], length: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(length);
        let mut counter = 0u64;
        
        while keystream.len() < length {
            let mut block_input = Vec::new();
            block_input.extend_from_slice(key);
            block_input.extend_from_slice(&counter.to_le_bytes());
            let block = sha3_256(&block_input);
            keystream.extend_from_slice(&block);
            counter += 1;
        }
        
        keystream.truncate(length);
        keystream
    }
}

/// Helper function to create entropy source from quantum RNG
pub fn create_entropy_source<T: crate::Config>() -> impl FnMut(usize) -> Result<Vec<u8>, DispatchError> {
    move |size: usize| {
        crate::Pallet::<T>::quantum_random(size)
            .ok_or(DispatchError::Other("No quantum entropy available"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lamport_signature() {
        // Create mock entropy source
        let mut entropy_source = |size: usize| -> Result<Vec<u8>, DispatchError> {
            Ok(vec![0xAA; size])
        };
        
        // Generate key pair
        let keypair = LamportKeyPair::generate::<crate::mock::Test>(&mut entropy_source)
            .expect("Failed to generate key pair");
        
        // Sign a message
        let message = b"Hello, quantum world!";
        let signature = keypair.sign(message);
        
        // Verify signature
        assert!(verify_lamport_signature(
            keypair.public_key(),
            message,
            &signature
        ));
        
        // Verify wrong message fails
        let wrong_message = b"Wrong message";
        assert!(!verify_lamport_signature(
            keypair.public_key(),
            wrong_message,
            &signature
        ));
    }
    
    #[test]
    fn test_double_ratchet() {
        // Create mock entropy source
        let mut entropy_counter = 0u8;
        let mut entropy_source = move |size: usize| -> Result<Vec<u8>, DispatchError> {
            let mut data = vec![entropy_counter; size];
            entropy_counter = entropy_counter.wrapping_add(1);
            Ok(data)
        };
        
        // Initialize Alice and Bob
        let shared_secret = [0x42; 32];
        let mut alice = DoubleRatchetState::initialize::<crate::mock::Test>(
            &shared_secret,
            true,
            &mut entropy_source,
        ).expect("Failed to initialize Alice");
        
        let mut bob = DoubleRatchetState::initialize::<crate::mock::Test>(
            &shared_secret,
            false,
            &mut entropy_source,
        ).expect("Failed to initialize Bob");
        
        // Exchange initial public keys
        bob.receiving_lamport_public = alice.sending_lamport.public_key.clone();
        alice.receiving_lamport_public = bob.sending_lamport.public_key.clone();
        
        // Alice sends message to Bob
        let plaintext = b"Quantum secure message";
        let encrypted = alice.encrypt_message::<crate::mock::Test>(
            plaintext,
            &mut entropy_source,
        ).expect("Failed to encrypt");
        
        // Bob decrypts message
        let decrypted = bob.decrypt_message::<crate::mock::Test>(
            &encrypted,
            &mut entropy_source,
        ).expect("Failed to decrypt");
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
// SHA3-256 helper function for quantum resistance
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}
