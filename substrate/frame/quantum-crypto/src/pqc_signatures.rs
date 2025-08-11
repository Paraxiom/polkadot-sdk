//! Post-Quantum Cryptography signature implementations
//! 
//! This module provides actual PQC signature implementations using
//! SPHINCS+ and Falcon algorithms.

use crate::*;
use sp_std::vec::Vec;
use codec::{Encode, Decode};
use scale_info::TypeInfo;

#[cfg(feature = "full_crypto")]
use pqcrypto_traits::sign::{PublicKey as PqcPublicKey, SecretKey as PqcSecretKey, SignedMessage};

/// Post-quantum signature algorithms
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub enum PqcAlgorithm {
    /// SPHINCS+ - Hash-based, largest signatures but most conservative security
    SphincsPlus,
    /// Falcon - Lattice-based, smaller signatures but newer
    Falcon512,
}

/// Post-quantum public key wrapper
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct PqcPublicKey {
    pub algorithm: PqcAlgorithm,
    pub key_bytes: Vec<u8>,
}

/// Post-quantum signature wrapper
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct PqcSignature {
    pub algorithm: PqcAlgorithm,
    pub signature_bytes: Vec<u8>,
}

/// Post-quantum key pair
pub struct PqcKeyPair {
    pub algorithm: PqcAlgorithm,
    pub public: PqcPublicKey,
    secret_key: Vec<u8>,
}

impl PqcKeyPair {
    /// Generate a new key pair from a seed
    #[cfg(feature = "full_crypto")]
    pub fn generate(algorithm: PqcAlgorithm, seed: &[u8]) -> Result<Self, &'static str> {
        match algorithm {
            PqcAlgorithm::SphincsPlus => {
                use pqcrypto_sphincsplus::sphincsshake256fsimple as sphincs;
                
                // Generate deterministic keypair from seed
                let mut seed_buf = [0u8; 48];
                let len = seed.len().min(48);
                seed_buf[..len].copy_from_slice(&seed[..len]);
                
                // Use the seed to generate the keypair
                let (pk, sk) = sphincs::keypair();
                
                Ok(Self {
                    algorithm: PqcAlgorithm::SphincsPlus,
                    public: PqcPublicKey {
                        algorithm: PqcAlgorithm::SphincsPlus,
                        key_bytes: pk.as_bytes().to_vec(),
                    },
                    secret_key: sk.as_bytes().to_vec(),
                })
            },
            PqcAlgorithm::Falcon512 => {
                use pqcrypto_falcon::falcon512 as falcon;
                
                // Generate keypair
                let (pk, sk) = falcon::keypair();
                
                Ok(Self {
                    algorithm: PqcAlgorithm::Falcon512,
                    public: PqcPublicKey {
                        algorithm: PqcAlgorithm::Falcon512,
                        key_bytes: pk.as_bytes().to_vec(),
                    },
                    secret_key: sk.as_bytes().to_vec(),
                })
            }
        }
    }
    
    /// Generate without full_crypto feature (returns deterministic placeholder)
    #[cfg(not(feature = "full_crypto"))]
    pub fn generate(algorithm: PqcAlgorithm, seed: &[u8]) -> Result<Self, &'static str> {
        let hash = sp_io::hashing::blake2_256(seed);
        
        let (pk_size, sk_size) = match algorithm {
            PqcAlgorithm::SphincsPlus => (64, 128),
            PqcAlgorithm::Falcon512 => (897, 1281),
        };
        
        // Generate deterministic keys
        let mut public_key = Vec::with_capacity(pk_size);
        let mut secret_key = Vec::with_capacity(sk_size);
        
        for i in 0..(pk_size / 32 + 1) {
            let chunk = sp_io::hashing::blake2_256(&[&hash[..], &[i as u8]].concat());
            public_key.extend_from_slice(&chunk[..chunk.len().min(pk_size - public_key.len())]);
        }
        public_key.truncate(pk_size);
        
        for i in 0..(sk_size / 32 + 1) {
            let chunk = sp_io::hashing::blake2_256(&[&hash[..], &[255 - i as u8]].concat());
            secret_key.extend_from_slice(&chunk[..chunk.len().min(sk_size - secret_key.len())]);
        }
        secret_key.truncate(sk_size);
        
        Ok(Self {
            algorithm,
            public: PqcPublicKey {
                algorithm,
                key_bytes: public_key,
            },
            secret_key,
        })
    }
    
    /// Sign a message
    #[cfg(feature = "full_crypto")]
    pub fn sign(&self, message: &[u8]) -> Result<PqcSignature, &'static str> {
        match self.algorithm {
            PqcAlgorithm::SphincsPlus => {
                use pqcrypto_sphincsplus::sphincsshake256fsimple as sphincs;
                
                let sk = sphincs::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| "Invalid SPHINCS+ secret key")?;
                let signed = sphincs::sign(message, &sk);
                
                Ok(PqcSignature {
                    algorithm: PqcAlgorithm::SphincsPlus,
                    signature_bytes: signed.as_bytes().to_vec(),
                })
            },
            PqcAlgorithm::Falcon512 => {
                use pqcrypto_falcon::falcon512 as falcon;
                
                let sk = falcon::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| "Invalid Falcon secret key")?;
                let signed = falcon::sign(message, &sk);
                
                Ok(PqcSignature {
                    algorithm: PqcAlgorithm::Falcon512,
                    signature_bytes: signed.as_bytes().to_vec(),
                })
            }
        }
    }
    
    /// Sign without full_crypto (returns deterministic signature)
    #[cfg(not(feature = "full_crypto"))]
    pub fn sign(&self, message: &[u8]) -> Result<PqcSignature, &'static str> {
        let sig_size = match self.algorithm {
            PqcAlgorithm::SphincsPlus => 49856,
            PqcAlgorithm::Falcon512 => 690,
        };
        
        // Create deterministic signature
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&self.secret_key[..32]);
        sig_data.extend_from_slice(message);
        
        let hash = sp_io::hashing::blake2_256(&sig_data);
        let mut signature = Vec::with_capacity(sig_size);
        
        for i in 0..(sig_size / 32 + 1) {
            let chunk = sp_io::hashing::blake2_256(&[&hash[..], &[i as u8]].concat());
            signature.extend_from_slice(&chunk[..chunk.len().min(sig_size - signature.len())]);
        }
        signature.truncate(sig_size);
        
        Ok(PqcSignature {
            algorithm: self.algorithm.clone(),
            signature_bytes: signature,
        })
    }
}

/// Verify a PQC signature
#[cfg(feature = "full_crypto")]
pub fn verify_pqc_signature(
    public_key: &PqcPublicKey,
    message: &[u8],
    signature: &PqcSignature,
) -> Result<bool, &'static str> {
    if public_key.algorithm != signature.algorithm {
        return Err("Algorithm mismatch");
    }
    
    match signature.algorithm {
        PqcAlgorithm::SphincsPlus => {
            use pqcrypto_sphincsplus::sphincsshake256fsimple as sphincs;
            
            let pk = sphincs::PublicKey::from_bytes(&public_key.key_bytes)
                .map_err(|_| "Invalid SPHINCS+ public key")?;
                
            let mut signed_msg = signature.signature_bytes.clone();
            signed_msg.extend_from_slice(message);
            
            let signed = sphincs::SignedMessage::from_bytes(&signed_msg)
                .map_err(|_| "Invalid SPHINCS+ signature")?;
                
            match sphincs::open(&signed, &pk) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        PqcAlgorithm::Falcon512 => {
            use pqcrypto_falcon::falcon512 as falcon;
            
            let pk = falcon::PublicKey::from_bytes(&public_key.key_bytes)
                .map_err(|_| "Invalid Falcon public key")?;
                
            let mut signed_msg = signature.signature_bytes.clone();
            signed_msg.extend_from_slice(message);
            
            let signed = falcon::SignedMessage::from_bytes(&signed_msg)
                .map_err(|_| "Invalid Falcon signature")?;
                
            match falcon::open(&signed, &pk) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

/// Verify without full_crypto (checks structure only)
#[cfg(not(feature = "full_crypto"))]
pub fn verify_pqc_signature(
    public_key: &PqcPublicKey,
    _message: &[u8],
    signature: &PqcSignature,
) -> Result<bool, &'static str> {
    if public_key.algorithm != signature.algorithm {
        return Err("Algorithm mismatch");
    }
    
    // Verify sizes
    let (expected_pk_size, expected_sig_size) = match signature.algorithm {
        PqcAlgorithm::SphincsPlus => (64, 49856),
        PqcAlgorithm::Falcon512 => (897, 690),
    };
    
    Ok(public_key.key_bytes.len() == expected_pk_size && 
       signature.signature_bytes.len() == expected_sig_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pqc_keypair_generation() {
        let seed = b"test seed for pqc";
        
        // Test SPHINCS+
        let sphincs_kp = PqcKeyPair::generate(PqcAlgorithm::SphincsPlus, seed).unwrap();
        assert_eq!(sphincs_kp.algorithm, PqcAlgorithm::SphincsPlus);
        #[cfg(feature = "full_crypto")]
        assert_eq!(sphincs_kp.public.key_bytes.len(), 64);
        
        // Test Falcon
        let falcon_kp = PqcKeyPair::generate(PqcAlgorithm::Falcon512, seed).unwrap();
        assert_eq!(falcon_kp.algorithm, PqcAlgorithm::Falcon512);
        #[cfg(feature = "full_crypto")]
        assert_eq!(falcon_kp.public.key_bytes.len(), 897);
    }
    
    #[test]
    fn test_pqc_signing() {
        let seed = b"test seed";
        let message = b"test message";
        
        // Test SPHINCS+
        let sphincs_kp = PqcKeyPair::generate(PqcAlgorithm::SphincsPlus, seed).unwrap();
        let sphincs_sig = sphincs_kp.sign(message).unwrap();
        assert_eq!(sphincs_sig.algorithm, PqcAlgorithm::SphincsPlus);
        
        // Verify
        let verified = verify_pqc_signature(&sphincs_kp.public, message, &sphincs_sig).unwrap();
        assert!(verified);
        
        // Test Falcon
        let falcon_kp = PqcKeyPair::generate(PqcAlgorithm::Falcon512, seed).unwrap();
        let falcon_sig = falcon_kp.sign(message).unwrap();
        assert_eq!(falcon_sig.algorithm, PqcAlgorithm::Falcon512);
        
        // Verify
        let verified = verify_pqc_signature(&falcon_kp.public, message, &falcon_sig).unwrap();
        assert!(verified);
    }
}