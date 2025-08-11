use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// SPHINCS+ public key (simplified for now)
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SphincsPlusPublic(pub [u8; 64]);

impl From<[u8; 64]> for SphincsPlusPublic {
    fn from(data: [u8; 64]) -> Self {
        Self(data)
    }
}

impl AsRef<[u8]> for SphincsPlusPublic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl sp_std::fmt::Debug for SphincsPlusPublic {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "SphincsPlusPublic({:?})", &self.0[..8])
    }
}

/// SPHINCS+ signature (simplified for now)
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct SphincsPlusSignature(pub Vec<u8>);

impl AsRef<[u8]> for SphincsPlusSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl sp_std::fmt::Debug for SphincsPlusSignature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "SphincsPlusSignature({} bytes)", self.0.len())
    }
}

/// Quantum signature that can be either classical (stub) or post-quantum
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub enum QuantumSignature {
    Ed25519(sp_runtime::quantum_stubs::ed25519::Signature),
    Sr25519(sp_runtime::quantum_stubs::sr25519::Signature),
    SphincsPlus(SphincsPlusSignature),
}

/// Quantum public key that can be either classical (stub) or post-quantum
#[derive(Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub enum QuantumPublic {
    Ed25519(sp_runtime::quantum_stubs::ed25519::Public),
    Sr25519(sp_runtime::quantum_stubs::sr25519::Public),
    SphincsPlus(SphincsPlusPublic),
}

impl From<sp_runtime::quantum_stubs::ed25519::Public> for QuantumPublic {
    fn from(key: sp_runtime::quantum_stubs::ed25519::Public) -> Self {
        QuantumPublic::Ed25519(key)
    }
}

impl From<sp_runtime::quantum_stubs::sr25519::Public> for QuantumPublic {
    fn from(key: sp_runtime::quantum_stubs::sr25519::Public) -> Self {
        QuantumPublic::Sr25519(key)
    }
}

impl From<SphincsPlusPublic> for QuantumPublic {
    fn from(key: SphincsPlusPublic) -> Self {
        QuantumPublic::SphincsPlus(key)
    }
}

impl sp_std::fmt::Debug for QuantumSignature {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            QuantumSignature::Ed25519(_) => write!(f, "QuantumSignature::Ed25519(stub)"),
            QuantumSignature::Sr25519(_) => write!(f, "QuantumSignature::Sr25519(stub)"),
            QuantumSignature::SphincsPlus(sig) => write!(f, "QuantumSignature::SphincsPlus({} bytes)", sig.0.len()),
        }
    }
}

impl sp_std::fmt::Debug for QuantumPublic {
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            QuantumPublic::Ed25519(_) => write!(f, "QuantumPublic::Ed25519(stub)"),
            QuantumPublic::Sr25519(_) => write!(f, "QuantumPublic::Sr25519(stub)"),
            QuantumPublic::SphincsPlus(key) => write!(f, "QuantumPublic::SphincsPlus({:?})", &key.0[..8]),
        }
    }
}