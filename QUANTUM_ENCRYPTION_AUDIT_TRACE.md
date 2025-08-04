# Quantum Encryption Audit Trace - Polkadot SDK

## Overview
This document traces all cryptographic changes made to transition from classical to quantum-safe/QKD-oriented encryption.

## Changes Made

### 1. Core Primitives (`/polkadot/primitives/src/v8/mod.rs`)
- **REMOVED**: sr25519 (ECDLP vulnerable)
- **REMOVED**: Blake2 hashing (not quantum-safe)
- **ADDED**: SPHINCS+ for signatures (hash-based, quantum-safe)
- **ADDED**: SHA3-256 for hashing (quantum-resistant)
- **ADDED**: QuantumPublic, QuantumSignature types
- **ADDED**: QuantumHasher using SHA3

### 2. Validator/Collator Types
```rust
// Before (quantum-vulnerable)
pub type ValidatorId = sp_core::sr25519::Public;
pub type CollatorId = sp_core::sr25519::Public;

// After (quantum-safe)
pub type ValidatorId = QuantumPublic;
pub type CollatorId = QuantumPublic;
```

### 3. Executor Parameters (`/polkadot/primitives/src/v8/executor_params.rs`)
- **CHANGED**: All hash references from BlakeTwo256 to QuantumHasher
- **UPDATED**: Hash calculations to use SHA3

### 4. Keystore (`/substrate/primitives/keystore/src/lib.rs`)
- **REMOVED**: All sr25519 methods
- **REMOVED**: All ed25519 methods  
- **REMOVED**: All ecdsa methods
- **KEPT**: SPHINCS methods (quantum-safe)
- **KEPT**: BLS381 methods (quantum-resistant)
- **KEPT**: Bandersnatch methods (quantum-resistant)

## Remaining Vulnerabilities to Address

### Identified Issues:
1. **GRANDPA consensus** - Still references ed25519
2. **BABE consensus** - Uses sr25519 for block production
3. **Session keys** - May still use classical crypto
4. **P2P networking** - LibP2P uses classical crypto
5. **RPC signatures** - Need quantum-safe alternatives

## QKD Integration Points

### Current Infrastructure:
- Toshiba QKD device (beacon signals)
- Crypto4A quantum RNG
- KIRQ hub for entropy distribution

### Proposed Architecture:
```
QKD Device → Beacon Signal → Fourier Transform → Tonnetz Filter → Quantum Key
     ↓                                                                    ↓
Double Ratchet ← Lamport Signatures ← HTM Processing ← Entropy Pool
```

## Next Steps for Complete Transition

1. **Consensus Layer**: Replace GRANDPA/BABE with quantum-safe alternatives
2. **Networking**: Implement QKD key exchange for P2P connections
3. **Storage**: Use quantum-derived keys for state encryption
4. **Runtime**: Ensure all pallets use quantum-safe crypto

## Validation Rules for NLP Parser

The parser should check for:
- No imports of: sr25519, ed25519, ecdsa, secp256k1
- No use of: Blake2, SHA2 (prefer SHA3, SHAKE)
- All signatures must use: SPHINCS+, Lamport, or other PQC
- All key exchanges must reference: QKD, post-quantum KEMs
- Entropy sources must trace to: quantum RNG or QKD devices