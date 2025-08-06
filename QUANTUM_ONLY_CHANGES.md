# Quantum-Only Polkadot SDK Changes

This document summarizes all changes made to create a quantum-only build of the Polkadot SDK that supports only Post-Quantum Cryptography (PQC) and Quantum Key Distribution (QKD).

## Overview

All classical cryptographic algorithms have been removed or disabled in favor of quantum-safe alternatives. The primary quantum-safe signature scheme is SPHINCS+ (NIST standardized), with QKD integration for key distribution.

## Changes Made

### 1. Root Cargo.toml

**File**: `/Cargo.toml`

- Commented out classical consensus modules:
  - `substrate/client/consensus/aura`
  - `substrate/client/consensus/babe` (already commented)
  - `substrate/client/consensus/babe/rpc` (already commented)
  - `substrate/client/consensus/beefy`
  - `substrate/client/consensus/beefy/rpc`
  - `substrate/client/consensus/grandpa` (already commented)
  - `substrate/client/consensus/grandpa/rpc` (already commented)

- Commented out classical crypto dependencies:
  - `ed25519-dalek`
  - `ed25519-zebra`
  - `libsecp256k1`
  - `secp256k1`

### 2. Core Cryptography Module

**File**: `/substrate/primitives/core/src/lib.rs`

- Removed module exports for:
  - `bandersnatch` (experimental)
  - `bls` (experimental)
  - `ecdsa`
  - `ed25519`
  - `sr25519`
  - `paired_crypto` BLS variants

- Kept only:
  - `sphincs` (quantum-safe signatures)
  - `quantum_randomness`
  - `quantum_signature`
  - `crypto_bytes`
  - `paired_crypto` (base functionality)

**Files Deleted**:
- `/substrate/primitives/core/src/ed25519.rs`
- `/substrate/primitives/core/src/sr25519.rs`
- `/substrate/primitives/core/src/ecdsa.rs`
- `/substrate/primitives/core/src/ed25519_stub.rs`
- `/substrate/primitives/core/src/sr25519_stub.rs`
- `/substrate/primitives/core/src/ecdsa_stub.rs`
- `/substrate/primitives/core/src/bandersnatch.rs`

### 3. Core Cargo.toml

**File**: `/substrate/primitives/core/Cargo.toml`

- Commented out dependencies:
  - All Ed25519 related deps
  - All secp256k1/ECDSA related deps
  - Schnorrkel (Sr25519)
  - BLS crypto (`sha2`, `w3f-bls`)
  - Bandersnatch (`ark-vrf`)

- Removed features:
  - `bls-experimental`
  - `bandersnatch-experimental`

### 4. Keystore Updates

**File**: `/substrate/primitives/keystore/src/lib.rs`

- Removed imports for bandersnatch and BLS
- Removed all bandersnatch methods from Keystore trait
- Removed all BLS methods from Keystore trait
- Kept only SPHINCS+ methods

### 5. Application Crypto

**File**: `/substrate/primitives/application-crypto/src/lib.rs`

- Removed module exports for all classical crypto
- Kept only `sphincs` and `sphincs_simple`

**Files Deleted**:
- `/substrate/primitives/application-crypto/src/bandersnatch.rs`
- `/substrate/primitives/application-crypto/src/bls381.rs`
- `/substrate/primitives/application-crypto/src/ecdsa_bls381.rs`

### 6. Build Infrastructure

**New File**: `/build-quantum-only.sh`

Created a build script that:
- Builds only quantum-safe components
- Provides clear documentation of included/excluded features
- Sets appropriate build flags
- Gives usage instructions for quantum-secure nodes

## Quantum Components Retained

1. **SPHINCS+ Signatures**
   - Full implementation in `/substrate/primitives/core/src/sphincs.rs`
   - 64-byte public keys, 49,856-byte signatures
   - NIST standardized post-quantum signature scheme

2. **QKD Integration**
   - KIRQ Hub client in `/substrate/client/network/src/qkd_integration.rs`
   - Toshiba QKD support
   - Quantum transport layer in `/substrate/client/network/src/quantum_transport.rs`

3. **Quantum Randomness**
   - Module in `/substrate/primitives/core/src/quantum_randomness.rs`
   - QKD-derived entropy integration

4. **Proof of Coherence**
   - Novel quantum consensus in `/substrate/frame/proof-of-coherence/`
   - Tonnetz harmonic framework

5. **Quantum Crypto Pallet**
   - Located in `/substrate/frame/quantum-crypto/`
   - Manages quantum keys and entropy

## Building

To build the quantum-only version:

```bash
cd /home/paraxiom/polkadot-sdk
./build-quantum-only.sh
```

## Important Notes

1. **Incompatibility**: This build is incompatible with standard Polkadot/Substrate networks that use classical cryptography.

2. **Performance**: SPHINCS+ signatures are significantly larger than classical signatures (49KB vs 64 bytes), which impacts block size and network performance.

3. **Hardware Requirements**: QKD integration requires compatible quantum hardware or access to KIRQ Hub services.

4. **Migration Path**: Networks must coordinate migration to ensure all nodes upgrade simultaneously.

## Future Work

1. Consider adding additional NIST PQC algorithms:
   - Dilithium (signatures)
   - Kyber (key encapsulation)
   - Falcon (signatures)

2. Optimize SPHINCS+ parameters for blockchain use cases

3. Implement quantum-safe key derivation schemes

4. Add quantum-safe consensus mechanisms beyond Proof of Coherence