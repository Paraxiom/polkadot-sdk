# Quantum RNG Architecture for QuantumHarmony Blockchain

## Overview

This document describes the secure quantum random number generation (QRNG) architecture that feeds all cryptographic operations in the QuantumHarmony blockchain, including SPHINCS+, Falcon signatures, and consensus mechanisms.

## Architecture Components

### 1. Quantum Entropy Sources
- **Toshiba QKD Systems** (192.168.0.152/153): Primary source of quantum randomness from photon measurements
- **Crypto4A HSM** (192.168.0.41:8132): Hardware security module with quantum RNG
- **KIRQ Hub** (localhost:8001): Aggregates multiple quantum entropy sources
- **Direct Measurements**: Raw quantum measurements from various devices

### 2. Priority Queue System
- **Purpose**: Orders and prioritizes quantum events by importance
- **Security**: All entropy immediately stored in secure vault upon receipt
- **Endpoints**:
  - Alice Queue: `localhost:5555` (leader nodes)
  - Bob Queue: `localhost:5556` (validator nodes)

### 3. Quantum Vault (Node-side)
- **Location**: `/node/src/quantum_vault.rs`
- **Features**:
  - AES-256-GCM encryption for entropy at rest
  - Zeroization of sensitive data
  - Usage tracking and replay prevention
  - Integration with Crypto4A HSM for master key derivation
  - Emergency sealing capability

### 4. Runtime Integration (no_std)
- **Location**: `/pallets/quantum-crypto/src/quantum_rng_provider.rs`
- **Purpose**: Provides quantum entropy to runtime without using `std`
- **Storage**: On-chain entropy pool with quality metrics

### 5. Host Functions
- **Location**: `/primitives/io/src/quantum_crypto.rs`
- **Purpose**: Bridge between node's vault and runtime's crypto operations
- **Functions**:
  - `quantum_sphincs_seed()`: 32-byte seeds for SPHINCS+ key generation
  - `quantum_falcon_seed()`: 32-byte seeds for Falcon key generation
  - `quantum_sphincs_signing_randomness()`: Randomness for SPHINCS+ signatures
  - `quantum_falcon_nonce()`: 40-byte nonces for Falcon signatures
  - `quantum_consensus_randomness()`: Entropy for leader election

## Data Flow

```
1. Quantum Sources (QKD/HSM/KIRQ)
       ↓
2. Quantum Event Pusher (Python)
       ↓
3. Priority Queue RPC
       ↓
4. Offchain Worker (fetches events)
       ↓
5. Quantum Vault (secure storage)
       ↓
6. Host Functions (node → runtime)
       ↓
7. Cryptographic Operations
   - SPHINCS+ signatures
   - Falcon signatures
   - Leader election
   - Validator shuffling
```

## Security Features

### Vault Security
- **Encryption**: AES-256-GCM with unique nonces
- **Key Management**: Master key derived from HSM
- **Memory Safety**: Zeroization of all sensitive data
- **Access Control**: Purpose-specific entropy channels

### Quality Assurance
- **Minimum Quality Scores**:
  - Key Generation: 90/100
  - Signing Operations: 80/100
  - Consensus: 85/100
- **Source Tracking**: Each entropy segment tagged with source
- **Usage Limits**: Prevent entropy reuse attacks

### Emergency Procedures
- **Vault Sealing**: Emergency shutdown clears all entropy
- **Fallback Mode**: Block hash-based entropy (NOT quantum-secure)
- **Quality Monitoring**: Automatic rejection of low-quality entropy

## Usage Examples

### SPHINCS+ Key Generation
```rust
// In runtime (no_std)
let seed = QuantumRngProvider::<T>::sphincs_key_gen_seed()?;
// seed is guaranteed to be 32 bytes of high-quality quantum entropy
```

### Falcon Signing
```rust
// In runtime (no_std)
let nonce = QuantumRngProvider::<T>::falcon_signing_nonce()?;
// nonce is guaranteed to be 40 bytes of quantum entropy
```

### Leader Election
```rust
// In runtime (no_std)
let randomness = QuantumRngProvider::<T>::consensus_randomness(b"election")?;
// Returns H256 mixed with quantum entropy
```

## Operational Commands

### Start Quantum Pipeline
```bash
./scripts/start_quantum_pipeline.sh
```

### Test Priority Queue
```bash
cargo run --bin quantumharmony -- priority-queue --port 5555
python3 scripts/test_priority_queue.py 5555
```

### Monitor Vault Status
```bash
# Check vault statistics in logs
tail -f quantum_node.log | grep "quantum vault"
```

## Important Notes

1. **No std in Runtime**: All runtime code is `no_std` for deterministic execution
2. **Entropy Conservation**: Each byte of entropy is used only once
3. **Quality Requirements**: Different operations have different quality thresholds
4. **Audit Trail**: All entropy usage is logged for security auditing
5. **Zero Trust**: Even quantum sources are validated before use

## Future Enhancements

1. **TEE Integration**: Run vault in trusted execution environment
2. **Distributed Vault**: Multi-party computation for vault operations
3. **Quantum Attestation**: Cryptographic proofs of quantum origin
4. **Entropy Mixing**: Combine multiple quantum sources cryptographically