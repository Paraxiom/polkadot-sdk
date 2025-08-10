# Quantum Integration Guide

This guide explains how the quantum-safe wrappers integrate with the existing Polkadot SDK.

## Overview

The quantum integration follows these principles:
1. **Intercept crypto operations** - All hash and signature operations check for quantum resources
2. **Fallback to original** - When quantum resources unavailable, use original Substrate crypto
3. **Gradual migration** - Allows smooth transition to quantum-safe systems

## Components

### 1. Quantum Hasher

Located in `substrate/primitives/core/src/hasher.rs`, the `QuantumHasher` provides:

```rust
use sp_core::QuantumHasher;
use hash_db::Hasher;

// Automatically uses quantum-safe hashing when available
let hash = QuantumHasher::hash(b"my data");
```

### 2. Quantum Signatures (PQC)

The system supports dual signature schemes:
- **SPHINCS+** - High security, larger signatures
- **Falcon-512** - Bandwidth-efficient, smaller signatures

Already implemented in:
- `substrate/primitives/core/src/sphincs.rs`
- `substrate/primitives/core/src/falcon.rs`
- `substrate/primitives/core/src/quantum_signature.rs`

### 3. Proof of Coherence (PoC) Consensus

Located in `substrate/primitives/consensus/poc/`, provides:
- Hardware-based authority (no token staking)
- Quantum coherence measurements for block validity
- QKD device integration

### 4. Quantum Wrapper

The `sp-quantum-wrapper` crate provides utility functions for:
- Checking QKD hardware availability
- Fetching quantum keys
- Managing entropy levels

## Usage Example

To use quantum hashing in your runtime:

```rust
// In your runtime/src/lib.rs
use sp_core::QuantumHasher as RuntimeHasher;

// Or define a type alias
type Hasher = sp_core::QuantumHasher;
```

## Configuration

The quantum features can be enabled/disabled via features:

```toml
[dependencies]
sp-quantum-wrapper = { version = "1.0", features = ["quantum"] }
```

## Migration Path

1. **Phase 1**: Deploy with quantum wrappers (current)
   - Quantum checks return false, uses fallback crypto
   - No breaking changes

2. **Phase 2**: Enable quantum hardware
   - Connect QKD devices
   - Quantum checks start returning true
   - Automatic switch to quantum crypto

3. **Phase 3**: Remove classical crypto
   - All nodes using quantum crypto
   - Remove fallback paths

## Testing

To test quantum functionality:

```bash
# Check compilation
cargo check -p sp-quantum-wrapper -p sp-consensus-poc

# Run with quantum features
cargo run --features quantum
```