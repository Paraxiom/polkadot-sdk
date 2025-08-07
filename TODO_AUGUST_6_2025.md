# TODO for August 6, 2025 - Polkadot SDK Quantum Integration

## Critical Issues to Resolve

### 1. Build Dependencies
- [ ] Fix `pallet-revive` secp256k1 dependency issue
  - Either remove pallet-revive from workspace members
  - Or create quantum-safe stub for secp256k1 (not recommended)
  - Update `/substrate/frame/revive/Cargo.toml` to remove secp256k1 references

### 2. Complete Quantum Cryptography Implementations

#### SPHINCS+ Implementation
- [ ] Replace placeholder verification in `/substrate/primitives/core/src/sphincs.rs:309`
- [ ] Integrate actual SPHINCS+ library (e.g., sphincsplus crate)
- [ ] Add proper error handling for signature verification
- [ ] Test with NIST test vectors

#### Falcon-512 Implementation  
- [ ] Implement actual key generation in `/substrate/primitives/core/src/falcon.rs:224`
- [ ] Implement actual signing in `/substrate/primitives/core/src/falcon.rs:234`
- [ ] Implement actual verification in `/substrate/primitives/core/src/falcon.rs:248`
- [ ] Implement key derivation from seed in `/substrate/primitives/core/src/falcon.rs:269`
- [ ] Add Falcon-512 test suite

### 3. Quantum Transport Layer
- [ ] Complete type system integration in `/substrate/client/network/src/transport.rs:100`
- [ ] Add bandwidth tracking wrapper in `/substrate/client/network/src/transport.rs:35`
- [ ] Integrate with libp2p transport layer properly

### 4. QKD Integration
- [ ] Implement Toshiba QKD negotiation in `/substrate/client/network/src/qkd_integration.rs:119`
- [ ] Add KIRQ Hub authentication
- [ ] Create QKD key rotation schedule
- [ ] Add fallback mechanism for QKD unavailability

### 5. Keystore Updates
- [ ] Complete SPHINCS+ keystore methods in `/substrate/client/keystore/src/local.rs:343`
- [ ] Add secure key storage for large SPHINCS+ keys (49KB signatures)
- [ ] Implement key backup/recovery for quantum keys

## Build and Testing

### 6. Fix Compilation
- [ ] Run `./build-quantum-only.sh` and resolve all errors
- [ ] Create CI pipeline for quantum-only builds
- [ ] Document any additional pallets that need exclusion

### 7. Integration Testing
- [ ] Create quantum signature benchmarks
- [ ] Test network performance with 49KB SPHINCS+ signatures
- [ ] Verify Proof of Coherence consensus operation
- [ ] Test QKD entropy integration

## Documentation

### 8. Update Documentation
- [ ] Document how to run quantum-only nodes
- [ ] Create migration guide from classical to quantum crypto
- [ ] Document hardware requirements for QKD
- [ ] Update README with quantum build instructions

## QuantumHarmony Integration Preparation

### 9. Pre-Integration Tasks
- [ ] Verify all quantum primitives are working
- [ ] Ensure clean compilation with no TODOs in critical paths
- [ ] Performance baseline with quantum signatures
- [ ] Security audit of quantum implementations

### 10. Known Limitations to Document
- [ ] SPHINCS+ signature size impact (49KB vs 64 bytes)
- [ ] Network bandwidth requirements increase
- [ ] Hardware QKD dependency for full security
- [ ] Incompatibility with classical Polkadot networks

## Priority Order
1. Fix build issues (items 1, 6)
2. Complete crypto implementations (items 2, 5)
3. Network layer integration (items 3, 4)
4. Testing and documentation (items 7, 8)
5. QuantumHarmony preparation (items 9, 10)

## Notes
- The quantum-only build intentionally removes all classical cryptography for security
- This makes the SDK incompatible with standard Polkadot/Substrate networks
- All nodes in a network must use the same quantum configuration
- Consider adding more NIST PQC algorithms (Dilithium, Kyber) in the future