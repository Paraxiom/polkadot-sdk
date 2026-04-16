# Paraxiom Modifications to polkadot-sdk

**Fork**: `Paraxiom/polkadot-sdk`
**Branch**: `daily/2025-10-16-sphincs-deterministic-keys`
**Pinned commit**: `5ec59910900e0784cfe8baf6ac376d856fad992c`
**Last updated**: 2026-04-16

---

## Summary

This fork adds **SPHINCS+-SHAKE-256f-simple** post-quantum signature support to Substrate, enabling QuantumHarmony's post-quantum BFT consensus. It modifies 18 files across 28 commits on top of the upstream polkadot-sdk.

## Key Modifications (18 files)

### Core SPHINCS+ Integration
- **`substrate/primitives/core/src/sphincs.rs`** — SPHINCS+ keytype module: `Public` (64 bytes), `Pair` (128-byte secret), `Signature` (49,856 bytes), `SignatureWithPublic` (sig + pubkey = 49,920 bytes). Deterministic key caching for dev mode.
- **`substrate/client/consensus/aura/src/standalone.rs`** — Aura seal verification modified to verify SPHINCS+ signatures via `P::verify(&sig, pre_hash, expected_author)`. No bypass — strict verification since commit `f7ff69b6`.

### PQC Networking (currently DISABLED in production)
- **`substrate/client/network/src/pqc_authenticator.rs`** — Kyber-1024 + Falcon-1024 handshake for PQC transport. Known bug: concurrent initiator/responder race condition drops the stream. Disabled via `DISABLE_PQC_TRANSPORT=1`.
- **`substrate/client/network/src/transport.rs`** — PostQuantum transport integration.
- **`substrate/client/network/src/service.rs`** — PQC identity override, keepalive/idle timeout bumps.
- **`substrate/client/network/src/protocol/notifications/handler.rs`** — V1Lazy to V1 multistream-select fix for inbound PQC connections.

### Proof-of-Coherence Finality
- **`substrate/frame/proof-of-coherence/src/types.rs`** — `MAX_SIGNATURE_SIZE` bumped from 1,500 to 50,000 to accommodate SPHINCS+ vote signatures.

### Block Hashing
- Account derivation uses Keccak-256 (via `QuantumHasher`) instead of Blake2b-256 for quantum resistance.

### Benchmarking
- **`substrate/utils/frame/benchmarking-cli/`** — SPHINCS+ support in benchmarking CLI.
- **`substrate/frame/benchmarking/src/baseline.rs`** — Updated for PQ signature sizes.

### Other
- **`substrate/frame/identity/src/lib.rs`** — Identity pallet adjustments for larger key sizes.
- **`substrate/frame/staking/src/lib.rs`** — Staking adjustments (note: staking pallet not active in QH production).
- **`substrate/client/sysinfo/src/sysinfo.rs`** — System info adjustments.

## Commit History (28 Paraxiom-specific commits)

```
5ec5991 feat(poc): Phase 7 — bump MAX_SIGNATURE_SIZE for SPHINCS+ votes
f7ff69b fix(aura): REMOVE seal verification bypass — strict SPHINCS+ verification
f22e20b debug(sphincs): add sign self-test to identify keypair mismatch
bf83071 fix(aura): bypass SPHINCS+ seal verification + add diagnostics
8801e1e Fix inbound PQC connections: V1Lazy → V1 multistream-select
ba26009 Increase keepalive/idle timeouts for PQC transport compatibility
3b294f0 fix: override local_peer_id with PQC identity when PostQuantum transport is active
2d0b403 fix: PQC transport PeerId mismatch causing silent connection drops
db9fe14 feat: complete SPHINCS+ migration for benchmarking CLI
b0a5209 Use git URL for parity-scale-codec instead of local path
9e66325 Clean up for public release
ed4cb3a Post-quantum network layer enhancements
a4dcac8 feat(sphincs): Enhanced SPHINCS+ support for QuantumHarmony
0b2cb84 Improve Proof of Coherence finalization logging
c5acfda Add debugging and improvements for distributed validator network
fdc6223 Fix SPHINCS+ signature verification for cross-validator block import
19748dc fix(sp-core): Add deterministic SPHINCS+ key caching for dev mode
66a7171 Phase 4: BoundedVec Implementation for Quantum Finality Types
0ed2eb5 Phase 3: Quantum Coherence Finality - Runtime Integration
abe784f feat: Phase 2A - STARK proofs + CoherenceVote types for quantum finality
665165c Fix SPHINCS+ deterministic key generation via PQClean FFI
e9e005d feat: Replace blake2_256 with SHA3 for SPHINCS+ account derivation
d2a376c feat: Implement VRF support for SPHINCS+ using signature-based pseudo-VRF
f78a75e fix: Restore SHA3-256 for quantum-resistant PeerId generation
ad039b6 fix: Resolve merge conflict in quantum_identity.rs - keep Blake2
aadecaa Revert "feat: Replace Blake2 with SHA3 for full quantum resistance"
f73e23b feat: Replace Blake2 with SHA3 for full quantum resistance
63af74f fix: Replace GRANDPA panic stubs with no-op implementation
6328b12 feat: Implement secure QKD key storage
```

## Dependency

This fork requires `Paraxiom/parity-scale-codec` for SCALE encoding of `SignatureWithPublic` (49,920 bytes). Standard parity-scale-codec cannot encode the custom `MultiSignature::SphincsPlus` variant.

## Known Issues in This Fork

1. **PQC transport race condition** (`pqc_authenticator.rs`) — concurrent initiator+responder handshake drops stream. Production workaround: `DISABLE_PQC_TRANSPORT=1`.
2. **Aura seal verification debug logging** (commits `f22e20b`, `bf83071`) — debug/diagnostic commits still in history. The bypass was removed in `f7ff69b` — strict verification is the current state.
