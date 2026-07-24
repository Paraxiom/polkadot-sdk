# Paraxiom Modifications to polkadot-sdk

**Fork**: `Paraxiom/polkadot-sdk`
**Branch**: `daily/2025-10-16-sphincs-deterministic-keys`
**Pinned commit**: `624ba59e2ddb15a2ee62f75522ec1de125ff304f` (branch tip; quantumharmony Cargo.lock pins this rev)
**Upstream base**: `e007db09171dd5248f5d8663a56be679b92fdbe7` (paritytech master, 2025-07-18, PR #9262)
**Last updated**: 2026-07-24 (fork-vs-vanilla audit)

---

## Summary

This fork adds **SPHINCS+-SHAKE-256f-simple** post-quantum signature support to Substrate, enabling QuantumHarmony's post-quantum BFT consensus.

Full divergence from vanilla (audited 2026-07-24, `git diff e007db09..624ba59e`): **80 Paraxiom commits, 309 files changed, +47,353 / −9,022 lines**. Upstream master had advanced 1,195 commits past the fork base as of the audit date. The sections below describe the load-bearing modifications, not every touched file.

## Key Modifications

### Core SPHINCS+ Integration
- **`substrate/primitives/core/src/sphincs.rs`** — SPHINCS+ keytype module: `Public` (64 bytes), `Pair` (128-byte secret), `Signature` (49,856 bytes), `SignatureWithPublic` (sig + pubkey = 49,920 bytes). Deterministic key caching for dev mode.
- **`substrate/client/consensus/aura/src/standalone.rs`** — Aura seal verification modified to verify SPHINCS+ signatures via `P::verify(&sig, pre_hash, expected_author)`. No bypass — strict verification since commit `f7ff69b6`.

### PQC Networking (currently DISABLED in production)
- **`substrate/client/network/src/pqc_authenticator.rs`** — Kyber-1024 + Falcon-1024 handshake for PQC transport. Known bug: concurrent initiator/responder race condition drops the stream. Disabled via `DISABLE_PQC_TRANSPORT=1`.
- **`substrate/client/network/src/transport.rs`** — PostQuantum transport integration.
- **`substrate/client/network/src/service.rs`** — PQC identity override, keepalive/idle timeout bumps.
- **`substrate/client/network/src/protocol/notifications/handler.rs`** — V1Lazy to V1 multistream-select fix for inbound PQC connections.

### Proof-of-Coherence Finality
- `substrate/frame/proof-of-coherence/src/types.rs`: `MAX_VOTES_PER_CERTIFICATE` 100 → 256
  (2026-07-08 — 100 capped clean finality at N=149; certificates are quorum-trimmed node-side)
- **`substrate/frame/proof-of-coherence/src/types.rs`** — `MAX_SIGNATURE_SIZE` bumped from 1,500 to 50,000 to accommodate SPHINCS+ vote signatures.
- **`substrate/frame/proof-of-coherence/src/lib.rs`** — Genesis builder restored (2026-06-01): `GenesisConfig` populates `Validators` from a chainspec-provided `initial_validators: Vec<AccountId>`. Without this, every fresh chain bootstrap leaves `Validators` empty, finality stalls until a sudo recovery (the 2026-05-28 testnet incident — Paraxiom/quantumharmony#33). The earlier "TODO: Fix genesis config serde issue" was the `#[serde(skip)]` PhantomData field acting without explicit serde derives; the fix drops the PhantomData entirely since `T` is already bound via the `Vec<T::AccountId>` field.

### Block Hashing
- Account derivation uses Keccak-256 (via `QuantumHasher`) instead of Blake2b-256 for quantum resistance.

### Benchmarking
- **`substrate/utils/frame/benchmarking-cli/`** — SPHINCS+ support in benchmarking CLI.
- **`substrate/frame/benchmarking/src/baseline.rs`** — Updated for PQ signature sizes.

### Other
- **`substrate/frame/identity/src/lib.rs`** — Identity pallet adjustments for larger key sizes.
- **`substrate/frame/staking/src/lib.rs`** — Staking adjustments (note: staking pallet not active in QH production).
- **`substrate/client/sysinfo/src/sysinfo.rs`** — System info adjustments.

## Commit History (most recent 28 of 80 Paraxiom commits)

Full list: `git log --oneline e007db09..624ba59e`. Recent notable commits since this list was drawn up: `c20b6a4d` (preserve session_keys in PqcStream post-handshake), `3c889e86` (restore PoC genesis builder, PR #1), `c4a7daa1` (drop unused pqc_kyber dep, PR #2), `624ba59e` (MAX_VOTES_PER_CERTIFICATE 100 → 256).

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

This fork uses `Paraxiom/parity-scale-codec` for SCALE encoding of `SignatureWithPublic` (49,920 bytes). The codec fork's only functional change vs upstream v3.7.5 is `INITIAL_PREALLOCATION` raised 16 KiB → 256 KiB so large SPHINCS+ values decode without repeated reallocation (vanilla codec would still decode them correctly, just slower); the remaining fork commits are documentation (`AUDIT_CERTIFICATE.md`) and diagnostics (`unreachable!` → descriptive `panic!`).

## Known Issues in This Fork

1. **PQC transport race condition** (`pqc_authenticator.rs`) — concurrent initiator+responder handshake drops stream. Production workaround: `DISABLE_PQC_TRANSPORT=1`.
2. **Aura seal verification debug logging** (commits `f22e20b`, `bf83071`) — debug/diagnostic commits still in history. The bypass was removed in `f7ff69b` — strict verification is the current state.
3. **Downstream mixed sdk lineages** (quantumharmony `Cargo.lock`, found in the 2026-07-24 audit) — the node's dependency graph resolves 229 crates from this fork (sp-core v28) **plus 34 crates from vanilla paritytech `release-polkadot-v1.1.0`** (a second `sp-core` v21, `frame-support`, `frame-system`) and a crates.io `sp-core` v31. Some dependency still pulls vanilla v1.1.0 primitives; trace with `cargo tree -i sp-core@21.0.0` in quantumharmony and unify.
