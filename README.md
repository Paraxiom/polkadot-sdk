# Polkadot SDK - Paraxiom SPHINCS+ Fork

This is a fork of [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) with **SPHINCS+ post-quantum signature** integration for [QuantumHarmony](https://github.com/Paraxiom/quantumharmony).

## What's Different

This fork adds post-quantum cryptographic primitives to Substrate:

### SPHINCS+ Integration
- **64-byte public keys** (SPHINCS+-SHAKE-128f)
- **Deterministic key derivation** from seeds
- Full keystore integration for validator keys
- Aura consensus compatibility

### Key Changes
- `substrate/primitives/core/src/sphincs.rs` - SPHINCS+ signature implementation
- `substrate/primitives/core/src/falcon.rs` - Falcon signature support
- `substrate/primitives/keyring/src/sphincs.rs` - Test keyring for SPHINCS+
- `substrate/primitives/quantum-wrapper/` - Quantum signature wrapper types

### Branch
Use branch: `daily/2025-10-16-sphincs-deterministic-keys`

```toml
[dependencies]
sp-core = { git = "https://github.com/Paraxiom/polkadot-sdk.git", branch = "daily/2025-10-16-sphincs-deterministic-keys" }
```

## Documentation

Additional quantum architecture documentation is in `docs/quantum/`.

## Upstream

Based on Polkadot SDK. See [upstream documentation](https://docs.polkadot.com) for general Substrate/Polkadot development.

## License

Same as upstream: Apache 2.0 / GPL-3.0
