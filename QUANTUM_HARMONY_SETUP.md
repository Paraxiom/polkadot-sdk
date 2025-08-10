# Quantum Harmony Setup Plan

## Current Situation
- **Directory**: `/home/paraxiom/polkadot-sdk` (Keep this name!)
- **Branch**: `quantum-wrapper-clean`
- **Remote**: Your fork at `QuantumVerseProtocols/polkadot-sdk`

## Why Keep "polkadot-sdk" Name?
1. **Upstream Compatibility**: Easy to pull updates from paritytech/polkadot-sdk
2. **Developer Familiarity**: Standard naming helps contributors
3. **Tool Compatibility**: Build scripts expect this structure
4. **Fork Management**: Clear relationship to upstream

## Setup Structure

```
/home/paraxiom/polkadot-sdk/          # Keep this name!
├── substrate/                        # Original substrate (with quantum mods)
│   ├── primitives/
│   │   ├── core/                    # Modified with QuantumHasher
│   │   ├── quantum-wrapper/         # Our quantum wrapper
│   │   └── consensus/poc/           # Proof of Coherence
│   └── frame/                       # Pallets go here
│
├── quantum-extensions/              # All new quantum code
│   ├── pallets/
│   │   ├── pallet-quantum-crypto/
│   │   ├── pallet-stark-verifier/
│   │   ├── pallet-symmetric-proof/
│   │   └── pallet-poc-consensus/
│   ├── primitives/
│   │   ├── stark-crypto/           # NEW: STARK + Symmetric
│   │   ├── proof-storage/          # NEW: Proof management
│   │   └── quantum-runtime/        # NEW: Runtime traits
│   └── node/
│       └── quantum-node/           # Quantum-enabled node
│
├── quantum-docs/                   # Documentation
│   ├── concepts/
│   ├── architecture/
│   └── implementation/
│
└── scripts/
    ├── build-quantum.sh
    └── test-quantum.sh
```

## Implementation Steps

### Step 1: Create STARK Crypto Primitive
```bash
cd /home/paraxiom/polkadot-sdk
mkdir -p quantum-extensions/primitives/stark-crypto/src
```

### Step 2: Create Symmetric Proof Pallet
```bash
mkdir -p quantum-extensions/pallets/pallet-symmetric-proof/src
```

### Step 3: Create Proof Storage System
```bash
mkdir -p quantum-extensions/primitives/proof-storage/src
```

### Step 4: Set Up Quantum Node
```bash
mkdir -p quantum-extensions/node/quantum-node/src
```

## Git Strategy

1. **Main Development Branch**: `quantum-wrapper-clean`
2. **Feature Branches**: 
   - `feat/stark-crypto`
   - `feat/symmetric-proofs`
   - `feat/proof-storage`

3. **Upstream Sync**:
   ```bash
   # Add upstream remote (if not exists)
   git remote add upstream https://github.com/paritytech/polkadot-sdk.git
   
   # Sync with upstream periodically
   git fetch upstream
   git merge upstream/master
   ```

## Build Configuration

Create `quantum-extensions/Cargo.toml`:
```toml
[workspace]
members = [
    "pallets/*",
    "primitives/*",
    "node/*",
]

[workspace.dependencies]
# Inherit from root workspace
sp-core = { path = "../substrate/primitives/core" }
sp-runtime = { path = "../substrate/primitives/runtime" }
frame-support = { path = "../substrate/frame/support" }
frame-system = { path = "../substrate/frame/system" }

# Quantum specific
winterfell = "0.7"
blake3 = "1.5"
chacha20poly1305 = "0.10"
```

## Next Commands to Run

```bash
# 1. Set up the structure
cd /home/paraxiom/polkadot-sdk
mkdir -p quantum-extensions/{pallets,primitives,node}

# 2. Create STARK crypto module
mkdir -p quantum-extensions/primitives/stark-crypto/src

# 3. Initialize proof storage
mkdir -p quantum-extensions/primitives/proof-storage/src

# 4. Create build script
cat > scripts/build-quantum.sh << 'EOF'
#!/bin/bash
cargo build --release --features quantum
EOF
chmod +x scripts/build-quantum.sh
```

## Project Identity

While keeping the directory name as `polkadot-sdk`, we can establish identity through:
1. **README.md**: Add Quantum Harmony branding
2. **Cargo.toml**: Update package names to `quantum-harmony-*`
3. **Chain Spec**: Use "Quantum Harmony" as network name
4. **Node Binary**: Build as `quantum-harmony` executable

This approach gives us the best of both worlds:
- Technical compatibility with Polkadot SDK
- Clear Quantum Harmony identity
- Easy upstream updates
- Professional fork management