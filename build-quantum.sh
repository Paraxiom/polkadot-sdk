#!/bin/bash
# Build script for quantum-only components

echo "Building quantum components only..."

# Build quantum pallets
cargo build -p pallet-quantum-crypto --release
cargo build -p pallet-qkd-network --release  
cargo build -p pallet-symmetric-proof --release
cargo build -p pallet-quantum-democracy --release

# Build quantum primitives
cargo build -p stark-crypto --release
cargo build -p proof-storage --release
cargo build -p sp-quantum-wrapper --release

# Build minimal substrate components needed
cargo build -p frame-system --release
cargo build -p frame-support --release
cargo build -p pallet-balances --release
cargo build -p pallet-timestamp --release
cargo build -p pallet-transaction-payment --release

echo "Quantum components built successfully!"