#!/bin/bash

echo "=== Quantum Harmony Blockchain Demo ==="
echo
echo "This demonstrates the quantum-classical hybrid blockchain architecture"
echo

# Check quantum mode
if [ "$QUANTUM_MODE" = "1" ]; then
    echo "✓ QUANTUM MODE ENABLED"
    HASHER="SHA3/Keccak (Quantum-Resistant)"
else
    echo "✗ Quantum mode disabled (set QUANTUM_MODE=1 to enable)"
    HASHER="Blake2 (Classical)"
fi

echo
echo "1. QUANTUM DETECTION SYSTEM:"
echo "   Checking for quantum resources..."

# Check for QKD devices
echo "   - QKD Hardware:"
if [ -e /dev/qkd0 ] || [ -e /dev/quantis0 ]; then
    echo "     ✓ QKD device detected"
else
    echo "     ✗ No QKD devices found (/dev/qkd0, /dev/quantis0)"
fi

# Check entropy
if [ -f /proc/sys/kernel/random/entropy_avail ]; then
    ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
    echo "   - System Entropy: $ENTROPY bits"
    if [ $ENTROPY -gt 3000 ]; then
        echo "     ✓ Sufficient for quantum mode (> 3000 bits)"
    else
        echo "     ✗ Insufficient for quantum mode (need > 3000 bits)"
    fi
fi

# Check for quantum network endpoints
echo "   - Quantum Network Endpoints:"
echo "     • Toshiba QKD Alice: 192.168.0.152:5000"
echo "     • Toshiba QKD Bob: 192.168.0.153:5000"
echo "     • KIRQ Hub: 127.0.0.1:8080"
echo "     • Quantum Bridge: localhost:9999"

echo
echo "2. CRYPTOGRAPHIC OPERATIONS:"
echo "   Current Hasher: $HASHER"
echo "   Post-Quantum Signatures: SPHINCS+ (8KB) / Falcon-512"
echo "   Key Exchange: QKD (when hardware available)"
echo "   Fallback: Classical Ed25519/Sr25519"

echo
echo "3. STARK PROOF SYSTEM:"
echo "   Every cryptographic operation generates a STARK proof:"
echo "   - Symmetric encryption proofs"
echo "   - Double ratchet evolution proofs"
echo "   - HTM context switching proofs"
echo "   - Proof size: ~100-200KB (stored off-chain)"
echo "   - On-chain: Only 32-byte hash"

echo
echo "4. PROOF OF COHERENCE (PoC) CONSENSUS:"
echo "   Block producers must have:"
echo "   - ✓ Active QKD hardware"
echo "   - ✓ Quantum coherence time > threshold"
echo "   - ✓ QBER < 11%"
echo "   - ✓ Valid STARK proof of quantum state"
echo "   No token staking required!"

echo
echo "5. ARCHITECTURE SUMMARY:"
echo "   ┌─────────────────────────────────────┐"
echo "   │      Quantum Harmony Blockchain      │"
echo "   ├─────────────────────────────────────┤"
echo "   │  Quantum Layer:                     │"
echo "   │  • QKD Hardware Integration         │"
echo "   │  • SPHINCS+/Falcon Signatures       │"
echo "   │  • Quantum Entropy Management       │"
echo "   │  • STARK Proof Generation           │"
echo "   ├─────────────────────────────────────┤"
echo "   │  Classical Fallback:                │"
echo "   │  • Blake2/Ed25519/Sr25519          │"
echo "   │  • Standard Substrate Runtime       │"
echo "   └─────────────────────────────────────┘"

echo
echo "To enable quantum mode:"
echo "  export QUANTUM_MODE=1"
echo
echo "Current status: Development/Testing"
echo "Next steps: Connect real QKD hardware"