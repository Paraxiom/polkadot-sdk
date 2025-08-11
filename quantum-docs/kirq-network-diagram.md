# KIRQ Network Integration Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          KIRQ QUANTUM NETWORK ARCHITECTURE                   │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   KIRQ HUB      │
                              │ localhost:8001  │
                              │                 │
                              │ • Entropy Mixer │
                              │ • STARK Proofs  │
                              │ • API Gateway   │
                              └────────┬────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                │                      │                      │
                ▼                      ▼                      ▼
     ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
     │   QKD DEVICES    │   │  CRYPTO4A HSM    │   │ DECENTRALIZED    │
     │                  │   │                  │   │    QRNG          │
     │ Toshiba Alice    │   │ Hardware Security│   │                  │
     │ 192.168.0.152    │   │ Module           │   │ Community Nodes  │
     │                  │   │                  │   │                  │
     │ Toshiba Bob      │   │ Quantum-Safe     │   │ Entropy Sources  │
     │ 192.168.0.153    │   │ Random Generator │   │                  │
     └──────────────────┘   └──────────────────┘   └──────────────────┘

═══════════════════════════════════════════════════════════════════════════════

                              ┌─────────────────┐
                              │ SUBSTRATE NODE  │
                              │ localhost:9944  │
                              │                 │
                              │ • PoC Consensus │
                              │ • PQC Crypto    │
                              │ • Quantum State │
                              └────────┬────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                │                      │                      │
                ▼                      ▼                      ▼
     ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
     │ QUANTUM PALLETS  │   │     DRISTA       │   │  TAO SIGNAL API  │
     │                  │   │  QUANTUM WALLET  │   │                  │
     │ • pallet_quantum │   │                  │   │ api.paraxiom.org │
     │ • pallet_qkd     │   │ • QPP Support    │   │                  │
     │ • pallet_kirq    │   │ • Quantum Tunnel │   │ • Web Gateway    │
     │ • pallet_pqc     │   │ • Desktop GUI    │   │ • FastAPI        │
     └──────────────────┘   └──────────────────┘   └──────────────────┘

═══════════════════════════════════════════════════════════════════════════════

## Data Flow

1. **Entropy Collection**
   ```
   QKD Devices → KIRQ Hub ← Crypto4A HSM
                     ↓
              Entropy Mixing
                     ↓
              STARK Attestation
   ```

2. **Blockchain Integration**
   ```
   KIRQ Hub → Substrate Node → Quantum Pallets
       ↓            ↓              ↓
   API Access   Consensus    State Updates
   ```

3. **Application Layer**
   ```
   Substrate Node → Drista Wallet → User
                 ↘                ↗
                  TAO Signal API
   ```

## Key Integration Points

### KIRQ Hub (Port 8001)
- **Endpoints**:
  - `/entropy` - Get quantum random bytes
  - `/health` - System status
  - `/attestation` - STARK proof verification
  - `/sources` - List active entropy sources

### Substrate Node (Port 9944)
- **WebSocket RPC**: ws://localhost:9944
- **Quantum Methods**:
  - `quantum_getEntropy`
  - `qkd_getActiveKeys`
  - `pqc_signTransaction`

### QKD Integration
- **Alice**: 192.168.0.152:5000
- **Bob**: 192.168.0.153:5000
- **Protocol**: ETSI GS QKD 014
- **Key Rate**: ~1000 keys/sec

### Quantum Features
- **Proof of Coherence**: Tonnetz-based consensus
- **Post-Quantum Crypto**: SPHINCS+, Falcon-512, Dilithium
- **Lamport Clocks**: Quantum event ordering
- **Double Ratchet**: Forward secrecy with QKD

## Security Layers

1. **Physical**: QKD hardware, HSM modules
2. **Network**: Quantum-safe TLS, VPN tunnels
3. **Protocol**: STARK proofs, zero-knowledge VRFs
4. **Application**: QPP patterns, quantum signatures

## Performance Metrics

- **Entropy Generation**: 10MB/sec aggregate
- **STARK Proof Time**: <100ms
- **Block Time**: 6 seconds
- **TPS**: 1000+ with quantum security