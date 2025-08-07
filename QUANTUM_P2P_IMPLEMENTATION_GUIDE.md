# Quantum P2P Implementation Guide
## Living Document - Last Updated: August 7, 2025

### 🎯 Overview
This guide tracks the implementation of quantum-safe P2P networking in Polkadot SDK, replacing classical cryptography with QKD-based security.

### 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Application   │     │  Bootstrap   │     │   QKD Device    │
│     Layer       │     │    Node      │     │  (Toshiba/KIRQ) │
└────────┬────────┘     └──────┬───────┘     └────────┬─────────┘
         │                     │                       │
┌────────▼────────────────────▼───────────────────────▼─────────┐
│                    QuantumTransport Layer                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐    │
│  │   Quantum   │  │     QKD      │  │   Beacon Signal   │    │
│  │  Identity   │  │   Clients    │  │    Processing     │    │
│  └─────────────┘  └──────────────┘  └───────────────────┘    │
└────────────────────────────┬───────────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────────┐
│                         libp2p Core                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐    │
│  │  Transport  │  │   Swarm/     │  │      Yamux        │    │
│  │    Trait    │  │   Network    │  │   Multiplexing    │    │
│  └─────────────┘  └──────────────┘  └───────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 📁 Key Components

#### 1. **QuantumTransport** (`substrate/client/network/src/quantum_transport.rs`)
- **Purpose**: Wraps existing transports with QKD capabilities
- **Status**: Core implemented, needs type fixes
- **Key Methods**:
  - `dial()`: Initiates quantum-secured connection
  - `listen_on()`: Creates quantum-aware listener
  - `poll()`: Handles async transport events

#### 2. **QKD Clients** (`substrate/client/network/src/qkd_integration.rs`)
- **KirqHubClient**: Cloud-based quantum entropy
- **ToshibaQkdClient**: Direct hardware integration
- **HybridQkdClient**: Automatic fallback logic

#### 3. **Quantum Identity** (`substrate/client/network/types/src/quantum_identity.rs`)
- **Purpose**: SPHINCS+ based peer identity
- **Status**: Implemented, replaces ed25519
- **Usage**: Network peer identification only

### 🔧 Implementation Steps

#### Phase 1: Fix Core Transport (CURRENT)
```rust
// Fix type mismatches in quantum_transport.rs
// Current issue: DialOpts conversion
impl<T> Transport for QuantumTransport<T> {
    type Error = T::Error;
    type ListenerUpgrade = BoxFuture<'static, Result<(T::Output, Option<QuantumKey>), T::Error>>;
    type Dial = BoxFuture<'static, Result<(T::Output, Option<QuantumKey>), T::Error>>;
    
    // TODO: Fix dial() implementation
    // TODO: Fix poll() return type
}
```

#### Phase 2: Bootstrap Node
```rust
// Create quantum bootstrap node
pub struct QuantumBootstrapNode {
    qkd_client: Arc<dyn QkdClient>,
    peer_keys: HashMap<PeerId, QuantumKey>,
    // Serves initial QKD keys to new peers
}
```

#### Phase 3: Stream Encryption
```rust
// Implement QKD-based stream encryption
pub struct QuantumEncryptedStream {
    inner: Box<dyn AsyncRead + AsyncWrite>,
    quantum_key: QuantumKey,
    cipher: Aes256Gcm,
}
```

### 🚀 Quick Start (Once Complete)

1. **Start Bootstrap Node**:
```bash
./target/release/substrate-node \
    --quantum-bootstrap \
    --qkd-endpoint "https://kirq-hub.example.com" \
    --listen-addr "/ip4/0.0.0.0/tcp/30333"
```

2. **Connect Peer Node**:
```bash
./target/release/substrate-node \
    --bootstrap-nodes "/ip4/127.0.0.1/tcp/30333/p2p/QUANTUM_PEER_ID" \
    --quantum-transport \
    --qkd-mode hybrid
```

### 🐛 Troubleshooting

#### Common Issues:
1. **"No QKD link available"**
   - Check QKD client configuration
   - Verify KIRQ Hub connectivity
   - Ensure peer has QKD capability

2. **"Quantum handshake failed"**
   - Check bootstrap node is running
   - Verify network connectivity
   - Check QKD key availability

3. **"Type mismatch in Transport"**
   - Known issue in quantum_transport.rs
   - See Phase 1 implementation steps

### 📊 Progress Tracking

| Component | Status | Notes |
|-----------|--------|-------|
| Quantum Identity | ✅ Complete | SPHINCS+ based |
| QKD Clients | ✅ Complete | KIRQ + Toshiba |
| Transport Wrapper | 🔄 In Progress | Type fixes needed |
| Bootstrap Node | ❌ TODO | Design complete |
| Stream Encryption | ❌ TODO | AES-256-GCM planned |
| NAT Traversal | ❌ TODO | Relay design needed |
| Test Harness | ❌ TODO | QKD simulator planned |

### 🔗 References
- ETSI QKD 014 API: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/
- libp2p Transport trait: https://docs.rs/libp2p/latest/libp2p/trait.Transport.html
- SPHINCS+ specification: https://sphincs.org/

### 📝 Configuration Examples

#### QKD Client Config (JSON)
```json
{
  "qkd": {
    "mode": "hybrid",
    "kirq_hub": {
      "endpoint": "https://api.kirq.com/v1",
      "api_key": "YOUR_API_KEY"
    },
    "toshiba": {
      "alice_endpoint": "https://10.0.0.1:8443",
      "bob_endpoint": "https://10.0.0.2:8443",
      "cert_path": "/etc/qkd/client.crt",
      "key_path": "/etc/qkd/client.key"
    }
  }
}
```

#### Network Topology
```
Bootstrap Node (with QKD)
    ├── Peer A (QKD-enabled)
    ├── Peer B (QKD-enabled)
    └── Peer C (Fallback to PQ crypto)
```

### 🔄 Update Log
- **Aug 7, 2025**: Initial guide creation
- **Aug 7, 2025**: Added quantum identity implementation
- **Aug 7, 2025**: Documented current blockers
- **Aug 7, 2025**: Created quantum_identity module with SPHINCS+
- **Aug 7, 2025**: Fixed MockQkdClient export
- **Aug 7, 2025**: Identified litep2p as not quantum-ready