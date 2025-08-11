# Polkadot-JS Setup for Quantum Harmony Chain

## Quick Connect

1. **Open Polkadot-JS Apps**: https://polkadot.js.org/apps/

2. **Connect to Quantum Chain**:
   - Click on the network dropdown (top left)
   - Select "Development" > "Custom"
   - Enter WebSocket endpoint: `ws://192.168.0.154:9944`
   - Click "Switch"

## Running Quantum Substrate Node

The quantum-enhanced substrate node is already running:
```bash
# Process: substrate-node-quantum
# PID: 2575841
# WebSocket: ws://192.168.0.154:9944
# P2P: 30333
# Options: --dev --rpc-external --rpc-cors=all --rpc-methods=unsafe
```

## Custom Types for Quantum Features

Add these custom types in Settings > Developer:

```json
{
  "QuantumProof": {
    "stark_proof": "Vec<u8>",
    "quantum_signature": "Option<Vec<u8>>",
    "entropy_source": "Text",
    "timestamp": "u64"
  },
  "QuantumAccount": {
    "classical_key": "AccountId",
    "quantum_key": "Option<Vec<u8>>",
    "pq_signature": "Vec<u8>",
    "coherence_score": "u32"
  },
  "QKDKey": {
    "alice": "AccountId",
    "bob": "AccountId",
    "key_id": "H256",
    "creation_time": "u64",
    "usage_count": "u32"
  },
  "KIRQEntropy": {
    "source": "Text",
    "entropy": "H256",
    "proof": "QuantumProof"
  }
}
```

## Available Quantum Pallets

- **pallet_quantum**: Core quantum functionality
- **pallet_qkd**: Quantum Key Distribution
- **pallet_kirq**: KIRQ entropy integration
- **pallet_pqc**: Post-quantum cryptography

## Testing Quantum Features

1. **Check KIRQ Connection**:
   - Developer > Chain state > quantum > kirqStatus()
   - Should show: `Connected` with latest entropy hash

2. **View Quantum Accounts**:
   - Developer > Chain state > quantum > quantumAccounts()
   - Shows accounts with quantum enhancements

3. **Submit Quantum Transaction**:
   - Developer > Extrinsics > quantum > submitWithQuantumProof()
   - Automatically uses KIRQ entropy

## Monitoring Quantum Metrics

- **Coherence Score**: Network > Explorer > Latest blocks > Quantum coherence
- **Entropy Usage**: Developer > Chain state > kirq > entropyUsage()
- **QKD Keys**: Developer > Chain state > qkd > activeKeys()

## Troubleshooting

If connection fails:
1. Verify node is running: `ps aux | grep substrate-node-quantum`
2. Check WebSocket: `curl http://192.168.0.154:9944`
3. Ensure KIRQ hub is active: `curl http://localhost:8001/health`

## External Connections

- **KIRQ API**: http://localhost:8001
- **Quantum Wallet**: Running on port (check with wallet team)
- **TAO Signal Agent**: https://api.paraxiom.org

## Development Mode Features

With `--rpc-methods=unsafe`, you can:
- Force produce blocks
- Rotate keys
- Access raw storage
- Submit unsigned extrinsics

⚠️ **Security Note**: These unsafe methods are for development only!