# KIRQ Integration Guide

## Quick Start Integration

### 1. Basic Entropy Request (Python)
```python
import requests
import base64

def get_quantum_entropy(num_bytes=32):
    """Get quantum random bytes from KIRQ"""
    response = requests.get(
        'http://localhost:8001/entropy',
        params={'bytes': num_bytes},
        headers={'X-Quantum-Nonce': f'app-{time.time()}'}
    )
    if response.status_code == 200:
        return base64.b64decode(response.text)
    raise Exception(f"KIRQ error: {response.status_code}")

# Example usage
quantum_random = get_quantum_entropy(64)
```

### 2. Rust Integration
```rust
use reqwest;
use base64;

async fn get_kirq_entropy(bytes: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8001/entropy")
        .query(&[("bytes", bytes)])
        .header("X-Quantum-Nonce", format!("rust-{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()))
        .send()
        .await?;
    
    let encoded = response.text().await?;
    let decoded = base64::decode(encoded)?;
    Ok(decoded)
}
```

### 3. Substrate Pallet Integration
```rust
// In your pallet's lib.rs
use sp_runtime::traits::Zero;
use frame_support::traits::Randomness;

pub trait KirqEntropy {
    fn get_quantum_random(bytes: u32) -> Vec<u8>;
}

impl<T: Config> Pallet<T> {
    pub fn use_quantum_randomness() -> DispatchResult {
        // Get 32 bytes of quantum entropy
        let quantum_bytes = T::KirqSource::get_quantum_random(32);
        
        // Use for secure operations
        let random_seed = H256::from_slice(&quantum_bytes[..32]);
        
        // Store proof on-chain
        QuantumProofs::<T>::insert(&random_seed, frame_system::Pallet::<T>::block_number());
        
        Ok(())
    }
}
```

### 4. JavaScript/TypeScript Integration
```typescript
import axios from 'axios';

class KirqClient {
    private baseUrl: string = 'http://localhost:8001';
    
    async getEntropy(bytes: number = 32): Promise<Uint8Array> {
        const response = await axios.get(`${this.baseUrl}/entropy`, {
            params: { bytes },
            headers: {
                'X-Quantum-Nonce': `js-${Date.now()}`
            }
        });
        
        // Decode base64 response
        const decoded = atob(response.data);
        const uint8Array = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            uint8Array[i] = decoded.charCodeAt(i);
        }
        return uint8Array;
    }
    
    async verifyAttestation(proof: string): Promise<boolean> {
        const response = await axios.post(`${this.baseUrl}/verify`, {
            proof
        });
        return response.data.valid;
    }
}
```

## Advanced Integration

### Streaming Entropy (WebSocket)
```javascript
const ws = new WebSocket('ws://localhost:8001/stream');

ws.onopen = () => {
    ws.send(JSON.stringify({
        type: 'subscribe',
        bytes_per_second: 1000
    }));
};

ws.onmessage = (event) => {
    const quantum_data = JSON.parse(event.data);
    // Process streaming quantum entropy
    processQuantumStream(quantum_data.entropy);
};
```

### Mixing Custom Entropy
```python
def mix_with_quantum(user_entropy: bytes) -> bytes:
    """Mix user entropy with quantum sources"""
    response = requests.post(
        'http://localhost:8001/mix',
        json={
            'user_entropy': base64.b64encode(user_entropy).decode(),
            'mixing_rounds': 3
        }
    )
    return base64.b64decode(response.json()['mixed_entropy'])
```

## Security Best Practices

### 1. Nonce Management
Always use unique nonces to prevent replay attacks:
```python
import uuid
nonce = f"{app_id}-{uuid.uuid4()}-{time.time()}"
```

### 2. Rate Limiting
Implement client-side rate limiting:
```python
from time import time, sleep

class RateLimitedKirq:
    def __init__(self, max_requests_per_second=10):
        self.max_rps = max_requests_per_second
        self.last_request = 0
    
    def get_entropy(self, bytes=32):
        # Enforce rate limit
        elapsed = time() - self.last_request
        if elapsed < 1.0 / self.max_rps:
            sleep(1.0 / self.max_rps - elapsed)
        
        self.last_request = time()
        return get_quantum_entropy(bytes)
```

### 3. Attestation Verification
Always verify STARK proofs:
```rust
fn verify_quantum_source(entropy: &[u8], proof: &StarkProof) -> bool {
    // Verify the STARK proof
    let public_input = hash(entropy);
    stark_verifier::verify(proof, public_input)
}
```

## Integration Patterns

### Pattern 1: Quantum Seed Generation
```python
def generate_quantum_seed():
    """Generate cryptographic seed from quantum source"""
    # Get 64 bytes for extra security
    quantum_bytes = get_quantum_entropy(64)
    
    # Apply KDF for uniform distribution
    seed = hashlib.pbkdf2_hmac(
        'sha3_256',
        quantum_bytes,
        b'quantum-seed-v1',
        iterations=100000
    )
    return seed
```

### Pattern 2: Quantum Nonce Generation
```rust
pub fn quantum_nonce() -> [u8; 32] {
    let entropy = get_kirq_entropy(32).expect("KIRQ available");
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&entropy[..32]);
    nonce
}
```

### Pattern 3: Distributed Consensus
```go
func quantumConsensus(validators []string) string {
    // Get quantum randomness
    entropy := getKirqEntropy(32)
    
    // Select leader using quantum randomness
    index := binary.BigEndian.Uint32(entropy[:4]) % uint32(len(validators))
    return validators[index]
}
```

## Testing

### Unit Tests
```python
def test_kirq_integration():
    # Mock KIRQ responses for testing
    with requests_mock.Mocker() as m:
        m.get('http://localhost:8001/entropy', 
              text=base64.b64encode(b'test_entropy').decode())
        
        result = get_quantum_entropy(12)
        assert result == b'test_entropy'
```

### Integration Tests
```bash
# Test script
#!/bin/bash

# 1. Check KIRQ health
curl -s http://localhost:8001/health | jq .

# 2. Get entropy
ENTROPY=$(curl -s http://localhost:8001/entropy?bytes=32)
echo "Got entropy: ${#ENTROPY} chars"

# 3. Verify attestation
curl -s http://localhost:8001/attestation | jq .valid
```

## Monitoring

### Metrics to Track
- Entropy consumption rate
- API response times
- Attestation verification success rate
- Source availability

### Example Prometheus Metrics
```python
from prometheus_client import Counter, Histogram

entropy_requests = Counter('kirq_entropy_requests_total', 
                          'Total entropy requests')
entropy_latency = Histogram('kirq_entropy_latency_seconds',
                           'Entropy request latency')

@entropy_latency.time()
def get_monitored_entropy(bytes=32):
    entropy_requests.inc()
    return get_quantum_entropy(bytes)
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if KIRQ is running
   ps aux | grep quantum_rng_kirq_hub
   # Check port
   netstat -tlnp | grep 8001
   ```

2. **Rate Limit Exceeded**
   - Implement exponential backoff
   - Cache entropy when possible
   - Use batch requests

3. **Invalid Attestation**
   - Ensure time sync between systems
   - Verify STARK proof parameters
   - Check for man-in-the-middle attacks

## Support

- **Documentation**: /home/paraxiom/quantum-rng-kirq-hub/docs/
- **Issues**: GitHub QuantumVerseProtocols/quantum-rng-kirq-hub
- **Community**: Discord #kirq-integration