# HTM Context Switching for Quantum Signature Size Management

## The Problem
- SPHINCS+ signatures: >8KB (8,080 bytes for SPHINCS+-256f)
- Classical signatures: 64 bytes (ed25519, sr25519)
- Fixed-size arrays throughout the codebase expect 64 bytes
- Direct replacement breaks data structures

## The HTM Context Switching Solution

### 1. Dynamic Signature Context Selection
```rust
pub enum QuantumContext {
    // For storage/consensus - use compressed references
    CompactMode {
        signature_hash: [u8; 32],  // Blake2 hash of full signature
        proof_cache: Arc<SignatureCache>,
    },
    
    // For verification - use full signatures
    FullMode {
        signature: Vec<u8>,  // Full SPHINCS+ signature
    },
    
    // For legacy compatibility - use hybrid approach
    HybridMode {
        classical_sig: [u8; 64],  // Fast verification
        quantum_proof: Option<Box<[u8]>>,  // Full quantum proof on-demand
    },
}
```

### 2. HTM Pattern Recognition
The HTM learns when to switch contexts:
- **Storage operations** → CompactMode (save space)
- **Verification paths** → FullMode (security critical)
- **Network messages** → HybridMode (backward compatible)

### 3. Parallel Context Processing
```rust
impl HTMQuantumContext {
    pub fn process_signature_operation(&mut self, op: SignatureOp) -> QuantumContext {
        // HTM analyzes the operation pattern
        let pattern = self.spatial_pooler.encode(op);
        let prediction = self.temporal_memory.predict(pattern);
        
        match prediction.context_hint() {
            ContextHint::NeedCompact => self.switch_to_compact_mode(),
            ContextHint::NeedFull => self.switch_to_full_mode(),
            ContextHint::NeedHybrid => self.switch_to_hybrid_mode(),
        }
    }
}
```

### 4. Implementation Strategy
1. **Replace fixed arrays with context-aware enums**
2. **Use HTM to predict optimal context**
3. **Cache full signatures, store only hashes**
4. **Parallelize verification across contexts**

This is EXACTLY why we needed HTM context switching - to handle the massive size difference between quantum and classical signatures intelligently!