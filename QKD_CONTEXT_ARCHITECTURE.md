# QKD-Driven Context Switching Architecture

## The Problem We're Solving
- Monolithic runtime with 9 pallets is too large (codec error)
- Need to split into smaller contexts
- But contexts need to coordinate - this is where QKD metrics help

## How QKD Metrics Drive the Architecture

### 1. **Context Size Determination**
```rust
// QKD coherence time determines context size
// Longer coherence = can have larger contexts
// Shorter coherence = need smaller, faster-switching contexts

pub fn determine_context_size(qkd_metrics: &QkdMetrics) -> ContextSize {
    let coherence_ns = qkd_metrics.coherence_time;
    
    match coherence_ns {
        c if c > 1000.0 => ContextSize::Large(3),   // 3 pallets per context
        c if c > 100.0 => ContextSize::Medium(2),   // 2 pallets per context  
        _ => ContextSize::Small(1),                 // 1 pallet per context
    }
}
```

### 2. **Context Switching Frequency**
```rust
// QBER determines how often we can switch contexts
// Low QBER = can switch frequently (parallel execution)
// High QBER = must minimize switches (sequential)

pub fn context_switch_strategy(qkd_metrics: &QkdMetrics) -> SwitchStrategy {
    match qkd_metrics.qber {
        q if q < 0.02 => SwitchStrategy::Aggressive {
            // Can afford frequent context switches
            switch_every_n_blocks: 1,
            parallel_contexts: 4,
        },
        q if q < 0.05 => SwitchStrategy::Moderate {
            switch_every_n_blocks: 5,
            parallel_contexts: 2,
        },
        _ => SwitchStrategy::Conservative {
            switch_every_n_blocks: 10,
            parallel_contexts: 1,
        }
    }
}
```

### 3. **Pallet Distribution Based on Entanglement**
```rust
// High entanglement fidelity = can separate dependent pallets
// Low entanglement = must keep dependent pallets together

pub fn distribute_pallets(qkd_metrics: &QkdMetrics) -> Vec<Context> {
    let contexts = if qkd_metrics.entanglement_fidelity > 0.95 {
        // Excellent entanglement - maximum distribution
        vec![
            Context::new("Core", vec![System, Timestamp]),
            Context::new("Money", vec![Balances, TransactionPayment]),
            Context::new("Quantum", vec![QuantumCrypto]),
            Context::new("Consensus", vec![ProofOfCoherence]),
            Context::new("Identity", vec![QuantumAccounts]),
        ]
    } else {
        // Poor entanglement - group related pallets
        vec![
            Context::new("Core", vec![System, Timestamp, Balances]),
            Context::new("Quantum", vec![QuantumCrypto, QuantumAccounts]),
            Context::new("Consensus", vec![ProofOfCoherence, QuantumAura]),
        ]
    };
    
    contexts
}
```

### 4. **Runtime Architecture Based on QKD**

Instead of one big runtime, we have:

```rust
// SCENARIO 1: Excellent QKD metrics
// Coherence: 1000ns, QBER: 1%, Fidelity: 99%
Runtime {
    contexts: [
        MicroRuntime { pallets: [System] },           // 50KB
        MicroRuntime { pallets: [QuantumCrypto] },    // 100KB
        MicroRuntime { pallets: [ProofOfCoherence] }, // 80KB
        // ... each small enough to compile
    ],
    switching: Parallel, // Can run multiple contexts at once
}

// SCENARIO 2: Poor QKD metrics  
// Coherence: 50ns, QBER: 8%, Fidelity: 70%
Runtime {
    contexts: [
        MiniRuntime { pallets: [System, Timestamp, Balances] }, // 150KB
        MiniRuntime { pallets: [All Quantum Pallets] },         // 200KB
    ],
    switching: Sequential, // Must run one at a time
}
```

### 5. **The Key Insight**

**QKD metrics tell us HOW to split the runtime:**

- **High Coherence** → Can have more granular contexts
- **Low QBER** → Can switch contexts frequently  
- **High Entanglement** → Can separate dependent pallets
- **Good Visibility** → Can use quantum channels between contexts

This solves our compilation problem while adapting to quantum hardware capabilities!

### 6. **Immediate Implementation**

```bash
# Based on current KIRQ hub metrics:
# Coherence: ~200ns, QBER: ~3%, Fidelity: ~85%

# We should split into 3 contexts:
1. Core Context: System + Timestamp + Balances
2. Quantum Context: QuantumCrypto + QuantumAccounts  
3. Consensus Context: ProofOfCoherence + QuantumAura + EncryptedPayload

# Each context ~100-150KB vs 400KB+ monolithic
```

This directly solves our "runtime too large" error while using QKD metrics to optimize the split!