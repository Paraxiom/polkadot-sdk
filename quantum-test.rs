#!/usr/bin/env -S cargo +nightly -Zscript

//! Test quantum functionality
//! ```cargo
//! [dependencies]
//! sp-core = { path = "substrate/primitives/core" }
//! ```

use sp_core::{Hasher, blake2_256};

fn main() {
    println!("=== Quantum Harmony Blockchain Test ===\n");
    
    // Test data
    let test_data = b"Hello Quantum World!";
    
    // Test 1: Check if quantum mode is enabled
    let quantum_enabled = std::env::var("QUANTUM_MODE").unwrap_or_default() == "1";
    println!("1. Quantum Mode Enabled: {}", quantum_enabled);
    
    // Test 2: Hash with QuantumHasher
    println!("\n2. Testing QuantumHasher:");
    println!("   Input: {:?}", std::str::from_utf8(test_data).unwrap());
    
    // Since we can't directly use QuantumHasher here, simulate its behavior
    if quantum_enabled {
        // Quantum mode: Would use SHA3/Keccak (quantum-resistant)
        println!("   Mode: Quantum (SHA3/Keccak)");
        println!("   Note: In production, this would use quantum-safe hashing");
    } else {
        // Classical mode: Uses Blake2
        let hash = blake2_256(test_data);
        println!("   Mode: Classical (Blake2)");
        println!("   Hash: 0x{}", hex::encode(hash));
    }
    
    // Test 3: Check for quantum resources
    println!("\n3. Quantum Resource Detection:");
    
    // Check for QKD devices
    let qkd_devices = ["/dev/qkd0", "/dev/quantis0"];
    let mut found_device = false;
    for device in &qkd_devices {
        if std::path::Path::new(device).exists() {
            println!("   ✓ Found QKD device: {}", device);
            found_device = true;
        }
    }
    if !found_device {
        println!("   ✗ No QKD hardware devices found");
    }
    
    // Check entropy levels
    if let Ok(entropy) = std::fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
        if let Ok(level) = entropy.trim().parse::<u32>() {
            println!("   System entropy: {} bits (quantum mode requires > 3000)", level);
            if level > 3000 {
                println!("   ✓ Sufficient entropy for quantum mode");
            } else {
                println!("   ✗ Insufficient entropy for quantum mode");
            }
        }
    }
    
    // Check for quantum network endpoints
    println!("\n4. Quantum Network Endpoints:");
    let endpoints = [
        ("Toshiba Alice", "192.168.0.152:5000"),
        ("Toshiba Bob", "192.168.0.153:5000"),
        ("KIRQ Hub", "127.0.0.1:8080"),
        ("Quantum Bridge", "localhost:9999"),
    ];
    
    for (name, endpoint) in &endpoints {
        // In production, this would actually try to connect
        println!("   {} @ {} - (would check connectivity)", name, endpoint);
    }
    
    // Test 5: Demonstrate STARK proof concept
    println!("\n5. STARK Proof Concept:");
    println!("   In production, every encryption operation would generate a STARK proof");
    println!("   - Proof size: ~100-200KB");
    println!("   - On-chain storage: Only 32-byte hash");
    println!("   - Verification time: ~10-20ms");
    
    // Test 6: Proof of Coherence (PoC) concept
    println!("\n6. Proof of Coherence Consensus:");
    println!("   Block production requires:");
    println!("   - Active QKD hardware");
    println!("   - Coherence time > threshold");
    println!("   - QBER < 11%");
    println!("   - Valid STARK proof of quantum measurement");
    
    println!("\n=== Summary ===");
    if quantum_enabled {
        println!("✓ Quantum mode is ENABLED via environment variable");
        println!("  Set QUANTUM_MODE=1 to enable quantum features");
    } else {
        println!("✗ Quantum mode is DISABLED");
        println!("  Set QUANTUM_MODE=1 to enable quantum features");
    }
    println!("\nThis demonstrates the quantum-classical hybrid approach where:");
    println!("- Quantum resources are used when available");
    println!("- Classical cryptography provides fallback");
    println!("- STARK proofs ensure verifiability");
    println!("- PoC consensus requires quantum hardware");
}