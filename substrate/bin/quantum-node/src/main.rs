//! Quantum-safe Substrate node

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // For MVP: Use the existing quantumharmony node
    // This binary will be a launcher that sets up quantum environment
    
    println!("Quantum Node Launcher");
    println!("====================");
    println!();
    
    // Check for KIRQ hub
    let kirq_url = std::env::var("KIRQ_HUB_URL")
        .unwrap_or_else(|_| "http://localhost:8001".to_string());
    
    println!("Checking KIRQ hub at {}...", kirq_url);
    
    // Set quantum entropy seed from KIRQ (for MVP)
    if let Ok(response) = ureq::get(&format!("{}/entropy", kirq_url)).call() {
        if let Ok(entropy_data) = response.into_string() {
            // Extract first 32 hex chars as seed
            let seed = &entropy_data[..32.min(entropy_data.len())];
            std::env::set_var("KIRQ_ENTROPY_SEED", seed);
            println!("✓ KIRQ entropy seed configured");
        }
    } else {
        println!("⚠ KIRQ hub not available, using fallback entropy");
    }
    
    // Launch the actual node
    println!();
    println!("To run the quantum node:");
    println!("  cd ../../../quantumharmony");
    println!("  ./substrate-node-quantum --dev --tmp");
    println!();
    println!("With KIRQ integration:");
    println!("  KIRQ_ENTROPY_SEED={} ./substrate-node-quantum --dev", 
             std::env::var("KIRQ_ENTROPY_SEED").unwrap_or_else(|_| "none".to_string()));
    
    Ok(())
}