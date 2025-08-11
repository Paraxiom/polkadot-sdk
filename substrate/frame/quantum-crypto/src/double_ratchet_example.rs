//! # Double Ratchet Lamport Example
//!
//! This module demonstrates how to use the Double Ratchet Lamport signatures
//! for post-quantum secure messaging between blockchain nodes.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::dispatch::DispatchResult;
use sp_runtime::traits::Zero;
use sp_std::vec::Vec;

/// Example: Setting up secure communication between two nodes
/// 
/// This example shows how two nodes (Alice and Bob) can establish
/// a quantum-secure communication channel using Double Ratchet with
/// Lamport signatures.
pub fn setup_secure_channel_example<T: crate::Config>() -> DispatchResult {
    // Step 1: Both nodes must have registered quantum hardware
    // This would typically be done during node setup
    
    // Step 2: Generate a shared secret using quantum key distribution
    // In practice, this would come from QKD hardware
    let shared_secret = [0x42; 32]; // Example shared secret
    
    // Step 3: Alice initiates the session
    // This creates Double Ratchet sessions for both parties
    // alice.establish_ratchet_session(bob_account_id, shared_secret)?;
    
    // Step 4: Exchange initial public keys
    // This happens automatically in the establish_ratchet_session call
    
    Ok(())
}

/// Example: Sending a quantum-secure message
pub fn send_secure_message_example<T: crate::Config>() -> DispatchResult {
    // Step 1: Prepare the message
    let message = b"TOP SECRET: Quantum blockchain is operational";
    
    // Step 2: Send the message
    // The pallet will:
    // - Encrypt the message using the current chain key
    // - Sign with the current Lamport key (one-time use)
    // - Generate a new Lamport key pair for the next message
    // - Update the ratchet state
    
    // alice.send_quantum_message(bob_account_id, message)?;
    
    Ok(())
}

/// Example: Receiving and decrypting a message
pub fn receive_secure_message_example<T: crate::Config>() -> DispatchResult {
    // Step 1: Check for pending messages
    // let message_id = get_next_message_id()?;
    
    // Step 2: Receive and decrypt the message
    // The pallet will:
    // - Verify the Lamport signature
    // - Decrypt the message
    // - Update the ratchet state
    // - Rotate keys as needed
    
    // bob.receive_quantum_message(alice_account_id, message_id)?;
    
    Ok(())
}

/// Example: Key rotation and forward secrecy
/// 
/// The Double Ratchet automatically provides:
/// 1. Forward secrecy: Old keys are deleted after use
/// 2. Break-in recovery: Compromise of current keys doesn't affect future messages
/// 3. Post-quantum security: Lamport signatures are quantum-resistant
pub fn demonstrate_forward_secrecy<T: crate::Config>() {
    // Each message automatically rotates keys
    // Old Lamport keys are never reused (one-time signatures)
    // Chain keys are continuously updated
    
    // Even if an attacker obtains the current state,
    // they cannot decrypt past messages (forward secrecy)
    // or forge future messages (each uses a new Lamport key)
}

/// Security properties provided by this implementation:
/// 
/// 1. **Post-Quantum Security**: Lamport signatures are based on hash functions,
///    which are believed to be quantum-resistant.
/// 
/// 2. **Perfect Forward Secrecy**: Each message uses unique keys that are
///    deleted after use.
/// 
/// 3. **Message Authentication**: Each message is signed with a one-time
///    Lamport signature that cannot be forged.
/// 
/// 4. **Replay Protection**: Message counters and the ratchet state prevent
///    replay attacks.
/// 
/// 5. **Out-of-Order Delivery**: The implementation handles messages that
///    arrive out of order (within limits).
/// 
/// 6. **Quantum Entropy**: All randomness comes from quantum sources,
///    ensuring true randomness.

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::mock::{Test, new_test_ext};
    use frame_support::assert_ok;
    
    #[test]
    fn test_full_secure_communication_flow() {
        new_test_ext().execute_with(|| {
            // Test the complete flow from session establishment to message exchange
            // This would require mock accounts and proper test setup
        });
    }
}

/// Performance characteristics:
/// 
/// - **Key Generation**: O(n) where n is the security parameter (256 bits)
/// - **Signing**: O(n) hash operations
/// - **Verification**: O(n) hash operations
/// - **Storage**: Each Lamport key is ~16KB (can be optimized)
/// - **Ratchet Update**: O(1) symmetric operations
/// 
/// The large key size is the main tradeoff for post-quantum security.
/// In practice, keys can be generated on-demand from a seed to reduce storage.