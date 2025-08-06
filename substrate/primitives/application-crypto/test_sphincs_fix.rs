// Test file to verify SPHINCS+ application crypto works without recursive type issues

use sp_application_crypto::sphincs::{Public, Signature, Pair};
use sp_application_crypto::{AppCrypto, RuntimePublic};
use sp_core::crypto::Pair as PairTrait;

#[test]
fn test_sphincs_app_crypto_no_recursion() {
    // This test verifies that the SPHINCS+ types can be used without hitting
    // the recursive type definition issue
    
    // Create a pair
    let seed = sp_core::sphincs::Seed::from([42u8; 48]);
    let pair = Pair::from_seed(&seed);
    
    // Get public key
    let public = pair.public();
    
    // Sign a message
    let message = b"Test message for SPHINCS+";
    let signature = pair.sign(message);
    
    // Verify signature
    assert!(Pair::verify(&signature, message, &public));
    
    // Test that signature is boxed (not on stack)
    let sig_size = std::mem::size_of::<Signature>();
    let expected_box_size = std::mem::size_of::<Box<[u8; 49856]>>();
    println!("Signature wrapper size: {} bytes", sig_size);
    println!("Expected box size: {} bytes", expected_box_size);
    
    // The wrapped signature should be much smaller than the actual signature data
    assert!(sig_size < 100, "Signature should be boxed, not stored inline");
}

#[test] 
fn test_sphincs_runtime_public_interface() {
    // Test the RuntimePublic interface
    let key_type = sp_core::testing::SPHINCS;
    
    // Generate a key pair
    let public = Public::generate_pair(key_type, None);
    
    // Sign a message
    let message = b"Runtime public test";
    if let Some(signature) = public.sign(key_type, &message[..]) {
        // Verify the signature
        assert!(public.verify(&message[..], &signature));
    }
}

fn main() {
    println!("Testing SPHINCS+ application crypto fix...");
    test_sphincs_app_crypto_no_recursion();
    test_sphincs_runtime_public_interface();
    println!("All tests passed!");
}