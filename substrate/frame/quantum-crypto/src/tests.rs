//! Unit tests for the quantum-crypto pallet

use super::*;
use frame_support::{assert_ok, traits::ConstU32, BoundedVec};
use sp_core::H256;
use crate::mock::*;
use crate::pallet::*;

#[test]
fn test_hardware_registration() {
    new_test_ext().execute_with(|| {
        let device_id = H256::from_low_u64_be(1);
        let manufacturer = BoundedVec::<u8, ConstU32<32>>::try_from(b"Toshiba".to_vec()).unwrap();
        let model = BoundedVec::<u8, ConstU32<32>>::try_from(b"QKD-1000".to_vec()).unwrap();
        let serial = BoundedVec::<u8, ConstU32<64>>::try_from(b"SN12345".to_vec()).unwrap();
        let cert = BoundedVec::<u8, ConstU32<4096>>::try_from(vec![1u8; 100]).unwrap();
        let public_key = [2u8; 32];
        
        // Register hardware
        assert_ok!(QuantumCrypto::register_quantum_hardware(
            RuntimeOrigin::signed(1),
            device_id,
            manufacturer.clone(),
            model,
            serial,
            cert,
            public_key,
            1000, // max_key_rate
            50,   // min_qber
        ));
        
        // Check storage
        let stored = HardwareRegistry::<Test>::get(device_id).unwrap();
        assert_eq!(stored.manufacturer, manufacturer);
        assert_eq!(NodeHardware::<Test>::get(1), Some(device_id));
    });
}

#[test]
fn test_entropy_provision() {
    new_test_ext().execute_with(|| {
        // First register hardware
        let device_id = H256::from_low_u64_be(1);
        assert_ok!(QuantumCrypto::register_quantum_hardware(
            RuntimeOrigin::signed(1),
            device_id,
            BoundedVec::try_from(b"Test".to_vec()).unwrap(),
            BoundedVec::try_from(b"Model".to_vec()).unwrap(),
            BoundedVec::try_from(b"Serial".to_vec()).unwrap(),
            BoundedVec::try_from(vec![1u8; 100]).unwrap(),
            [2u8; 32],
            1000,
            50,
        ));
        
        // Provide entropy  
        let entropy = BoundedVec::<u8, MaxEntropyPoolSize>::try_from(vec![42u8; 32]).unwrap();
        assert_ok!(QuantumCrypto::provide_quantum_entropy(
            RuntimeOrigin::signed(1),
            entropy.clone(),
            0, // QuantumRng source
        ));
        
        // Check storage
        let pool = crate::EntropyPoolStorage::<Test>::get();
        assert!(pool.entropy.len() > 0);
    });
}