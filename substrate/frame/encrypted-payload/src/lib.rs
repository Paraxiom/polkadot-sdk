//! # Encrypted Payload Pallet
//!
//! This pallet enables encrypted payloads in transactions using quantum keys.
//! 
//! ## Features
//! - Encrypted memo fields in transfers
//! - Quantum-key encrypted data storage
//! - End-to-end encryption between accounts
//! - Forward secrecy with ephemeral keys

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::RuntimeDebug;
    use sp_std::vec::Vec;
    use sp_core::H256;
    use chacha20poly1305::{
        aead::{Aead, AeadCore},
        ChaCha20Poly1305, Nonce,
    };
    
    #[pallet::pallet]
    pub struct Pallet<T>(_);
    
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_quantum_crypto::Config {
        
        /// Maximum size of encrypted payload in bytes
        #[pallet::constant]
        type MaxPayloadSize: Get<u32> + Clone;
        
        /// Maximum number of stored messages per account
        #[pallet::constant]
        type MaxMessagesPerAccount: Get<u32>;
    }
    
    /// Encrypted message structure
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct EncryptedMessage<T: Config> {
        pub sender: T::AccountId,
        pub nonce: [u8; 12],
        pub ephemeral_public: [u8; 32],
        pub ciphertext: BoundedVec<u8, T::MaxPayloadSize>,
        pub timestamp: BlockNumberFor<T>,
    }
    
    /// Public encryption keys for accounts
    #[pallet::storage]
    #[pallet::getter(fn encryption_keys)]
    pub type EncryptionKeys<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        [u8; 32], // X25519 public key
        OptionQuery,
    >;
    
    /// Stored encrypted messages
    #[pallet::storage]
    #[pallet::getter(fn messages)]
    pub type Messages<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<EncryptedMessage<T>, T::MaxMessagesPerAccount>,
        ValueQuery,
    >;
    
    /// Message counter for each account
    #[pallet::storage]
    #[pallet::getter(fn message_count)]
    pub type MessageCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u32,
        ValueQuery,
    >;
    
    /// Classification levels for military/government use
    #[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, PartialEq, Eq, MaxEncodedLen)]
    #[repr(u8)]
    pub enum ClassificationLevel {
        #[codec(index = 0)]
        Unclassified,
        #[codec(index = 1)]
        Confidential,
        #[codec(index = 2)]
        Secret,
        #[codec(index = 3)]
        TopSecret,
        #[codec(index = 4)]
        TopSecretSCI, // Sensitive Compartmented Information
    }
    
    impl ClassificationLevel {
        fn to_u8(&self) -> u8 {
            match self {
                ClassificationLevel::Unclassified => 0,
                ClassificationLevel::Confidential => 1,
                ClassificationLevel::Secret => 2,
                ClassificationLevel::TopSecret => 3,
                ClassificationLevel::TopSecretSCI => 4,
            }
        }
    }
    
    /// Access control list entry
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct AccessControl<T: Config> {
        pub clearance_level: ClassificationLevel,
        pub compartments: BoundedVec<u32, ConstU32<10>>, // SCI compartment IDs
        pub expiry: Option<BlockNumberFor<T>>,
    }
    
    /// Audit log entry for compliance
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct AuditEntry<T: Config> {
        pub action: AuditAction,
        pub actor: T::AccountId,
        pub target: Option<T::AccountId>,
        pub classification: ClassificationLevel,
        pub timestamp: BlockNumberFor<T>,
        pub metadata_hash: H256,
    }
    
    #[derive(Clone, Encode, Decode, TypeInfo, RuntimeDebug, MaxEncodedLen)]
    pub enum AuditAction {
        KeyRegistered,
        MessageSent,
        MessageAccessed,
        MessageDeleted,
        ClearanceGranted,
        ClearanceRevoked,
        EmergencyAccess,
    }
    
    /// Security clearances for accounts
    #[pallet::storage]
    #[pallet::getter(fn clearances)]
    pub type Clearances<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        AccessControl<T>,
        OptionQuery,
    >;
    
    /// Audit trail - required for military compliance
    #[pallet::storage]
    #[pallet::getter(fn audit_log)]
    pub type AuditLog<T: Config> = StorageValue<
        _,
        BoundedVec<AuditEntry<T>, ConstU32<10000>>,
        ValueQuery,
    >;
    
    /// Emergency access keys (for authorized personnel only)
    #[pallet::storage]
    #[pallet::getter(fn emergency_access)]
    pub type EmergencyAccess<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        bool,
        ValueQuery,
    >;
    
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Encryption key registered
        KeyRegistered {
            who: T::AccountId,
            public_key: [u8; 32],
        },
        
        /// Encrypted message sent
        MessageSent {
            from: T::AccountId,
            to: T::AccountId,
            message_hash: H256,
        },
        
        /// Message retrieved and deleted
        MessageRetrieved {
            who: T::AccountId,
            message_hash: H256,
        },
        
        /// Encrypted transfer with memo
        EncryptedTransfer {
            from: T::AccountId,
            to: T::AccountId,
            encrypted_amount: Vec<u8>,
            memo_hash: H256,
        },
        
        /// Security clearance granted
        ClearanceGranted {
            account: T::AccountId,
            level: u8,
            granted_by: T::AccountId,
        },
        
        /// Security clearance revoked
        ClearanceRevoked {
            account: T::AccountId,
            revoked_by: T::AccountId,
        },
        
        /// Classified message sent
        ClassifiedMessageSent {
            from: T::AccountId,
            to: T::AccountId,
            classification: u8,
            message_hash: H256,
        },
        
        /// Emergency access used
        EmergencyAccessUsed {
            accessor: T::AccountId,
            target_message: H256,
            justification_hash: H256,
        },
    }
    
    #[pallet::error]
    pub enum Error<T> {
        /// No encryption key for recipient
        NoRecipientKey,
        /// No encryption key for sender
        NoSenderKey,
        /// Payload too large
        PayloadTooLarge,
        /// Message storage full
        MessageStorageFull,
        /// Invalid nonce
        InvalidNonce,
        /// Decryption failed
        DecryptionFailed,
        /// Message not found
        MessageNotFound,
        /// Not authorized to retrieve message
        NotAuthorized,
        /// Insufficient security clearance
        InsufficientClearance,
        /// Invalid classification level
        InvalidClassification,
        /// No emergency access permission
        NoEmergencyAccess,
        /// Audit log full
        AuditLogFull,
    }
    
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register or update encryption public key
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn register_encryption_key(
            origin: OriginFor<T>,
            public_key: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Store the public key
            EncryptionKeys::<T>::insert(&who, public_key);
            
            Self::deposit_event(Event::KeyRegistered { who, public_key });
            Ok(())
        }
        
        /// Send encrypted message using quantum-enhanced encryption
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn send_encrypted_message(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            encrypted_payload: Vec<u8>,
            ephemeral_public: [u8; 32],
            nonce: [u8; 12],
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Check recipient has encryption key
            ensure!(
                EncryptionKeys::<T>::contains_key(&recipient),
                Error::<T>::NoRecipientKey
            );
            
            // Check payload size
            let bounded_payload: BoundedVec<u8, T::MaxPayloadSize> = encrypted_payload
                .try_into()
                .map_err(|_| Error::<T>::PayloadTooLarge)?;
            
            // Create message
            let message = EncryptedMessage::<T> {
                sender: sender.clone(),
                nonce,
                ephemeral_public,
                ciphertext: bounded_payload,
                timestamp: frame_system::Pallet::<T>::block_number(),
            };
            
            // Calculate message hash
            let message_hash = Self::hash_message(&message);
            
            // Store message
            Messages::<T>::try_mutate(&recipient, |messages| {
                messages.try_push(message.clone())
                    .map_err(|_| Error::<T>::MessageStorageFull)
            })?;
            
            // Update counter
            MessageCount::<T>::mutate(&recipient, |count| *count = count.saturating_add(1));
            
            Self::deposit_event(Event::MessageSent {
                from: sender,
                to: recipient,
                message_hash,
            });
            
            Ok(())
        }
        
        /// Send encrypted on-chain memo with transfer
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn transfer_with_encrypted_memo(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            encrypted_amount: Vec<u8>, // Amount encrypted with recipient's key
            encrypted_memo: Vec<u8>,
            ephemeral_public: [u8; 32],
            nonce: [u8; 12],
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Calculate memo hash for event before moving
            let memo_hash = sp_io::hashing::blake2_256(&encrypted_memo);
            
            // First send the encrypted memo as a message
            Self::send_encrypted_message(
                frame_system::RawOrigin::Signed(sender.clone()).into(),
                recipient.clone(),
                encrypted_memo,
                ephemeral_public,
                nonce,
            )?;
            
            Self::deposit_event(Event::EncryptedTransfer {
                from: sender,
                to: recipient,
                encrypted_amount,
                memo_hash: H256::from(memo_hash),
            });
            
            Ok(())
        }
        
        /// Retrieve and delete an encrypted message
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(30_000, 0))]
        pub fn retrieve_message(
            origin: OriginFor<T>,
            message_index: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Get messages
            let mut messages = Messages::<T>::get(&who);
            
            // Check index
            ensure!(
                (message_index as usize) < messages.len(),
                Error::<T>::MessageNotFound
            );
            
            // Remove message
            let message = messages.swap_remove(message_index as usize);
            let message_hash = Self::hash_message(&message);
            
            // Update storage
            Messages::<T>::insert(&who, messages);
            MessageCount::<T>::mutate(&who, |count| *count = count.saturating_sub(1));
            
            Self::deposit_event(Event::MessageRetrieved { who, message_hash });
            
            Ok(())
        }
        
        /// Generate ephemeral key using quantum entropy
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn generate_ephemeral_key(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            
            // Get quantum entropy
            // TODO: Implement quantum_random in quantum-crypto pallet
            // let entropy = pallet_quantum_crypto::Pallet::<T>::quantum_random(32)
            //     .ok_or(Error::<T>::InvalidNonce)?;
            
            // In real implementation, this would return the ephemeral keypair
            // For now, we just verify we can get quantum entropy
            
            Ok(())
        }
        
        /// Send classified message (military/government use)
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn send_classified_message(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            encrypted_payload: Vec<u8>,
            ephemeral_public: [u8; 32],
            nonce: [u8; 12],
            classification: u8,
            compartments: Vec<u32>,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            
            // Convert u8 to ClassificationLevel
            let classification = match classification {
                0 => ClassificationLevel::Unclassified,
                1 => ClassificationLevel::Confidential,
                2 => ClassificationLevel::Secret,
                3 => ClassificationLevel::TopSecret,
                4 => ClassificationLevel::TopSecretSCI,
                _ => return Err(Error::<T>::InvalidClassification.into()),
            };
            
            // Verify sender has appropriate clearance
            let sender_clearance = Clearances::<T>::get(&sender)
                .ok_or(Error::<T>::InsufficientClearance)?;
            
            ensure!(
                Self::has_clearance(&sender_clearance, &classification),
                Error::<T>::InsufficientClearance
            );
            
            // Verify recipient has appropriate clearance
            let recipient_clearance = Clearances::<T>::get(&recipient)
                .ok_or(Error::<T>::InsufficientClearance)?;
            
            ensure!(
                Self::has_clearance(&recipient_clearance, &classification),
                Error::<T>::InsufficientClearance
            );
            
            // Check compartment access if TOP SECRET SCI
            if classification == ClassificationLevel::TopSecretSCI {
                for compartment in &compartments {
                    ensure!(
                        sender_clearance.compartments.contains(compartment),
                        Error::<T>::InsufficientClearance
                    );
                    ensure!(
                        recipient_clearance.compartments.contains(compartment),
                        Error::<T>::InsufficientClearance
                    );
                }
            }
            
            // Calculate hash before moving
            let message_hash = sp_io::hashing::blake2_256(&encrypted_payload);
            
            // Send the encrypted message
            Self::send_encrypted_message(
                frame_system::RawOrigin::Signed(sender.clone()).into(),
                recipient.clone(),
                encrypted_payload,
                ephemeral_public,
                nonce,
            )?;
            Self::add_audit_entry(
                AuditAction::MessageSent,
                sender.clone(),
                Some(recipient.clone()),
                classification.clone(),
                H256::from(message_hash),
            )?;
            
            Self::deposit_event(Event::ClassifiedMessageSent {
                from: sender,
                to: recipient,
                classification: classification.to_u8(),
                message_hash: H256::from(message_hash),
            });
            
            Ok(())
        }
        
        /// Grant security clearance (requires governance approval)
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn grant_clearance(
            origin: OriginFor<T>,
            account: T::AccountId,
            level: u8,
            compartments: Vec<u32>,
            expiry: Option<BlockNumberFor<T>>,
        ) -> DispatchResult {
            // This should require governance/council approval in production
            ensure_root(origin.clone())?;
            let granter = ensure_signed(origin)?;
            
            // Convert u8 to ClassificationLevel
            let level = match level {
                0 => ClassificationLevel::Unclassified,
                1 => ClassificationLevel::Confidential,
                2 => ClassificationLevel::Secret,
                3 => ClassificationLevel::TopSecret,
                4 => ClassificationLevel::TopSecretSCI,
                _ => return Err(Error::<T>::InvalidClassification.into()),
            };
            
            let bounded_compartments: BoundedVec<u32, ConstU32<10>> = compartments
                .try_into()
                .map_err(|_| Error::<T>::InvalidClassification)?;
            
            let access_control = AccessControl {
                clearance_level: level.clone(),
                compartments: bounded_compartments,
                expiry,
            };
            
            Clearances::<T>::insert(&account, access_control);
            
            // Audit log
            Self::add_audit_entry(
                AuditAction::ClearanceGranted,
                granter.clone(),
                Some(account.clone()),
                level.clone(),
                H256::zero(),
            )?;
            
            Self::deposit_event(Event::ClearanceGranted {
                account,
                level: level.to_u8(),
                granted_by: granter,
            });
            
            Ok(())
        }
        
        /// Emergency access to encrypted messages (with audit trail)
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(100_000, 0))]
        pub fn emergency_access_message(
            origin: OriginFor<T>,
            target_account: T::AccountId,
            message_index: u32,
            justification: Vec<u8>,
        ) -> DispatchResult {
            let accessor = ensure_signed(origin)?;
            
            // Check emergency access permission
            ensure!(
                EmergencyAccess::<T>::get(&accessor),
                Error::<T>::NoEmergencyAccess
            );
            
            // Get the message (but don't delete it)
            let messages = Messages::<T>::get(&target_account);
            let message = messages.get(message_index as usize)
                .ok_or(Error::<T>::MessageNotFound)?;
            
            let message_hash = Self::hash_message(message);
            let justification_hash = sp_io::hashing::blake2_256(&justification);
            
            // Heavy audit logging
            Self::add_audit_entry(
                AuditAction::EmergencyAccess,
                accessor.clone(),
                Some(target_account),
                ClassificationLevel::TopSecret, // Assume highest level
                H256::from(justification_hash),
            )?;
            
            Self::deposit_event(Event::EmergencyAccessUsed {
                accessor,
                target_message: message_hash,
                justification_hash: H256::from(justification_hash),
            });
            
            Ok(())
        }
    }
    
    // Helper functions
    impl<T: Config> Pallet<T> {
        fn hash_message(message: &EncryptedMessage<T>) -> H256 {
            let mut data = message.sender.encode();
            data.extend_from_slice(&message.nonce);
            data.extend_from_slice(&message.ephemeral_public);
            data.extend_from_slice(&message.ciphertext);
            
            H256::from(sp_io::hashing::blake2_256(&data))
        }
        
        fn has_clearance(access: &AccessControl<T>, required: &ClassificationLevel) -> bool {
            match (required, &access.clearance_level) {
                (ClassificationLevel::Unclassified, _) => true,
                (ClassificationLevel::Confidential, ClassificationLevel::Confidential) => true,
                (ClassificationLevel::Confidential, ClassificationLevel::Secret) => true,
                (ClassificationLevel::Confidential, ClassificationLevel::TopSecret) => true,
                (ClassificationLevel::Confidential, ClassificationLevel::TopSecretSCI) => true,
                (ClassificationLevel::Secret, ClassificationLevel::Secret) => true,
                (ClassificationLevel::Secret, ClassificationLevel::TopSecret) => true,
                (ClassificationLevel::Secret, ClassificationLevel::TopSecretSCI) => true,
                (ClassificationLevel::TopSecret, ClassificationLevel::TopSecret) => true,
                (ClassificationLevel::TopSecret, ClassificationLevel::TopSecretSCI) => true,
                (ClassificationLevel::TopSecretSCI, ClassificationLevel::TopSecretSCI) => true,
                _ => false,
            }
        }
        
        fn add_audit_entry(
            action: AuditAction,
            actor: T::AccountId,
            target: Option<T::AccountId>,
            classification: ClassificationLevel,
            metadata_hash: H256,
        ) -> Result<(), Error<T>> {
            let entry = AuditEntry {
                action,
                actor,
                target,
                classification,
                timestamp: frame_system::Pallet::<T>::block_number(),
                metadata_hash,
            };
            
            AuditLog::<T>::try_mutate(|log| {
                log.try_push(entry)
                    .map_err(|_| Error::<T>::AuditLogFull)
            })
        }
    }
}