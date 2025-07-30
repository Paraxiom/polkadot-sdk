# SPHINCS+ Application Crypto Fix Summary

## Problem
The `app_crypto!` macro in sp-application-crypto creates recursive type definitions when used with SPHINCS+ signatures. This happens because:
1. SPHINCS+ has a very large signature size (49,856 bytes vs 64 bytes for ed25519)
2. The macro creates wrapper types that include the signature inline
3. This leads to "cycle detected when computing when sphincs::app::Public needs drop" errors

## Solution
Instead of using the `app_crypto!` macro, we manually implement all the required wrapper types with a key modification:

### Key Changes:
1. **Boxed Signatures**: The `Signature` wrapper uses `Box<sphincs::Signature>` instead of storing the signature inline
   ```rust
   pub struct Signature(Box<sphincs::Signature>);
   ```

2. **Manual Trait Implementation**: All traits that the `app_crypto!` macro would generate are implemented manually:
   - `AppCrypto` for Public, Signature, and Pair
   - `AppPublic` for Public
   - `AppSignature` for Signature  
   - `AppPair` for Pair
   - `RuntimePublic` for Public
   - All conversion traits (From, TryFrom, AsRef, etc.)

3. **Custom Encode/Decode**: Special handling for encoding/decoding the boxed signature to maintain compatibility

## Benefits
1. Avoids recursive type issues completely
2. Reduces stack usage by boxing large signatures
3. Maintains full compatibility with the application crypto API
4. Works seamlessly with the existing SPHINCS+ implementation in sp-core

## Implementation Details
The fix is implemented in `/home/paraxiom/polkadot-sdk/substrate/primitives/application-crypto/src/sphincs.rs`

The implementation provides:
- Full wrapper types for Public, Signature, and Pair
- All required trait implementations
- Proper boxing of the large signature data
- Compatibility with sp_io crypto functions
- Test coverage to ensure functionality

## Usage
The SPHINCS+ application crypto types can now be used exactly like other crypto types:
```rust
use sp_application_crypto::sphincs::{Public, Signature, Pair};

// Use in runtime
pub type SphincsPublic = sphincs::Public;
pub type SphincsSignature = sphincs::Signature;
```

No special handling is required by users of the API.