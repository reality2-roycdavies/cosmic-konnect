//! CKP Cryptographic operations
//!
//! Handles:
//! - X25519 key exchange for pairing
//! - BLAKE3 key derivation
//! - Verification code generation

use rand::RngCore;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Size of X25519 public key
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of session nonce
pub const SESSION_NONCE_SIZE: usize = 32;

/// Cryptographic key pair for pairing
pub struct KeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex::encode(self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// Perform key exchange with a peer's public key
    pub fn key_exchange(self, peer_public: &[u8; PUBLIC_KEY_SIZE]) -> SharedSecret {
        let peer_public = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer_public)
    }
}

/// Derive a pairing key from the shared secret using BLAKE3
pub fn derive_pairing_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("cosmic-konnect-v1 pairing");
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

/// Generate the 6-digit verification code from the shared secret
pub fn generate_verification_code(shared_secret: &[u8]) -> String {
    let hash = blake3::hash(shared_secret);
    let bytes = hash.as_bytes();

    // Take first 4 bytes and convert to number, then take last 6 digits
    let num = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", num % 1_000_000)
}

/// Generate a random session nonce
pub fn generate_session_nonce() -> [u8; SESSION_NONCE_SIZE] {
    let mut nonce = [0u8; SESSION_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Stored pairing information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairingInfo {
    pub device_id: String,
    pub device_name: String,
    /// The derived pairing key (from key exchange)
    pub pairing_key: [u8; 32],
    /// When the pairing was established
    pub paired_at: u64,
}

/// Crypto errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Invalid public key")]
    InvalidPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_public = alice.public_key_bytes();
        let bob_public = bob.public_key_bytes();

        let alice_shared = alice.key_exchange(&bob_public);
        let bob_shared = bob.key_exchange(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_verification_code() {
        let secret = [0u8; 32];
        let code = generate_verification_code(&secret);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
