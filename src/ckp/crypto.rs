//! CKP Cryptographic operations
//!
//! Handles:
//! - X25519 key exchange for pairing
//! - ChaCha20-Poly1305 encryption for messages
//! - Verification code generation

use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;

/// Size of encryption nonce
pub const NONCE_SIZE: usize = 12;

/// Size of auth tag
pub const TAG_SIZE: usize = 16;

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

/// Derive a pairing key from the shared secret
pub fn derive_pairing_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"cosmic-konnect-v1", &mut key)
        .expect("32 bytes is valid length for HKDF");
    key
}

/// Generate the 6-digit verification code from the shared secret
pub fn generate_verification_code(shared_secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();

    // Take first 4 bytes and convert to number, then take last 6 digits
    let num = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    format!("{:06}", num % 1_000_000)
}

/// Session encryption context
pub struct SessionCrypto {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl SessionCrypto {
    /// Create a new session crypto from pairing key and nonces
    pub fn new(pairing_key: &[u8; 32], nonce_a: &[u8], nonce_b: &[u8]) -> Self {
        // Derive session key from pairing key and both nonces
        let hk = Hkdf::<Sha256>::new(None, pairing_key);
        let mut info = Vec::with_capacity(nonce_a.len() + nonce_b.len() + 7);
        info.extend_from_slice(nonce_a);
        info.extend_from_slice(nonce_b);
        info.extend_from_slice(b"session");

        let mut session_key = [0u8; 32];
        hk.expand(&info, &mut session_key)
            .expect("32 bytes is valid length for HKDF");

        let cipher = ChaCha20Poly1305::new_from_slice(&session_key)
            .expect("32 bytes is valid key size");

        Self { cipher, counter: 0 }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate nonce from counter
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[4..12].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a message
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Generate a random session nonce
pub fn generate_session_nonce() -> [u8; SESSION_NONCE_SIZE] {
    let mut nonce = [0u8; SESSION_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
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

    #[test]
    fn test_session_crypto() {
        let pairing_key = [1u8; 32];
        let nonce_a = [2u8; 32];
        let nonce_b = [3u8; 32];

        let mut crypto_a = SessionCrypto::new(&pairing_key, &nonce_a, &nonce_b);
        let crypto_b = SessionCrypto::new(&pairing_key, &nonce_a, &nonce_b);

        let plaintext = b"Hello, World!";
        let ciphertext = crypto_a.encrypt(plaintext).unwrap();
        let decrypted = crypto_b.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
