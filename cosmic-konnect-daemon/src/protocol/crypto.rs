//! CKP Cryptographic operations
//!
//! Handles:
//! - X25519 key exchange for pairing
//! - HKDF-SHA256 key derivation (compatible with Android CkpCrypto)
//! - SHA-256 verification code generation
//! - AES-256-GCM session encryption

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Size of X25519 public key
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of session nonce
pub const SESSION_NONCE_SIZE: usize = 32;

/// AES-GCM nonce size
const AES_NONCE_SIZE: usize = 12;

/// AES-GCM tag size
const AES_TAG_SIZE: usize = 16;

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

/// Derive a pairing key from the shared secret using HKDF-SHA256.
///
/// Matches Android CkpCrypto.derivePairingKey():
///   hkdf(sharedSecret, salt=null, info="cosmic-konnect-v1", length=32)
pub fn derive_pairing_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"cosmic-konnect-v1", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Derive a session key from pairing key and both session nonces.
///
/// Matches Android CkpCrypto.deriveSessionKey():
///   hkdf(pairingKey, salt=null, info=nonceA+nonceB+"session", length=32)
pub fn derive_session_key(
    pairing_key: &[u8; 32],
    nonce_a: &[u8],
    nonce_b: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, pairing_key);
    let mut info = Vec::with_capacity(nonce_a.len() + nonce_b.len() + 7);
    info.extend_from_slice(nonce_a);
    info.extend_from_slice(nonce_b);
    info.extend_from_slice(b"session");
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Generate the 6-digit verification code from the shared secret using SHA-256.
///
/// Matches Android CkpCrypto.generateVerificationCode():
///   SHA-256(sharedSecret), take first 4 bytes as u32 BE, mod 1_000_000
pub fn generate_verification_code(shared_secret: &[u8]) -> String {
    let hash = Sha256::digest(shared_secret);
    let num = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    format!("{:06}", num % 1_000_000)
}

/// Generate a random session nonce
pub fn generate_session_nonce() -> [u8; SESSION_NONCE_SIZE] {
    let mut nonce = [0u8; SESSION_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Session encryption using AES-256-GCM.
///
/// Matches Android SessionCrypto / CkpCrypto.encrypt() / CkpCrypto.decrypt():
/// - Nonce: 12 bytes, counter placed in bytes 4..12 as big-endian u64
/// - Output: nonce || ciphertext || tag
pub struct SessionCrypto {
    session_key: [u8; 32],
    counter: AtomicU64,
}

impl SessionCrypto {
    /// Create a new session crypto context from pairing key and both nonces.
    pub fn new(pairing_key: &[u8; 32], nonce_a: &[u8], nonce_b: &[u8]) -> Self {
        let session_key = derive_session_key(pairing_key, nonce_a, nonce_b);
        Self {
            session_key,
            counter: AtomicU64::new(0),
        }
    }

    /// Encrypt a plaintext payload.
    /// Returns nonce || ciphertext (which includes the GCM tag).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);

        // Build 12-byte nonce: 4 zero bytes + 8-byte BE counter
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        nonce_bytes[4..12].copy_from_slice(&count.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher =
            Aes256Gcm::new_from_slice(&self.session_key).map_err(|_| CryptoError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Prepend nonce
        let mut output = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt data produced by encrypt() (nonce || ciphertext+tag).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < AES_NONCE_SIZE + AES_TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce = Nonce::from_slice(&data[..AES_NONCE_SIZE]);
        let ciphertext = &data[AES_NONCE_SIZE..];

        let cipher =
            Aes256Gcm::new_from_slice(&self.session_key).map_err(|_| CryptoError::DecryptionFailed)?;
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
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

    #[test]
    fn test_pairing_key_derivation() {
        let secret = [42u8; 32];
        let key = derive_pairing_key(&secret);
        assert_eq!(key.len(), 32);
        // Should be deterministic
        let key2 = derive_pairing_key(&secret);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_session_crypto_roundtrip() {
        let pairing_key = [1u8; 32];
        let nonce_a = [2u8; 32];
        let nonce_b = [3u8; 32];

        let crypto = SessionCrypto::new(&pairing_key, &nonce_a, &nonce_b);

        let plaintext = b"hello world";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_session_key_derivation() {
        let pairing_key = [5u8; 32];
        let nonce_a = [6u8; 32];
        let nonce_b = [7u8; 32];

        let key = derive_session_key(&pairing_key, &nonce_a, &nonce_b);
        assert_eq!(key.len(), 32);

        // Same inputs should yield same key
        let key2 = derive_session_key(&pairing_key, &nonce_a, &nonce_b);
        assert_eq!(key, key2);

        // Different nonce order should yield different key
        let key3 = derive_session_key(&pairing_key, &nonce_b, &nonce_a);
        assert_ne!(key, key3);
    }
}
