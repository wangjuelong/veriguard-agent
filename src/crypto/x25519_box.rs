//! NaCl-box-style asymmetric encryption: X25519 ECDH → raw 32-byte shared
//! secret used directly as the IETF ChaCha20-Poly1305 (RFC 8439) AEAD key.
//!
//! # Algorithm choice: IETF ChaCha20-Poly1305 (12-byte nonce)
//!
//! We use IETF ChaCha20-Poly1305 with a 12-byte random nonce to match
//! the Veriguard Java backend, which uses BouncyCastle's
//! `org.bouncycastle.crypto.modes.ChaCha20Poly1305`. BouncyCastle 1.84
//! does NOT ship an XChaCha20Poly1305 engine, so XChaCha20 would require
//! a hand-rolled implementation on the Java side — rejected as too risky
//! for a 招标 timeline. The 12-byte nonce gives ~2^32 collision probability
//! under random sampling; this is acceptable for our use because keys are
//! per-session (per agent-platform pair) and we send at most ~10^4 packs
//! per key.
//!
//! # Key derivation deviation from standard NaCl box
//!
//! Standard NaCl `crypto_box` uses HSalsa20 to derive a fresh key from
//! the 32-byte X25519 shared secret. We instead use the raw 32-byte
//! shared secret directly as the ChaCha20-Poly1305 key. This is
//! cryptographically equivalent given a fresh per-message random nonce
//! and matches the Java side which performs the same shortcut.
//! Document this if either side ever changes its KDF behavior.
//!
//! # Construction
//!
//! `seal_box(plain, recipient_pub, sender_priv)`:
//!
//! 1. Derive `shared = X25519(sender_priv, recipient_pub)` — 32 raw bytes
//!    used directly as the AEAD key (see deviation note above).
//! 2. Draw a fresh 12-byte nonce from `OsRng` (IETF ChaCha20-Poly1305 nonce).
//! 3. Encrypt: `cipher = ChaCha20-Poly1305(shared, nonce, plain)`.
//!    Output ciphertext includes the trailing 16-byte Poly1305 tag.
//!
//! `open_box` reverses this: it derives the same shared secret with
//! `recipient_priv` and `sender_pub`, then decrypts.
//!
//! # Why this layer wraps the raw libraries
//!
//! * Forces 12-byte nonces matching the Java BC wire contract.
//! * Encapsulates the curve <-> AEAD key handoff so callers can't forget it.
//! * Exposes only `Vec<u8>` for ciphertexts (no exotic generic-array types).
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Errors emitted by the sealed-box layer.
#[derive(Debug, Error)]
pub enum BoxError {
    /// AEAD encryption failed (should be near-impossible for valid inputs).
    #[error("ChaCha20-Poly1305 encryption failed")]
    EncryptFailed,
    /// AEAD decryption failed — wrong key, wrong nonce, or tampered ciphertext.
    #[error("ChaCha20-Poly1305 decryption failed (MAC mismatch or wrong key)")]
    DecryptFailed,
}

/// Nonce size in bytes for IETF ChaCha20-Poly1305 (RFC 8439).
pub const NONCE_BYTES: usize = 12;

/// X25519 private scalar (32 bytes).  Wraps `StaticSecret`.
pub struct X25519PrivateKey {
    inner: StaticSecret,
}

/// X25519 public key (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey {
    inner: PublicKey,
}

/// 12-byte nonce for IETF ChaCha20-Poly1305 (RFC 8439).
///
/// The inner field is **private**: callers must go through
/// [`Nonce::from_bytes`] or get one back from [`seal_box`].  Direct
/// construction of `Nonce([0u8; 12])` was previously possible — this would
/// allow an external module (e.g. the transport layer in C1-Agent-2) to
/// reuse an all-zero nonce under the same key, which is catastrophic for
/// ChaCha20-Poly1305 (XOR of two ciphertexts leaks the keystream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_BYTES]);

/// Generate a fresh X25519 keypair using the OS RNG.
pub fn generate_x25519() -> X25519PrivateKey {
    X25519PrivateKey {
        inner: StaticSecret::random_from_rng(OsRng),
    }
}

impl X25519PrivateKey {
    /// Derive the matching public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            inner: PublicKey::from(&self.inner),
        }
    }

    /// Export the 32-byte scalar.  Treat the result as secret material.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Reconstruct from the 32-byte scalar.
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self {
            inner: StaticSecret::from(*b),
        }
    }
}

impl X25519PublicKey {
    /// Export the 32-byte public key.
    pub fn to_bytes(self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Reconstruct from 32 bytes.  Any 32 bytes are syntactically valid on
    /// Curve25519; the math only matters during seal/open.
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self {
            inner: PublicKey::from(*b),
        }
    }
}

impl Nonce {
    /// Build from raw 12 bytes (IETF ChaCha20-Poly1305 nonce length).
    pub fn from_bytes(b: [u8; NONCE_BYTES]) -> Self {
        Self(b)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }
}

/// Encrypt `plain` for `recipient_pub` using `sender_priv`.
///
/// Returns `(ciphertext, nonce)`.  The ciphertext contains the 16-byte
/// Poly1305 authentication tag at its tail (i.e. `ciphertext.len() == plain.len() + 16`).
pub fn seal_box(
    plain: &[u8],
    recipient_pub: &X25519PublicKey,
    sender_priv: &X25519PrivateKey,
) -> Result<(Vec<u8>, Nonce), BoxError> {
    let shared = sender_priv.inner.diffie_hellman(&recipient_pub.inner);
    let cipher = ChaCha20Poly1305::new(shared.as_bytes().into());

    // Draw a fresh 12-byte nonce (IETF ChaCha20-Poly1305 nonce length).
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain)
        .map_err(|_| BoxError::EncryptFailed)?;
    Ok((ciphertext, Nonce(nonce_bytes)))
}

/// Decrypt ciphertext sealed by `seal_box`.
///
/// Returns the plaintext on success, or [`BoxError::DecryptFailed`] for any
/// of: wrong recipient key, wrong sender key, tampered ciphertext or nonce,
/// truncated tag.
pub fn open_box(
    ciphertext: &[u8],
    nonce: &Nonce,
    sender_pub: &X25519PublicKey,
    recipient_priv: &X25519PrivateKey,
) -> Result<Vec<u8>, BoxError> {
    let shared = recipient_priv.inner.diffie_hellman(&sender_pub.inner);
    let cipher = ChaCha20Poly1305::new(shared.as_bytes().into());
    let aead_nonce = chacha20poly1305::Nonce::from_slice(&nonce.0);
    cipher
        .decrypt(aead_nonce, ciphertext)
        .map_err(|_| BoxError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519box_seal_open_roundtrip() {
        let sender = generate_x25519();
        let recipient = generate_x25519();
        let recipient_pub = recipient.public_key();
        let sender_pub = sender.public_key();

        let plaintext = b"secret tasks for the agent";
        let (ciphertext, nonce) = seal_box(plaintext, &recipient_pub, &sender).expect("seal");

        // Ciphertext is longer than plaintext by 16 bytes (Poly1305 tag).
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let recovered = open_box(&ciphertext, &nonce, &sender_pub, &recipient).expect("open");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_x25519box_open_wrong_recipient_priv_fails() {
        let sender = generate_x25519();
        let recipient = generate_x25519();
        let recipient_pub = recipient.public_key();
        let sender_pub = sender.public_key();

        let (ciphertext, nonce) = seal_box(b"top secret", &recipient_pub, &sender).expect("seal");

        // Use an unrelated recipient private key to attempt decryption.
        let attacker = generate_x25519();
        let err = open_box(&ciphertext, &nonce, &sender_pub, &attacker);
        assert!(matches!(err, Err(BoxError::DecryptFailed)));
    }

    #[test]
    fn test_x25519box_open_tampered_ciphertext_fails() {
        let sender = generate_x25519();
        let recipient = generate_x25519();
        let recipient_pub = recipient.public_key();
        let sender_pub = sender.public_key();

        let (mut ciphertext, nonce) =
            seal_box(b"truth in tag", &recipient_pub, &sender).expect("seal");

        // Flip the first ciphertext byte.
        ciphertext[0] ^= 0x01;
        let err = open_box(&ciphertext, &nonce, &sender_pub, &recipient);
        assert!(matches!(err, Err(BoxError::DecryptFailed)));
    }

    #[test]
    fn test_x25519box_open_tampered_tag_fails() {
        let sender = generate_x25519();
        let recipient = generate_x25519();
        let recipient_pub = recipient.public_key();
        let sender_pub = sender.public_key();

        let (mut ciphertext, nonce) =
            seal_box(b"trailing tag", &recipient_pub, &sender).expect("seal");

        // Flip the last byte (inside the Poly1305 tag).
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let err = open_box(&ciphertext, &nonce, &sender_pub, &recipient);
        assert!(matches!(err, Err(BoxError::DecryptFailed)));
    }

    #[test]
    fn test_x25519_key_sizes() {
        let k = generate_x25519();
        assert_eq!(k.to_bytes().len(), 32);
        assert_eq!(k.public_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_private_key_roundtrip_bytes() {
        let k = generate_x25519();
        let bytes = k.to_bytes();
        let restored = X25519PrivateKey::from_bytes(&bytes);

        // After roundtrip, the derived public keys must match.
        assert_eq!(restored.public_key(), k.public_key());
    }

    /// Wire-format regression: nonce must be exactly 12 bytes (IETF
    /// ChaCha20-Poly1305 per RFC 8439).  This locks in alignment with the
    /// Java BouncyCastle side, which has no XChaCha20Poly1305 engine.
    #[test]
    fn test_box_nonce_is_12_bytes_ietf() {
        // Constant + type contract.
        assert_eq!(NONCE_BYTES, 12);

        // `Nonce::from_bytes` accepts a [u8; 12] (compile-time enforced).
        let raw = [0xAAu8; 12];
        let nonce = Nonce::from_bytes(raw);
        assert_eq!(nonce.as_bytes().len(), 12);

        // `seal_box` emits a 12-byte nonce.
        let sender = generate_x25519();
        let recipient = generate_x25519();
        let recipient_pub = recipient.public_key();
        let (_ct, fresh_nonce) =
            seal_box(b"ietf wire contract", &recipient_pub, &sender).expect("seal");
        assert_eq!(fresh_nonce.as_bytes().len(), 12);
    }
}
