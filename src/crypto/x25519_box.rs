//! X25519 ECDH + XChaCha20-Poly1305 sealed box ("NaCl box" equivalent).
//!
//! ## Construction
//!
//! `seal_box(plain, recipient_pub, sender_priv)`:
//!
//! 1. Derive `shared = X25519(sender_priv, recipient_pub)` — 32 raw bytes.
//!    Note: standard NaCl `crypto_box` runs HSalsa20 over the shared point
//!    plus a zero nonce to derive the symmetric key.  For Veriguard the Java
//!    BouncyCastle side performs the SAME shortcut (raw shared secret as the
//!    XChaCha20-Poly1305 key), so the wire formats line up.  Document this
//!    deviation if cross-implementation interop ever changes.
//! 2. Draw a fresh 24-byte nonce from `OsRng` (XChaCha20 needs 24 B).
//! 3. Encrypt: `cipher = XChaCha20-Poly1305(shared, nonce, plain)`.
//!    Output ciphertext includes the trailing 16-byte Poly1305 tag.
//!
//! `open_box` reverses this: it derives the same shared secret with
//! `recipient_priv` and `sender_pub`, then decrypts.
//!
//! ## Why this layer wraps the raw libraries
//!
//! * Forces 24-byte nonces (we never want 12-byte ChaCha20-Poly1305 with this
//!   key — the spec only allows XChaCha for the Mode-C pack envelope).
//! * Encapsulates the curve <-> AEAD key handoff so callers can't forget it.
//! * Exposes only `Vec<u8>` for ciphertexts (no exotic generic-array types).
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Errors emitted by the sealed-box layer.
#[derive(Debug, Error)]
pub enum BoxError {
    /// AEAD encryption failed (should be near-impossible for valid inputs).
    #[error("XChaCha20-Poly1305 encryption failed")]
    EncryptFailed,
    /// AEAD decryption failed — wrong key, wrong nonce, or tampered ciphertext.
    #[error("XChaCha20-Poly1305 decryption failed (MAC mismatch or wrong key)")]
    DecryptFailed,
}

/// Nonce size in bytes for XChaCha20-Poly1305.
pub const NONCE_BYTES: usize = 24;

/// X25519 private scalar (32 bytes).  Wraps `StaticSecret`.
pub struct X25519PrivateKey {
    inner: StaticSecret,
}

/// X25519 public key (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey {
    inner: PublicKey,
}

/// 24-byte nonce for XChaCha20-Poly1305.
///
/// The inner field is **private**: callers must go through
/// [`Nonce::from_bytes`] or get one back from [`seal_box`].  Direct
/// construction of `Nonce([0u8; 24])` was previously possible — this would
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
    /// Build from raw 24 bytes.
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
    let cipher = XChaCha20Poly1305::new(shared.as_bytes().into());

    // Draw a fresh 24-byte nonce.
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

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
    let cipher = XChaCha20Poly1305::new(shared.as_bytes().into());
    let xnonce = XNonce::from_slice(&nonce.0);
    cipher
        .decrypt(xnonce, ciphertext)
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
}
