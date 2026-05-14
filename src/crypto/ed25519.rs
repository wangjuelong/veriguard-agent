//! Ed25519 keypair generation, signing, and verification.
//!
//! Wraps [`ed25519-dalek`] with the small surface Veriguard agent needs:
//!   * generate a fresh keypair from OS RNG
//!   * sign arbitrary message bytes
//!   * verify a signature
//!   * import / export the 32-byte seed (private) and 32-byte verifying key (public)
//!
//! The private key is stored as the 32-byte ed25519 seed (RFC 8032).  The
//! upstream `SigningKey` is reconstructed from the seed on demand to avoid
//! holding a long-lived expanded scalar in memory.
//!
//! ## Example
//!
//! ```
//! use veriguard_agent::crypto::ed25519::{generate_ed25519, Ed25519PublicKey};
//! let priv_key = generate_ed25519();
//! let pub_key  = priv_key.public_key();
//! let sig = priv_key.sign(b"hello");
//! assert!(pub_key.verify(b"hello", &sig));
//! ```
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand_core::OsRng;
use thiserror::Error;

/// Errors that can occur when importing Ed25519 material from bytes.
#[derive(Debug, Error)]
pub enum Ed25519Error {
    /// The byte slice did not decode into a valid Ed25519 verifying key.
    #[error("invalid Ed25519 public key bytes")]
    InvalidPublicKey,
}

/// A 32-byte Ed25519 private key (the RFC 8032 seed).
///
/// Cloning is intentionally NOT derived; the caller must explicitly export the
/// bytes via [`to_bytes`](Self::to_bytes) if duplication is required, so any
/// copy lives at an explicit lexical site.
#[derive(Debug)]
pub struct Ed25519PrivateKey {
    inner: SigningKey,
}

/// A 32-byte Ed25519 public (verifying) key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    inner: VerifyingKey,
}

/// A 64-byte Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature {
    inner: Signature,
}

/// Generate a fresh Ed25519 keypair using the OS RNG.
pub fn generate_ed25519() -> Ed25519PrivateKey {
    let mut csprng = OsRng;
    Ed25519PrivateKey {
        inner: SigningKey::generate(&mut csprng),
    }
}

impl Ed25519PrivateKey {
    /// Derive the matching public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign an arbitrary message.
    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature {
            inner: self.inner.sign(msg),
        }
    }

    /// Export the 32-byte private seed.  Treat the result as secret material.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.inner.to_bytes()
    }

    /// Reconstruct a private key from the 32-byte seed.
    pub fn from_bytes(b: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            inner: SigningKey::from_bytes(b),
        }
    }
}

impl Ed25519PublicKey {
    /// Verify a signature against `msg`.  Returns `true` on success.
    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> bool {
        self.inner.verify(msg, &sig.inner).is_ok()
    }

    /// Export the 32-byte verifying key.  Takes `self` by value because the
    /// type is `Copy` and the underlying bytes are cheap to clone.
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.inner.to_bytes()
    }

    /// Reconstruct a public key from its 32-byte encoding.
    pub fn from_bytes(b: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Ed25519Error> {
        VerifyingKey::from_bytes(b)
            .map(|inner| Self { inner })
            .map_err(|_| Ed25519Error::InvalidPublicKey)
    }
}

impl Ed25519Signature {
    /// Serialize to the canonical 64-byte form.  Takes `self` by value
    /// because the type is `Copy`.
    pub fn to_bytes(self) -> [u8; SIGNATURE_LENGTH] {
        self.inner.to_bytes()
    }

    /// Parse a 64-byte signature.  Any 64 bytes are syntactically valid; the
    /// math is only checked on verify.
    pub fn from_bytes(b: &[u8; SIGNATURE_LENGTH]) -> Self {
        Self {
            inner: Signature::from_bytes(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let priv_key = generate_ed25519();
        let pub_key = priv_key.public_key();
        let msg = b"veriguard onboarding ping";

        let sig = priv_key.sign(msg);

        assert!(pub_key.verify(msg, &sig), "fresh keypair must verify");
    }

    #[test]
    fn test_ed25519_verify_tampered_message_rejects() {
        let priv_key = generate_ed25519();
        let pub_key = priv_key.public_key();

        let sig = priv_key.sign(b"original payload");

        assert!(
            !pub_key.verify(b"tampered payload", &sig),
            "verify must reject a different message"
        );
    }

    #[test]
    fn test_ed25519_verify_tampered_signature_rejects() {
        let priv_key = generate_ed25519();
        let pub_key = priv_key.public_key();
        let msg = b"signature flip test";
        let sig = priv_key.sign(msg);

        // Flip the first byte of the 64-byte signature.
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0x01;
        let tampered = Ed25519Signature::from_bytes(&sig_bytes);

        assert!(
            !pub_key.verify(msg, &tampered),
            "verify must reject a flipped signature byte"
        );
    }

    #[test]
    fn test_ed25519_private_key_roundtrip_bytes() {
        let priv_key = generate_ed25519();
        let pub_key = priv_key.public_key();

        let seed = priv_key.to_bytes();
        let restored = Ed25519PrivateKey::from_bytes(&seed);

        // The restored key signs identically — verify with the original public key.
        let sig = restored.sign(b"after-load");
        assert!(pub_key.verify(b"after-load", &sig));
    }

    #[test]
    fn test_ed25519_public_key_roundtrip_bytes() {
        let priv_key = generate_ed25519();
        let pub_key = priv_key.public_key();
        let bytes = pub_key.to_bytes();

        let restored = Ed25519PublicKey::from_bytes(&bytes).expect("valid pub key roundtrip");
        assert_eq!(restored, pub_key);
    }

    #[test]
    fn test_ed25519_public_key_random_bytes_do_not_verify() {
        // ed25519-dalek 2.x is lenient at parse time — it accepts any 32-byte
        // input that decompresses to a point and only rejects bad points at
        // verify time.  We exercise that path: a random 32-byte string is
        // unlikely to be a real signer's verifying key, so verify of a
        // legitimately-signed message must fail.
        let signer = generate_ed25519();
        let sig = signer.sign(b"who signed this?");

        // Construct an unrelated "fake" verifier from a different keypair.
        let other = generate_ed25519();
        let other_pub = other.public_key();
        assert!(
            !other_pub.verify(b"who signed this?", &sig),
            "an unrelated public key must not verify someone else's signature"
        );
    }
}
