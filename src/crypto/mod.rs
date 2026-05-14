//! Asymmetric + AEAD primitives used by the Veriguard agent.
//!
//! Why this module exists: §2.4 of the C1+C2 design replaces upstream's
//! shared `api_key` bearer scheme with a per-agent identity built from two
//! keypairs (`A_sign` = Ed25519 for request authentication, `A_enc` = X25519
//! for sealing Mode-C offline packs).  Veriguard's Java backend uses the
//! same primitives via BouncyCastle, so the wire format is interoperable.

pub mod cert_pin;
pub mod ed25519;
pub mod keys;
pub mod x25519_box;

#[allow(unused_imports)]
pub use cert_pin::{cert_sha256, verify_cert_pin, CertPinError};
#[allow(unused_imports)]
pub use ed25519::{
    generate_ed25519, Ed25519Error, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};
#[allow(unused_imports)]
pub use keys::{
    load_ed25519_priv, load_x25519_priv, save_ed25519_priv, save_x25519_priv, KeyIoError,
};
#[allow(unused_imports)]
pub use x25519_box::{
    generate_x25519, open_box, seal_box, BoxError, Nonce, X25519PrivateKey, X25519PublicKey,
};
