//! PKCS #11 crypto provider for [`certval`].
//!
//! [`certval`] performs hashing and signature verification through callbacks registered on a
//! [`PkiEnvironment`](certval::PkiEnvironment). This crate supplies one implementation of those
//! callbacks that routes the work to a PKCS #11 module, so certification path validation can be
//! performed using a cryptographic implementation a deployment is obliged to use rather than the
//! in-process software implementation.
//!
//! Only public-key operations are involved. Verification and hashing operate entirely on public
//! data, so the session opened here is a public session and no `C_Login` is performed; a token PIN
//! is neither required nor accepted.
//!
//! ```no_run
//! use certval::PkiEnvironment;
//! use certval_pkcs11::Pkcs11Crypto;
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let crypto = Arc::new(Pkcs11Crypto::open("/usr/lib/softhsm/libsofthsm2.so", None)?);
//!
//! let mut pe = PkiEnvironment::default();
//!
//! // Registering before populate_5280_pki_environment puts the module ahead of the software
//! // implementations, so it is consulted first and software answers only what it declined.
//! pe.add_verify_signature_message_callback(crypto.clone());
//! pe.add_verify_signature_digest_callback(crypto.clone());
//! pe.add_calculate_hash_callback(crypto);
//!
//! pe.populate_5280_pki_environment();
//! # Ok(())
//! # }
//! ```
//!
//! # Registration is additive
//!
//! [`PkiEnvironment`](certval::PkiEnvironment) consults registered implementations in order and
//! takes the first success, so an implementation that declines - or that rejects a signature - falls
//! through to the next one. That is what allows a module to answer for the algorithms it offers
//! while software covers the rest, and it is the reason the example above still calls
//! `populate_5280_pki_environment`.
//!
//! It also means registering this provider does **not** by itself guarantee every verification
//! reaches the module. A caller who requires that must make the registration exclusive by clearing
//! the software callbacks first:
//!
//! ```no_run
//! # use certval::PkiEnvironment;
//! # use certval_pkcs11::Pkcs11Crypto;
//! # use std::sync::Arc;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let crypto = Arc::new(Pkcs11Crypto::open("/usr/lib/softhsm/libsofthsm2.so", None)?);
//! # let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.clear_verify_signature_message_callbacks();
//! pe.clear_verify_signature_digest_callbacks();
//! pe.add_verify_signature_message_callback(crypto.clone());
//! pe.add_verify_signature_digest_callback(crypto);
//! # Ok(())
//! # }
//! ```
//!
//! Note also that a [`SignatureVerificationCache`](certval::SignatureVerificationCache), if one is
//! registered, short-circuits repeat verifications before any callback runs. It is not installed by
//! `populate_5280_pki_environment`, so a caller who wants every verification to reach the module
//! simply does not add one.
//!
//! # Cost
//!
//! certval hands a verification callback a raw
//! [`SubjectPublicKeyInfoOwned`](spki::SubjectPublicKeyInfoOwned), whereas PKCS #11 verifies against
//! a key object. Importing a key for every signature would mean `C_CreateObject`, `C_VerifyInit` +
//! `C_Verify`, and `C_DestroyObject` on every call. Because path validation repeatedly verifies
//! certificates issued under the same handful of CA keys, this provider keeps imported public keys
//! in a cache keyed by a hash of the encoded key (see [`Pkcs11Crypto::cached_key_count`]), which
//! collapses that to a single round trip for every repeat issuer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod key;
mod mechanism;
mod provider;

pub use error::{Error, Result};
pub use provider::Pkcs11Crypto;
