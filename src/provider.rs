//! The provider that implements certval's hashing and verification interfaces against a PKCS #11 module.

use crate::error::{Error, Result};
use crate::key::{digest_info, ec_field_len, public_key_template, signature_for_token};
use crate::mechanism::{
    digest_mechanism, hash_mechanism, hash_oid_for_signature, message_mechanism, KeyKind,
};
use certval::{
    CalculateHash, PathValidationStatus, PkiEnvironment, VerifySignatureDigest,
    VerifySignatureMessage,
};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use der::Encode;
use log::debug;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

/// A [`certval`] crypto provider backed by a PKCS #11 module.
///
/// One value implements all three interfaces it supports - hashing, verification over a message and
/// verification over a digest - because they share a session, a cache of imported keys and the
/// knowledge of which mechanisms the token offers. Register the same value in each role rather than
/// opening a module once per role:
///
/// ```no_run
/// # use certval::PkiEnvironment;
/// # use certval_pkcs11::Pkcs11Crypto;
/// # use std::sync::Arc;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let crypto = Arc::new(Pkcs11Crypto::open("/usr/lib/softhsm/libsofthsm2.so", None)?);
/// # let mut pe = PkiEnvironment::default();
/// pe.add_calculate_hash_callback(crypto.clone());
/// pe.add_verify_signature_message_callback(crypto.clone());
/// pe.add_verify_signature_digest_callback(crypto);
/// # Ok(())
/// # }
/// ```
///
/// Every operation is a public-key operation over public data, so the session is a public session
/// and no `C_Login` is performed.
pub struct Pkcs11Crypto {
    /// The session and everything whose validity is tied to it. Imported keys are session objects,
    /// so a cached handle is only meaningful alongside the session that created it; holding both
    /// under one lock is what keeps that pairing from coming apart.
    inner: Mutex<Inner>,

    /// Whether the token was found to offer the hashing mechanisms. A module that verifies but does
    /// not digest is common enough to be worth answering quickly rather than by a failed call.
    offers_hashing: bool,

    /// Retained so the module outlives every session opened from it, and so callers can be told
    /// which token answered.
    context: Pkcs11,

    /// The slot the session was opened against.
    slot: Slot,
}

struct Inner {
    session: Session,
    /// Imported public keys, keyed by a SHA-256 hash of the encoded `SubjectPublicKeyInfo`.
    keys: BTreeMap<[u8; 32], ObjectHandle>,
}

impl Pkcs11Crypto {
    /// Loads a PKCS #11 module and opens a read-only public session against a token.
    ///
    /// When `token_label` is `None` the first slot reporting a token present is used, which is the
    /// common case for a module fronting a single device. Supply a label to disambiguate a module
    /// that exposes several.
    pub fn open<P: AsRef<Path>>(module: P, token_label: Option<&str>) -> Result<Self> {
        let context = Pkcs11::new(module.as_ref())?;
        context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Self::from_context(context, token_label)
    }

    /// Opens a session on an already-initialized module, for callers that load the module
    /// themselves or share one across several components.
    pub fn from_context(context: Pkcs11, token_label: Option<&str>) -> Result<Self> {
        let slots = context.get_slots_with_token()?;
        let slot = match token_label {
            None => *slots.first().ok_or(Error::NoTokenPresent)?,
            Some(label) => {
                let mut found = None;
                for slot in slots {
                    let info = context.get_token_info(slot)?;
                    if info.label().trim_end() == label {
                        found = Some(slot);
                        break;
                    }
                }
                found.ok_or_else(|| Error::TokenNotFound(label.to_string()))?
            }
        };

        let mechanisms = context.get_mechanism_list(slot)?;
        let offers_hashing = mechanisms.iter().any(|m| {
            use cryptoki::mechanism::MechanismType as T;
            [T::SHA1, T::SHA224, T::SHA256, T::SHA384, T::SHA512].contains(m)
        });

        let session = context.open_ro_session(slot)?;

        Ok(Pkcs11Crypto {
            inner: Mutex::new(Inner {
                session,
                keys: BTreeMap::new(),
            }),
            offers_hashing,
            context,
            slot,
        })
    }

    /// Returns the number of public keys currently held in the key cache.
    ///
    /// Exposed because the cache is the difference between one token round trip per issuer and
    /// three per signature, which makes it the number worth watching when verification through a
    /// module turns out slower than expected.
    pub fn cached_key_count(&self) -> usize {
        self.inner.lock().map(|i| i.keys.len()).unwrap_or(0)
    }

    /// Discards every cached public key, destroying the objects on the token.
    ///
    /// Not needed for correctness, since the objects are session objects and go when the session
    /// does. It exists for a long-lived process validating paths under an unbounded set of issuers,
    /// where the cache would otherwise only grow.
    pub fn clear_key_cache(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let handles: Vec<ObjectHandle> = inner.keys.values().copied().collect();
        for handle in handles {
            let _ = inner.session.destroy_object(handle);
        }
        inner.keys.clear();
    }

    /// Returns the label of the token this provider is using.
    pub fn token_label(&self) -> Option<String> {
        let info = self.context.get_token_info(self.slot).ok()?;
        Some(info.label().trim_end().to_string())
    }

    /// Runs `op` with a handle to `spki` imported on the token, importing it first if this is the
    /// first time the key has been seen.
    ///
    /// The key is hashed rather than compared, so an issuer that appears throughout a path is
    /// imported once no matter how many certificates it signed.
    fn with_key<T>(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        kind: KeyKind,
        op: impl FnOnce(&Session, ObjectHandle) -> std::result::Result<T, cryptoki::error::Error>,
    ) -> Option<std::result::Result<T, cryptoki::error::Error>> {
        let encoded = spki.to_der().ok()?;
        let key_id: [u8; 32] = Sha256::digest(&encoded).into();

        let mut inner = self.inner.lock().ok()?;

        let handle = match inner.keys.get(&key_id) {
            Some(handle) => *handle,
            None => {
                let template = public_key_template(spki, kind)?;
                let handle = match inner.session.create_object(&template) {
                    Ok(handle) => handle,
                    Err(e) => {
                        // A module that cannot hold this kind of key is not a failure of the
                        // signature; it is a reason to let another implementation answer.
                        debug!("PKCS #11 module declined to import a public key: {e}");
                        return None;
                    }
                };
                inner.keys.insert(key_id, handle);
                handle
            }
        };

        Some(op(&inner.session, handle))
    }

    /// Verifies `data` against `signature` using `mechanism`, reporting the outcome in the terms
    /// certval's interfaces are defined in.
    fn verify_with(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        kind: KeyKind,
        mechanism: Mechanism<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        let field_len = match kind {
            KeyKind::Ec => match ec_field_len(spki) {
                Some(len) => len,
                None => return Err(certval::Error::Unrecognized),
            },
            _ => 0,
        };
        let Some(signature) = signature_for_token(signature, kind, field_len) else {
            return Err(certval::Error::Unrecognized);
        };

        let outcome = self.with_key(spki, kind, |session, handle| {
            session.verify(&mechanism, handle, data, &signature)
        });

        match outcome {
            // The token verified the signature.
            Some(Ok(())) => Ok(()),

            // The token reached a verdict and it was negative. Reported as a verification failure
            // rather than as a decline, though note that the environment continues to the next
            // registered implementation either way; a caller who needs this to be final clears the
            // other implementations before registering this one.
            Some(Err(e)) => {
                debug!("PKCS #11 verification failed: {e}");
                Err(certval::Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                ))
            }

            // The key could not be imported or the request could not be assembled, so no verdict
            // was reached and another implementation should answer.
            None => Err(certval::Error::Unrecognized),
        }
    }
}

impl CalculateHash for Pkcs11Crypto {
    fn calculate_hash(
        &self,
        _pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        if !self.offers_hashing {
            return Err(certval::Error::Unrecognized);
        }
        let Some(mechanism) = hash_mechanism(&hash_alg.oid) else {
            return Err(certval::Error::Unrecognized);
        };

        let Ok(inner) = self.inner.lock() else {
            return Err(certval::Error::Unrecognized);
        };
        match inner.session.digest(&mechanism, buffer_to_hash) {
            Ok(digest) => Ok(digest),
            Err(e) => {
                debug!("PKCS #11 module could not calculate a digest: {e}");
                Err(certval::Error::Unrecognized)
            }
        }
    }
}

impl VerifySignatureMessage for Pkcs11Crypto {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some((mechanism, kind)) = message_mechanism(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        self.verify_with(spki, kind, mechanism, message_to_verify, signature)
    }
}

impl VerifySignatureDigest for Pkcs11Crypto {
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some((mechanism, kind)) = digest_mechanism(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };

        // PKCS #1 v1.5 verification is defined over a DigestInfo rather than a bare digest, so the
        // hash algorithm has to be named again here. ECDSA and PSS take the digest as it stands.
        let data = match mechanism {
            Mechanism::RsaPkcs => {
                let Some(hash_oid) = hash_oid_for_signature(signature_alg) else {
                    return Err(certval::Error::Unrecognized);
                };
                let Some(wrapped) = digest_info(hash_oid, hash_to_verify) else {
                    return Err(certval::Error::Unrecognized);
                };
                wrapped
            }
            _ => hash_to_verify.to_vec(),
        };

        self.verify_with(spki, kind, mechanism, &data, signature)
    }
}
