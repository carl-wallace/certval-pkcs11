//! certval-cms's recipient and signing credentials over private keys a PKCS #11 token holds, under
//! the `cms` feature, and a source that finds them among the token's certificates.
//!
//! A [`Pkcs11Token`] is a logged-in session that the credentials made from it share. Each private
//! key operation happens on the token, and only its result leaves:
//!
//! - **Key transport.** RSAES-PKCS1-v1_5 is a raw RSA decryption (`CKM_RSA_X_509`), whose padding
//!   certval-cms's [`unpad_pkcs1v15`] removes in constant time, so that the token's padding check
//!   cannot become an oracle. A token without raw RSA is asked for `CKM_RSA_PKCS` instead.
//!   RSAES-OAEP is `CKM_RSA_PKCS_OAEP`.
//! - **Key agreement.** `CKM_ECDH1_DERIVE` with no KDF returns the shared secret, from which
//!   [`cek_from_ecdh_secret`] derives the key-encryption key and unwraps the content-encryption
//!   key. The shared secret therefore leaves the token.
//! - **KEM.** `C_DecapsulateKey` with `CKM_ML_KEM` returns the shared secret, from which
//!   [`cek_from_kem_secret`] does the rest. It too leaves the token.
//! - **Signing.** The token signs with the mechanism the signature algorithm calls for, over the
//!   message where it offers one that hashes, and over the digest otherwise.
//!
//! A mechanism the token does not offer is the credential declining ([`Error::Unrecognized`]); any
//! other failure is [`Error::Crypto`].

use std::path::Path;
use std::sync::{Arc, Mutex};

use certval_cms::{
    cek_from_ecdh_secret, cek_from_kem_secret, recipient_matches, unpad_pkcs1v15, CmsEnvironment,
    Error, KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
    RecipientCredential, RecipientCredentialSource, Result, SharedRecipientCredential,
    SharedSigningCredential, SigningCredential, SigningCredentialLookup, SigningCredentialSource,
};
use cms::enveloped_data::RecipientIdentifier;
use cryptoki::context::Pkcs11;
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use der::Decode;
use log::debug;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::key::{digest_info, ec_field_len, rsa_modulus_len, signature_from_token};
use crate::mechanism::{digest_mechanism, hash_oid_for_signature, message_mechanism};
use crate::provider::{find_slot, shared_context};

/// The length in octets of an ML-KEM shared secret (FIPS 203).
const ML_KEM_SHARED_SECRET_LEN: u64 = 32;

/// A logged-in session on a token, shared by the credentials made from it.
///
/// PKCS #11 logs a user in to a token for the whole process, not for one session, so a second
/// [`Pkcs11Token`] on the same token finds the user already logged in, which is not an error. For
/// the same reason nothing here logs out: logging out would end the login for every session the
/// process holds on the token.
pub struct Pkcs11Token {
    session: Mutex<Session>,
}

impl Pkcs11Token {
    /// Loads a PKCS #11 module, opens a read-only session on the token labelled `token_label` (or
    /// with `None`, the first slot with a token present), and logs the user in with `pin`.
    ///
    /// The module is initialized once per process and shared, as with
    /// [`Pkcs11Crypto::open`](crate::Pkcs11Crypto::open).
    pub fn open<P: AsRef<Path>>(
        module: P,
        token_label: Option<&str>,
        pin: &AuthPin,
    ) -> crate::Result<Self> {
        Self::from_context(shared_context(module.as_ref())?, token_label, pin)
    }

    /// Opens a read-only session on an already-initialized module and logs the user in with `pin`.
    pub fn from_context(
        context: Pkcs11,
        token_label: Option<&str>,
        pin: &AuthPin,
    ) -> crate::Result<Self> {
        let slot = find_slot(&context, token_label)?;
        let session = context.open_ro_session(slot)?;
        match session.login(UserType::User, Some(pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Runs `op` with the session, e.g. to find or generate keys on the token. Objects created
    /// through it are visible to the credentials, which use the same session.
    pub fn with_session<T>(&self, op: impl FnOnce(&Session) -> T) -> Result<T> {
        let session = self
            .session
            .lock()
            .map_err(|_| Error::Crypto(String::from("the token's session lock is poisoned")))?;
        Ok(op(&session))
    }

    /// Runs `op` with the session, mapping a PKCS #11 error to the credential's error.
    fn perform<T>(
        &self,
        what: &str,
        op: impl FnOnce(&Session) -> cryptoki::error::Result<T>,
    ) -> Result<T> {
        self.with_session(op)?.map_err(|e| token_error(what, e))
    }

    /// The value of a secret key object the token derived, which is then destroyed.
    fn take_secret(&self, session: &Session, key: ObjectHandle) -> Result<Zeroizing<Vec<u8>>> {
        let value = session.get_attributes(key, &[AttributeType::Value]);
        if let Err(e) = session.destroy_object(key) {
            debug!("the PKCS #11 module could not destroy a derived secret: {e}");
        }
        match value
            .map_err(|e| token_error("read a derived secret", e))?
            .pop()
        {
            Some(Attribute::Value(value)) => Ok(Zeroizing::new(value)),
            _ => Err(Error::Crypto(String::from(
                "the PKCS #11 module returned no derived secret",
            ))),
        }
    }
}

/// A PKCS #11 error as a credential's error: a mechanism or key type the token does not offer is
/// the credential declining, and anything else a failure.
fn token_error(what: &str, e: Pkcs11Error) -> Error {
    if let Pkcs11Error::Pkcs11(
        RvError::MechanismInvalid | RvError::MechanismParamInvalid | RvError::KeyTypeInconsistent,
        _,
    ) = e
    {
        debug!("the PKCS #11 module declined to {what}: {e}");
        return Error::Unrecognized;
    }
    Error::Crypto(format!("the PKCS #11 module could not {what}: {e}"))
}

/// The template for a secret the token derives, as a session object whose value can be read.
fn derived_secret_template(len: u64) -> [Attribute; 6] {
    [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::ValueLen(len.into()),
        Attribute::Token(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ]
}

/// The certificate's public key.
fn spki(certificate: &Certificate) -> &SubjectPublicKeyInfoOwned {
    certificate.tbs_certificate().subject_public_key_info()
}

/// A recipient's private key on a token, with its certificate, which decrypts each recipient type.
pub struct Pkcs11RecipientKey {
    token: Arc<Pkcs11Token>,
    key: ObjectHandle,
    certificate: Certificate,
}

impl Pkcs11RecipientKey {
    /// The credential for the private key `key` on `token`, whose certificate is `certificate`.
    pub fn new(token: Arc<Pkcs11Token>, certificate: Certificate, key: ObjectHandle) -> Self {
        Self {
            token,
            key,
            certificate,
        }
    }
}

impl RecipientCredential for Pkcs11RecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (hash, mgf) = match alg {
            KeyTransportAlgorithm::RsaPkcs1v15 => return self.decrypt_pkcs1v15(encrypted_key),
            KeyTransportAlgorithm::RsaOaepSha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            KeyTransportAlgorithm::RsaOaepSha256 => {
                (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256)
            }
            KeyTransportAlgorithm::RsaOaepSha384 => {
                (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384)
            }
            KeyTransportAlgorithm::RsaOaepSha512 => {
                (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512)
            }
            _ => return Err(Error::Unrecognized),
        };
        let mechanism =
            Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty()));
        match self
            .token
            .with_session(|session| session.decrypt(&mechanism, self.key, encrypted_key))?
        {
            Ok(key) => Ok(Zeroizing::new(key)),
            // Some modules answer OAEP parameters they do not offer with the generic
            // CKR_ARGUMENTS_BAD rather than CKR_MECHANISM_PARAM_INVALID, e.g. SoftHSM 2.7 for any
            // hash but SHA-1. The parameters are the only argument that varies here, so it is the
            // same decline.
            Err(Pkcs11Error::Pkcs11(RvError::ArgumentsBad, _)) => {
                debug!("the PKCS #11 module declined RSAES-OAEP with {hash}");
                Err(Error::Unrecognized)
            }
            Err(e) => Err(token_error("perform RSAES-OAEP decryption", e)),
        }
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let field_len = ec_field_len(spki(&self.certificate)).ok_or(Error::Unrecognized)?;
        let point = originator
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::InvalidInput(String::from("an originator key of unused bits")))?;
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), point));
        let z = self.token.with_session(|session| {
            let secret = session
                .derive_key(
                    &mechanism,
                    self.key,
                    &derived_secret_template(field_len as u64),
                )
                .map_err(|e| token_error("perform ECDH", e))?;
            self.token.take_secret(session, secret)
        })??;
        cek_from_ecdh_secret(alg, wrap, &z, ukm, encrypted_key)
    }

    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let ss = self.token.with_session(|session| {
            let secret = session
                .decapsulate_key(
                    &Mechanism::MlKem,
                    self.key,
                    &derived_secret_template(ML_KEM_SHARED_SECRET_LEN),
                    kem_ct,
                )
                .map_err(|e| token_error("decapsulate", e))?;
            self.token.take_secret(session, secret)
        })??;
        cek_from_kem_secret(kdf, wrap, &ss, ukm, encrypted_key)
    }
}

impl Pkcs11RecipientKey {
    /// RSAES-PKCS1-v1_5 decryption: a raw RSA decryption, unpadded here, or where the token offers
    /// no raw RSA, `CKM_RSA_PKCS`.
    fn decrypt_pkcs1v15(&self, encrypted_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let k = rsa_modulus_len(spki(&self.certificate)).ok_or(Error::Unrecognized)?;
        let raw = self.token.perform("perform raw RSA decryption", |session| {
            session.decrypt(&Mechanism::RsaX509, self.key, encrypted_key)
        });
        match raw {
            Ok(em) => {
                let em = Zeroizing::new(em);
                // A module may return the raw result without its leading zero octets.
                if em.len() > k {
                    return Err(Error::Crypto(String::from("key transport failed")));
                }
                let mut padded = Zeroizing::new(vec![0u8; k - em.len()]);
                padded.extend_from_slice(&em);
                unpad_pkcs1v15(&padded, k)
            }
            Err(Error::Unrecognized) => self
                .token
                .perform("perform RSAES-PKCS1-v1_5 decryption", |session| {
                    session.decrypt(&Mechanism::RsaPkcs, self.key, encrypted_key)
                })
                .map(Zeroizing::new),
            Err(e) => Err(e),
        }
    }
}

/// A signer's private key on a token, with its certificate.
pub struct Pkcs11SigningKey {
    token: Arc<Pkcs11Token>,
    key: ObjectHandle,
    certificate: Certificate,
}

impl Pkcs11SigningKey {
    /// The credential for the private key `key` on `token`, whose certificate is `certificate`.
    pub fn new(token: Arc<Pkcs11Token>, certificate: Certificate, key: ObjectHandle) -> Self {
        Self {
            token,
            key,
            certificate,
        }
    }
}

impl SigningCredential for Pkcs11SigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let (mechanism, kind) = message_mechanism(alg).ok_or(Error::Unrecognized)?;
        let signature = self.token.perform("sign", |session| {
            session.sign(&mechanism, self.key, message)
        })?;
        signature_from_token(signature, kind).ok_or_else(malformed_signature)
    }

    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        let (mechanism, kind) = digest_mechanism(alg).ok_or(Error::Unrecognized)?;
        // PKCS #1 v1.5 signs a DigestInfo rather than a bare digest; ECDSA and PSS take the digest
        // as it stands.
        let data = if let Mechanism::RsaPkcs = mechanism {
            hash_oid_for_signature(alg)
                .and_then(|oid| digest_info(oid, digest))
                .ok_or(Error::Unrecognized)?
        } else {
            digest.to_vec()
        };
        let signature = self.token.perform("sign a digest", |session| {
            session.sign(&mechanism, self.key, &data)
        })?;
        signature_from_token(signature, kind).ok_or_else(malformed_signature)
    }
}

fn malformed_signature() -> Error {
    Error::Crypto(String::from(
        "the PKCS #11 module returned a malformed signature",
    ))
}

/// The certificates on a token, each with the private key that shares its `CKA_ID`, as a source of
/// both recipient and signing credentials. A token can hold many keys; the one a recipient
/// identifier names is found by its certificate's issuer and serial number or subject key
/// identifier, and signing keys by any [`SigningCredentialLookup`].
#[derive(Clone)]
pub struct TokenIdentities {
    token: Arc<Pkcs11Token>,
}

impl TokenIdentities {
    /// A source over the certificates on `token`.
    pub fn new(token: Arc<Pkcs11Token>) -> Self {
        Self { token }
    }

    /// Every certificate on the token that `matches` and has a private key with the same `CKA_ID`,
    /// with that key.
    fn find(
        &self,
        matches: impl Fn(&Certificate) -> bool,
    ) -> Result<Vec<(Certificate, ObjectHandle)>> {
        self.token.perform("search for certificates", |session| {
            let mut found = vec![];
            let certificates = session.find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
            ])?;
            for handle in certificates {
                // An object can go between the search and the read, e.g. a session object of a
                // session that has since closed, so a failed read passes the object over.
                let attributes = match session
                    .get_attributes(handle, &[AttributeType::Value, AttributeType::Id])
                {
                    Ok(attributes) => attributes,
                    Err(e) => {
                        debug!("passing over a certificate the token could not read: {e}");
                        continue;
                    }
                };
                let mut value = None;
                let mut id = None;
                for attribute in attributes {
                    match attribute {
                        Attribute::Value(v) => value = Some(v),
                        Attribute::Id(i) => id = Some(i),
                        _ => {}
                    }
                }
                let (Some(value), Some(id)) = (value, id) else {
                    continue;
                };
                let Ok(certificate) = Certificate::from_der(&value) else {
                    continue;
                };
                if !matches(&certificate) {
                    continue;
                }
                let keys = session.find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Id(id),
                ])?;
                if let Some(key) = keys.first() {
                    found.push((certificate, *key));
                }
            }
            Ok(found)
        })
    }

    /// Every certificate on the token with a private key of the same `CKA_ID`, for a caller to list
    /// or choose among. A credential for one is found through either source interface, by its
    /// identifier.
    pub fn certificates(&self) -> Result<Vec<Certificate>> {
        Ok(self.find(|_| true)?.into_iter().map(|(c, _)| c).collect())
    }
}

impl RecipientCredentialSource for TokenIdentities {
    fn find_recipient_credential(
        &self,
        _env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>> {
        Ok(self
            .find(|c| recipient_matches(rid, c))?
            .into_iter()
            .next()
            .map(|(certificate, key)| {
                Arc::new(Pkcs11RecipientKey::new(
                    self.token.clone(),
                    certificate,
                    key,
                )) as SharedRecipientCredential
            }))
    }
}

impl SigningCredentialSource for TokenIdentities {
    fn find_signing_credentials(
        &self,
        _env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        Ok(self
            .find(|c| lookup.matches(c))?
            .into_iter()
            .map(|(certificate, key)| {
                Arc::new(Pkcs11SigningKey::new(self.token.clone(), certificate, key))
                    as SharedSigningCredential
            })
            .collect())
    }
}
