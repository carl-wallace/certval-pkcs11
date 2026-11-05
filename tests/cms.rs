//! certval-cms credentials over keys a token holds. Each key is generated on the token, so its
//! private half never leaves it, and a certificate for its public half is issued by a CA in software
//! and stored on the token beside it. certval-cms's RustCrypto software builds the messages to that
//! certificate and verifies the signatures, and the token's credential decrypts and signs.
//!
//! Key transport with every algorithm; ECDH on P-256, P-384 and P-521 with each KDF hash and wrap;
//! ML-KEM with each parameter set; signing with RSA PKCS #1 v1.5 and RSASSA-PSS, ECDSA and ML-DSA;
//! and the credentials found through `TokenIdentities` rather than passed in.
//!
//! The module, token and user PIN are named by `CERTVAL_PKCS11_MODULE`, `CERTVAL_PKCS11_TOKEN_LABEL`
//! and `CERTVAL_PKCS11_USER_PIN`; with any unset, each test says so and passes. A mechanism the
//! token does not offer, e.g. ML-KEM before SoftHSM 2.7's successor, skips that case and says so.

#![cfg(feature = "cms")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use certval::PkiEnvironment;
use certval_cms::{
    rsa_pss, AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm, DigestAlgorithm,
    EnvelopedDataBuilder, KdfAlgorithm, KemRecipient, KeyAgreeRecipient, KeyAgreementAlgorithm,
    KeyTransRecipient, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential,
    SignedDataBuilder, Signer, SignerPolicy, SigningCredential,
};
use certval_pkcs11::{Pkcs11RecipientKey, Pkcs11SigningKey, Pkcs11Token, TokenIdentities};
use cms::content_info::ContentInfo;
use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::db::rfc5912::{
    ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER, ID_EC_PUBLIC_KEY, RSA_ENCRYPTION,
    SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use const_oid::ObjectIdentifier;
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, MlDsaParameterSetType, MlKemParameterSetType,
    ObjectClass, ObjectHandle,
};
use cryptoki::types::AuthPin;
use der::asn1::{Any, BitString, Ia5String, OctetString, UintRef};
use der::{Decode, Encode, Sequence};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use sha1::{Digest, Sha1};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{
        pkix::{name::GeneralName, SubjectAltName, SubjectKeyIdentifier},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate,
};

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] = b"certval-pkcs11, longer than one AES block so that padding is exercised";

const MODULE: &str = "CERTVAL_PKCS11_MODULE";
const TOKEN_LABEL: &str = "CERTVAL_PKCS11_TOKEN_LABEL";
const USER_PIN: &str = "CERTVAL_PKCS11_USER_PIN";

const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128,
    KeyWrapAlgorithm::Aes192,
    KeyWrapAlgorithm::Aes256,
];

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// The token the environment names, logged in, or `None` after saying which variable is unset.
fn token(test: &str) -> Option<Arc<Pkcs11Token>> {
    for name in [MODULE, USER_PIN] {
        if env(name).is_none() {
            println!("{test}: skipped, {name} is not set");
            return None;
        }
    }
    let pin = AuthPin::new(env(USER_PIN).unwrap().into());
    let token = Pkcs11Token::open(env(MODULE).unwrap(), env(TOKEN_LABEL).as_deref(), &pin)
        .unwrap_or_else(|e| panic!("{test}: opening the token: {e}"));
    Some(Arc::new(token))
}

/// RustCrypto for everything, over a PkiEnvironment of certval's software.
fn software() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// Runs `test` on a thread with an 8 MiB stack. With certval's `pqc` feature, software signature
/// verification in a debug build exceeds the 2 MiB a test thread has by default.
fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

// ---- keys on the token, and their certificates

/// A kind of key to generate on the token.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Rsa,
    Ec(ObjectIdentifier),
    MlKem(MlKemParameterSetType, ObjectIdentifier),
    MlDsa(MlDsaParameterSetType, ObjectIdentifier),
}

/// A key pair generated on the token, with a certificate for it stored beside it under the same
/// `CKA_ID`.
struct TokenKey {
    certificate: Certificate,
    private: ObjectHandle,
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// Issues certificates from a throwaway P-256 CA, with a subject key identifier and optionally an
/// email address.
struct Profile {
    subject: Name,
    email: Option<String>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str("CN=certval-pkcs11 test CA").unwrap()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let skid = SubjectKeyIdentifier(
            OctetString::new(Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec()).unwrap(),
        );
        let mut extensions = vec![Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(skid.to_der().unwrap()).unwrap(),
        }];
        if let Some(email) = &self.email {
            let san = SubjectAltName(vec![GeneralName::Rfc822Name(
                Ia5String::new(email).unwrap(),
            )]);
            extensions.push(Extension {
                extn_id: ID_CE_SUBJECT_ALT_NAME,
                critical: false,
                extn_value: OctetString::new(san.to_der().unwrap()).unwrap(),
            });
        }
        Ok(extensions)
    }
}

/// Generates a `kind` key pair on the token as session objects, and stores a certificate for it,
/// containing `email` if given. `None`, after saying so, when the token does not offer the
/// mechanism.
fn generate(token: &Pkcs11Token, kind: Kind, email: Option<&str>, test: &str) -> Option<TokenKey> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).unwrap();
    let common_public = vec![Attribute::Token(false)];
    let common_private = vec![
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Id(id.to_vec()),
    ];
    let (mechanism, public, private) = match kind {
        Kind::Rsa => (
            Mechanism::RsaPkcsKeyPairGen,
            vec![
                Attribute::ModulusBits(2048u64.into()),
                Attribute::PublicExponent(vec![1, 0, 1]),
                Attribute::Encrypt(true),
                Attribute::Verify(true),
            ],
            vec![Attribute::Decrypt(true), Attribute::Sign(true)],
        ),
        Kind::Ec(curve) => (
            Mechanism::EccKeyPairGen,
            vec![
                Attribute::EcParams(curve.to_der().unwrap()),
                Attribute::Verify(true),
            ],
            vec![Attribute::Derive(true), Attribute::Sign(true)],
        ),
        Kind::MlKem(set, _) => (
            Mechanism::MlKemKeyPairGen,
            vec![
                Attribute::ParameterSet(set.into()),
                Attribute::Encapsulate(true),
            ],
            vec![Attribute::Decapsulate(true)],
        ),
        Kind::MlDsa(set, _) => (
            Mechanism::MlDsaKeyPairGen,
            vec![Attribute::ParameterSet(set.into()), Attribute::Verify(true)],
            vec![Attribute::Sign(true)],
        ),
    };
    let public: Vec<Attribute> = common_public.into_iter().chain(public).collect();
    let private: Vec<Attribute> = common_private.into_iter().chain(private).collect();

    let generated = token
        .with_session(|session| {
            let (public_key, private_key) =
                match session.generate_key_pair(&mechanism, &public, &private) {
                    Ok(pair) => pair,
                    Err(Pkcs11Error::Pkcs11(RvError::MechanismInvalid, _)) => return None,
                    Err(e) => panic!("{test}: generating a {kind:?} key: {e}"),
                };
            let spki = public_key_info(session, public_key, kind);
            Some((spki, private_key))
        })
        .unwrap();
    let Some((spki, private)) = generated else {
        println!("{test}: skipped {kind:?}, the token does not offer the mechanism");
        return None;
    };

    let mut serial = [0u8; 8];
    getrandom::fill(&mut serial).unwrap();
    serial[0] &= 0x7f;
    let subject = Name::from_str(&format!("CN=certval-pkcs11 {}", hex(&id))).unwrap();
    let ca = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let certificate = CertificateBuilder::new(
        Profile {
            subject: subject.clone(),
            email: email.map(String::from),
        },
        SerialNumber::new(&serial).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        spki,
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&ca)
    .unwrap();

    token
        .with_session(|session| {
            session.create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(false),
                Attribute::Id(id.to_vec()),
                Attribute::Subject(subject.to_der().unwrap()),
                Attribute::Value(certificate.to_der().unwrap()),
            ])
        })
        .unwrap()
        .unwrap_or_else(|e| panic!("{test}: storing a certificate: {e}"));
    Some(TokenKey {
        certificate,
        private,
    })
}

/// The public key the token generated, as a `SubjectPublicKeyInfo`.
fn public_key_info(
    session: &cryptoki::session::Session,
    key: ObjectHandle,
    kind: Kind,
) -> SubjectPublicKeyInfoOwned {
    let attribute = |t: AttributeType| -> Vec<u8> {
        match session.get_attributes(key, &[t]).unwrap().pop() {
            Some(Attribute::Modulus(v) | Attribute::PublicExponent(v))
            | Some(Attribute::EcPoint(v) | Attribute::Value(v)) => v,
            other => panic!("unexpected attribute {other:?}"),
        }
    };
    let (oid, parameters, public_key) = match kind {
        Kind::Rsa => {
            let modulus = attribute(AttributeType::Modulus);
            let exponent = attribute(AttributeType::PublicExponent);
            let key = RsaPublicKey {
                modulus: UintRef::new(&modulus).unwrap(),
                public_exponent: UintRef::new(&exponent).unwrap(),
            };
            (RSA_ENCRYPTION, Some(Any::null()), key.to_der().unwrap())
        }
        Kind::Ec(curve) => {
            // CKA_EC_POINT is the point in a DER OCTET STRING.
            let point = attribute(AttributeType::EcPoint);
            let point = OctetString::from_der(&point)
                .map(|o| o.as_bytes().to_vec())
                .unwrap_or(point);
            (
                ID_EC_PUBLIC_KEY,
                Some(Any::encode_from(&curve).unwrap()),
                point,
            )
        }
        Kind::MlKem(_, oid) | Kind::MlDsa(_, oid) => (oid, None, attribute(AttributeType::Value)),
    };
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid, parameters },
        subject_public_key: BitString::from_bytes(&public_key).unwrap(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- decryption

fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipient: impl cms::builder::RecipientInfoBuilder<Rng = Rng> + 'e,
) -> ContentInfo {
    if alg.is_authenticated() {
        AuthEnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    } else {
        EnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    }
}

fn assert_decrypts(
    env: &CmsEnvironment,
    ci: &ContentInfo,
    credential: Option<&dyn RecipientCredential>,
    name: &str,
) {
    let decrypted = env
        .decrypt_enveloped_data(ci, credential)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
}

#[test]
fn key_transport_with_each_algorithm() {
    const TEST: &str = "key_transport_with_each_algorithm";
    let Some(token) = token(TEST) else { return };
    let env = software();
    let key = generate(&token, Kind::Rsa, None, TEST).expect("RSA key generation");
    let credential = Pkcs11RecipientKey::new(token, key.certificate.clone(), key.private);
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for content in [
            ContentEncryptionAlgorithm::Aes128Cbc,
            ContentEncryptionAlgorithm::Aes256Gcm,
        ] {
            let r = KeyTransRecipient::from_certificate(&env, &key.certificate, None, alg).unwrap();
            let ci = envelop(&env, content, r);
            let name = format!("{alg:?} {content:?}");
            // A token declines what it does not offer, e.g. SoftHSM 2.7 OAEP with SHA-2.
            if let Err(certval_cms::Error::Unrecognized) =
                env.decrypt_enveloped_data(&ci, Some(&credential))
            {
                println!("{TEST}: skipped {name}, the token declined it");
                continue;
            }
            assert_decrypts(&env, &ci, Some(&credential), &name);
        }
    }
}

#[test]
fn key_agreement_on_each_curve_with_each_kdf_and_wrap() {
    const TEST: &str = "key_agreement_on_each_curve_with_each_kdf_and_wrap";
    let Some(token) = token(TEST) else { return };
    let env = software();
    for (curve, name) in [
        (SECP_256_R_1, "P-256"),
        (SECP_384_R_1, "P-384"),
        (SECP_521_R_1, "P-521"),
    ] {
        let Some(key) = generate(&token, Kind::Ec(curve), None, TEST) else {
            continue;
        };
        let credential =
            Pkcs11RecipientKey::new(token.clone(), key.certificate.clone(), key.private);
        for alg in [
            KeyAgreementAlgorithm::EcdhSha256,
            KeyAgreementAlgorithm::EcdhSha384,
            KeyAgreementAlgorithm::EcdhSha512,
        ] {
            for wrap in WRAPS {
                for ukm in [None, Some(b"user keying material".to_vec())] {
                    let r = KeyAgreeRecipient::from_certificate(
                        &env,
                        &key.certificate,
                        None,
                        alg,
                        wrap,
                        ukm.clone(),
                    )
                    .unwrap();
                    let ci = envelop(&env, ContentEncryptionAlgorithm::Aes256Gcm, r);
                    assert_decrypts(
                        &env,
                        &ci,
                        Some(&credential),
                        &format!("{name} {alg:?} {wrap:?} ukm={}", ukm.is_some()),
                    );
                }
            }
        }
    }
}

#[test]
fn kem_with_each_parameter_set() {
    const TEST: &str = "kem_with_each_parameter_set";
    let Some(token) = token(TEST) else { return };
    let env = software();
    for (set, oid) in [
        (MlKemParameterSetType::ML_KEM_512, ID_ALG_ML_KEM_512),
        (MlKemParameterSetType::ML_KEM_768, ID_ALG_ML_KEM_768),
        (MlKemParameterSetType::ML_KEM_1024, ID_ALG_ML_KEM_1024),
    ] {
        let Some(key) = generate(&token, Kind::MlKem(set, oid), None, TEST) else {
            continue;
        };
        let credential =
            Pkcs11RecipientKey::new(token.clone(), key.certificate.clone(), key.private);
        for kdf in [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ] {
            for wrap in WRAPS {
                let r = KemRecipient::from_certificate(
                    &env,
                    &key.certificate,
                    None,
                    kdf,
                    wrap,
                    Some(b"user keying material".to_vec()),
                )
                .unwrap();
                let ci = envelop(&env, ContentEncryptionAlgorithm::Aes256Cbc, r);
                assert_decrypts(
                    &env,
                    &ci,
                    Some(&credential),
                    &format!("{oid} {kdf:?} {wrap:?}"),
                );
            }
        }
    }
}

// ---- signing

fn assert_verifies(env: &CmsEnvironment, ci: &ContentInfo, name: &str) {
    let verified = env
        .verify_signed_data(ci, None, None, SignerPolicy::All)
        .unwrap_or_else(|e| panic!("{name}: verifying: {e}"));
    assert_eq!(verified.content, MESSAGE, "{name}");
}

fn sign(
    env: &CmsEnvironment,
    credential: &dyn SigningCredential,
    configure: impl Fn(Signer<'_>) -> Signer<'_>,
    name: &str,
) -> ContentInfo {
    SignedDataBuilder::new(MESSAGE)
        .add_signer(configure(Signer::explicit(credential)))
        .build(env)
        .unwrap_or_else(|e| panic!("{name}: signing: {e}"))
        .content_info
}

#[test]
fn rsa_pkcs1v15_and_pss_with_each_digest() {
    with_large_stack(|| {
        const TEST: &str = "rsa_pkcs1v15_and_pss_with_each_digest";
        let Some(token) = token(TEST) else { return };
        let env = software();
        let key = generate(&token, Kind::Rsa, None, TEST).expect("RSA key generation");
        let credential = Pkcs11SigningKey::new(token, key.certificate, key.private);
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let name = format!("PKCS #1 v1.5 {digest:?}");
            let ci = sign(&env, &credential, |s| s.digest(digest), &name);
            assert_verifies(&env, &ci, &name);
            let name = format!("PSS {digest:?}");
            let ci = sign(
                &env,
                &credential,
                |s| {
                    s.digest(digest)
                        .signature_algorithm(rsa_pss(digest).unwrap())
                },
                &name,
            );
            assert_verifies(&env, &ci, &name);
        }
    });
}

#[test]
fn ecdsa_on_each_curve_with_each_digest() {
    with_large_stack(|| {
        const TEST: &str = "ecdsa_on_each_curve_with_each_digest";
        let Some(token) = token(TEST) else { return };
        let env = software();
        for (curve, name) in [
            (SECP_256_R_1, "P-256"),
            (SECP_384_R_1, "P-384"),
            (SECP_521_R_1, "P-521"),
        ] {
            let Some(key) = generate(&token, Kind::Ec(curve), None, TEST) else {
                continue;
            };
            let credential = Pkcs11SigningKey::new(token.clone(), key.certificate, key.private);
            for digest in [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ] {
                let name = format!("{name} {digest:?}");
                let ci = sign(&env, &credential, |s| s.digest(digest), &name);
                assert_verifies(&env, &ci, &name);
            }
        }
    });
}

#[test]
fn ml_dsa_with_each_parameter_set() {
    with_large_stack(|| {
        const TEST: &str = "ml_dsa_with_each_parameter_set";
        if !cfg!(feature = "pqc") {
            println!("{TEST}: skipped, software verifies ML-DSA only with the pqc feature");
            return;
        }
        let Some(token) = token(TEST) else { return };
        let env = software();
        for (set, oid) in [
            (MlDsaParameterSetType::ML_DSA_44, ID_ML_DSA_44),
            (MlDsaParameterSetType::ML_DSA_65, ID_ML_DSA_65),
            (MlDsaParameterSetType::ML_DSA_87, ID_ML_DSA_87),
        ] {
            let Some(key) = generate(&token, Kind::MlDsa(set, oid), None, TEST) else {
                continue;
            };
            let credential = Pkcs11SigningKey::new(token.clone(), key.certificate, key.private);
            let name = format!("{oid}");
            let ci = sign(&env, &credential, |s| s, &name);
            assert_verifies(&env, &ci, &name);
        }
    });
}

// ---- credentials found on the token

#[test]
fn token_identities_find_the_recipient_and_the_signer() {
    with_large_stack(|| {
        const TEST: &str = "token_identities_find_the_recipient_and_the_signer";
        let Some(token) = token(TEST) else { return };
        let mut env = software();
        env.add_recipient_credential_source(TokenIdentities::new(token.clone()));
        env.add_signing_credential_source(TokenIdentities::new(token.clone()));

        let recipient = generate(&token, Kind::Ec(SECP_256_R_1), None, TEST).expect("EC key");
        let r = KeyAgreeRecipient::from_certificate(
            &env,
            &recipient.certificate,
            None,
            KeyAgreementAlgorithm::EcdhSha256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        let ci = envelop(&env, ContentEncryptionAlgorithm::Aes256Gcm, r);
        assert_decrypts(&env, &ci, None, "a recipient found by identifier");

        let mut email = [0u8; 8];
        getrandom::fill(&mut email).unwrap();
        let email = format!("{}@example.com", hex(&email));
        let signer = generate(&token, Kind::Rsa, Some(&email), TEST).expect("RSA key");
        let built = SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_email_address(email.as_str()))
            .build(&env)
            .unwrap_or_else(|e| panic!("a signer found by email address: {e}"));
        let verified = env
            .verify_signed_data(&built.content_info, None, None, SignerPolicy::All)
            .unwrap();
        assert_eq!(verified.signers[0].certificate, signer.certificate);

        let listed = TokenIdentities::new(token).certificates().unwrap();
        assert!(
            listed.contains(&recipient.certificate),
            "the recipient is listed"
        );
        assert!(listed.contains(&signer.certificate), "the signer is listed");
    });
}
