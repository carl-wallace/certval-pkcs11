//! Translation from the algorithm identifiers certval presents to the PKCS #11 mechanisms a module
//! understands.
//!
//! certval separates verification into two interfaces: one that is handed a message and hashes it, and
//! one that is handed a digest that has already been calculated. PKCS #11 draws the same line, in
//! that `CKM_SHA256_RSA_PKCS` and `CKM_ECDSA_SHA256` hash the data themselves while `CKM_RSA_PKCS`
//! and `CKM_ECDSA` operate on a digest, so each interface maps onto its own mechanism family.

use certval::{
    PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384,
    PKIXALG_ECDSA_WITH_SHA512, PKIXALG_RSASSA_PSS, PKIXALG_SHA1, PKIXALG_SHA224,
    PKIXALG_SHA224_WITH_RSA_ENCRYPTION, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
    PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::ObjectIdentifier;
use cryptoki::mechanism::{dsa, rsa::PkcsMgfType, rsa::PkcsPssParams, Mechanism, MechanismType};
use cryptoki::object::MlDsaParameterSetType;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;

/// The shape of public key a signature algorithm implies, which determines the object template used
/// to import the key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum KeyKind {
    /// An RSA key, imported as modulus and public exponent.
    Rsa,
    /// An elliptic curve key, imported as curve parameters and a point.
    Ec,
    /// An ML-DSA key of the given parameter set, imported as a raw value.
    MlDsa(MlDsaParameterSetType),
}

/// Returns the digest mechanism for a hash algorithm identifier.
pub(crate) fn hash_mechanism(oid: &ObjectIdentifier) -> Option<Mechanism<'static>> {
    match *oid {
        PKIXALG_SHA1 => Some(Mechanism::Sha1),
        PKIXALG_SHA224 => Some(Mechanism::Sha224),
        PKIXALG_SHA256 => Some(Mechanism::Sha256),
        PKIXALG_SHA384 => Some(Mechanism::Sha384),
        PKIXALG_SHA512 => Some(Mechanism::Sha512),
        _ => None,
    }
}

/// Returns the mechanism that verifies a signature over a message, hashing the message on the
/// token, together with the kind of key it needs.
pub(crate) fn message_mechanism(
    alg: &AlgorithmIdentifierOwned,
) -> Option<(Mechanism<'static>, KeyKind)> {
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => Some((Mechanism::Sha224RsaPkcs, KeyKind::Rsa)),
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => Some((Mechanism::Sha256RsaPkcs, KeyKind::Rsa)),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => Some((Mechanism::Sha384RsaPkcs, KeyKind::Rsa)),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => Some((Mechanism::Sha512RsaPkcs, KeyKind::Rsa)),

        PKIXALG_ECDSA_WITH_SHA224 => Some((Mechanism::EcdsaSha224, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA256 => Some((Mechanism::EcdsaSha256, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA384 => Some((Mechanism::EcdsaSha384, KeyKind::Ec)),
        PKIXALG_ECDSA_WITH_SHA512 => Some((Mechanism::EcdsaSha512, KeyKind::Ec)),

        // ML-DSA carries no separate hash: the algorithm consumes the message directly, so the same
        // mechanism serves regardless of message length. A deterministic (non-hedged) verification
        // with no context string is what a certificate signature uses.
        ID_ML_DSA_44 => Some((
            ml_dsa_mechanism(),
            KeyKind::MlDsa(MlDsaParameterSetType::ML_DSA_44),
        )),
        ID_ML_DSA_65 => Some((
            ml_dsa_mechanism(),
            KeyKind::MlDsa(MlDsaParameterSetType::ML_DSA_65),
        )),
        ID_ML_DSA_87 => Some((
            ml_dsa_mechanism(),
            KeyKind::MlDsa(MlDsaParameterSetType::ML_DSA_87),
        )),

        // PKCS #11 defines no SHA-224 variant of the hash-and-verify PSS mechanism, so a SHA-224
        // PSS signature has no message form here and is left to software.
        PKIXALG_RSASSA_PSS => pss_params(alg).and_then(|p| {
            let mechanism = match p.hash_alg {
                MechanismType::SHA256 => Mechanism::Sha256RsaPkcsPss(p),
                MechanismType::SHA384 => Mechanism::Sha384RsaPkcsPss(p),
                MechanismType::SHA512 => Mechanism::Sha512RsaPkcsPss(p),
                _ => return None,
            };
            Some((mechanism, KeyKind::Rsa))
        }),

        _ => None,
    }
}

/// Returns the mechanism that verifies a signature over an already-calculated digest, together with
/// the kind of key it needs.
///
/// ML-DSA is absent by design rather than by omission: it signs the message itself and has no
/// digest-only form, so a caller holding only a digest cannot verify one.
pub(crate) fn digest_mechanism(
    alg: &AlgorithmIdentifierOwned,
) -> Option<(Mechanism<'static>, KeyKind)> {
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION
        | PKIXALG_SHA256_WITH_RSA_ENCRYPTION
        | PKIXALG_SHA384_WITH_RSA_ENCRYPTION
        | PKIXALG_SHA512_WITH_RSA_ENCRYPTION => Some((Mechanism::RsaPkcs, KeyKind::Rsa)),

        PKIXALG_ECDSA_WITH_SHA224
        | PKIXALG_ECDSA_WITH_SHA256
        | PKIXALG_ECDSA_WITH_SHA384
        | PKIXALG_ECDSA_WITH_SHA512 => Some((Mechanism::Ecdsa, KeyKind::Ec)),

        PKIXALG_RSASSA_PSS => pss_params(alg).map(|p| (Mechanism::RsaPkcsPss(p), KeyKind::Rsa)),

        _ => None,
    }
}

/// Returns the hash algorithm a signature algorithm digests with, which the digest interface needs in
/// order to name the digest inside the `DigestInfo` that PKCS #1 v1.5 verification expects.
pub(crate) fn hash_oid_for_signature(alg: &AlgorithmIdentifierOwned) -> Option<ObjectIdentifier> {
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA224 => Some(PKIXALG_SHA224),
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA256 => Some(PKIXALG_SHA256),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA384 => Some(PKIXALG_SHA384),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA512 => Some(PKIXALG_SHA512),
        _ => None,
    }
}

/// A certificate signature carries no context string, and hedging is a property of how a signature
/// was produced rather than of how it is checked, so verification needs no parameters at all. This
/// combination is the one `SignAdditionalContext` renders as an absent parameter block.
fn ml_dsa_mechanism() -> Mechanism<'static> {
    Mechanism::MlDsa(dsa::SignAdditionalContext::new(
        dsa::HedgeType::Preferred,
        None,
    ))
}

/// Reads the hash and salt length out of RSASSA-PSS parameters.
///
/// The PKCS #11 mechanism has no defaults of its own, so every field it needs must come from the
/// parameter block. RFC 4055 defaults every field to its SHA-1 form, and a SHA-1 PSS signature is
/// not something this provider will assemble a mechanism for, so an algorithm identifier that omits
/// the hash is declined and software answers instead.
fn pss_params(alg: &AlgorithmIdentifierOwned) -> Option<PkcsPssParams> {
    let encoded = alg.parameters.as_ref()?.to_der().ok()?;
    let pss = RsaPssParams::from_der(&encoded).ok()?;

    let (hash_alg, mgf, default_salt) = match pss.hash?.oid {
        PKIXALG_SHA224 => (MechanismType::SHA224, PkcsMgfType::MGF1_SHA224, 28),
        PKIXALG_SHA256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32),
        PKIXALG_SHA384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48),
        PKIXALG_SHA512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64),
        _ => return None,
    };

    Some(PkcsPssParams {
        hash_alg,
        mgf,
        // RFC 4055 defaults the salt length to 20, but that default accompanies the SHA-1 default
        // for the hash, which is already excluded above. A parameter block naming a SHA-2 hash and
        // omitting the salt length is unusual enough that matching the digest length is the more
        // useful reading.
        s_len: (pss.salt_len.unwrap_or(default_salt) as u64).into(),
    })
}

/// The parameter block carried by an RSASSA-PSS algorithm identifier. Only the fields that bear on
/// mechanism selection are read; the trailer field is fixed at 1 by RFC 4055 and offers no choice.
#[derive(der::Sequence)]
struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer_field: Option<u32>,
}
