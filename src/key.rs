//! Turning a `SubjectPublicKeyInfo` into a PKCS #11 public key object, and reshaping signatures so
//! the token sees the encoding it expects.
//!
//! Two encoding differences between X.509 and PKCS #11 have to be bridged here, and neither is
//! optional:
//!
//! - An elliptic curve point travels in a certificate as the raw bytes of a `BIT STRING`, while
//!   `CKA_EC_POINT` holds that point wrapped in a DER `OCTET STRING`.
//! - An ECDSA signature travels in a certificate as `SEQUENCE { r INTEGER, s INTEGER }`, while
//!   PKCS #11 uses the fixed-width concatenation of `r` and `s`.

use crate::mechanism::KeyKind;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use der::asn1::{OctetString, UintRef};
use der::{Decode, Encode, Sequence};
use spki::SubjectPublicKeyInfoOwned;

/// Builds the object template that imports `spki` as a public key usable for verification.
///
/// The object is deliberately a session object (`CKA_TOKEN` false): it is derived entirely from
/// public data already held in memory, so writing it to the token would consume token storage to no
/// benefit and would outlive the run that created it.
pub(crate) fn public_key_template(
    spki: &SubjectPublicKeyInfoOwned,
    kind: KeyKind,
) -> Option<Vec<Attribute>> {
    let mut template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Verify(true),
    ];

    match kind {
        KeyKind::Rsa => {
            let key = RsaPublicKey::from_der(spki.subject_public_key.as_bytes()?).ok()?;
            template.push(Attribute::KeyType(KeyType::RSA));
            template.push(Attribute::Modulus(key.modulus.as_bytes().to_vec()));
            template.push(Attribute::PublicExponent(
                key.public_exponent.as_bytes().to_vec(),
            ));
        }
        KeyKind::Ec => {
            // The curve is named in the algorithm parameters; without it the token has no way to
            // interpret the point.
            let params = spki.algorithm.parameters.as_ref()?.to_der().ok()?;
            let point = spki.subject_public_key.as_bytes()?;
            let wrapped = OctetString::new(point).ok()?.to_der().ok()?;
            template.push(Attribute::KeyType(KeyType::EC));
            template.push(Attribute::EcParams(params));
            template.push(Attribute::EcPoint(wrapped));
        }
        KeyKind::MlDsa(parameter_set) => {
            let key = spki.subject_public_key.as_bytes()?;
            template.push(Attribute::KeyType(KeyType::ML_DSA));
            template.push(Attribute::ParameterSet(parameter_set.into()));
            template.push(Attribute::Value(key.to_vec()));
        }
    }

    Some(template)
}

/// Reshapes a signature from its X.509 encoding into the encoding the mechanism expects.
///
/// Only ECDSA needs the work. `field_len` is the size of a single coordinate, which is what fixes
/// the width each of `r` and `s` is padded to; it is taken from the key rather than from the
/// signature, since either integer can be short by more than one byte.
pub(crate) fn signature_for_token(
    signature: &[u8],
    kind: KeyKind,
    field_len: usize,
) -> Option<Vec<u8>> {
    match kind {
        KeyKind::Rsa | KeyKind::MlDsa(_) => Some(signature.to_vec()),
        KeyKind::Ec => {
            let parsed = EcdsaSignature::from_der(signature).ok()?;
            let r = parsed.r.as_bytes();
            let s = parsed.s.as_bytes();
            if r.len() > field_len || s.len() > field_len {
                return None;
            }
            let mut out = vec![0u8; field_len * 2];
            out[field_len - r.len()..field_len].copy_from_slice(r);
            out[field_len * 2 - s.len()..].copy_from_slice(s);
            Some(out)
        }
    }
}

/// Returns the size in bytes of a single coordinate of the key in `spki`, for keys where that is
/// meaningful. An uncompressed point is a leading `0x04` followed by two coordinates of equal size.
pub(crate) fn ec_field_len(spki: &SubjectPublicKeyInfoOwned) -> Option<usize> {
    let point = spki.subject_public_key.as_bytes()?;
    if point.first() != Some(&0x04) || point.len() < 3 || point.len() % 2 == 0 {
        return None;
    }
    Some((point.len() - 1) / 2)
}

/// Wraps a digest in the `DigestInfo` structure that PKCS #1 v1.5 verification is defined over.
///
/// certval's digest interface hands over a bare hash, whereas `CKM_RSA_PKCS` verifies the encoded
/// `DigestInfo`, so the naming of the hash algorithm has to be restored here before the token sees
/// it.
pub(crate) fn digest_info(hash_oid: const_oid::ObjectIdentifier, digest: &[u8]) -> Option<Vec<u8>> {
    DigestInfo {
        algorithm: spki::AlgorithmIdentifierOwned {
            oid: hash_oid,
            // RFC 4055 requires the parameters be present and NULL for these hash algorithms.
            parameters: Some(der::Any::null()),
        },
        digest: OctetString::new(digest).ok()?,
    }
    .to_der()
    .ok()
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
#[derive(Sequence)]
struct EcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
#[derive(Sequence)]
struct DigestInfo {
    algorithm: spki::AlgorithmIdentifierOwned,
    digest: OctetString,
}
