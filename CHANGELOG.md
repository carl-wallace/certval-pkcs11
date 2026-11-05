# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## Unreleased

Added a `cms` feature, under which private keys on a token serve as certval-cms credentials:
`Pkcs11Token` is a logged-in session, `Pkcs11RecipientKey` decrypts KeyTransRecipientInfo (raw RSA
with certval-cms's constant-time unpadding, and RSAES-OAEP), KeyAgreeRecipientInfo (ECDH) and
KEMRecipientInfo (ML-KEM), `Pkcs11SigningKey` signs SignedData with RSA, ECDSA and ML-DSA, and
`TokenIdentities` finds both among the token's certificates by `CKA_ID`. `pqc` also turns on
certval-cms's `pqc` under `cms`.

## [0.1.0-rc.1] - 2026-11-02

Initial release. Calculates SHA-1/224/256/384/512 digests and verifies RSA PKCS #1 v1.5,
RSASSA-PSS, ECDSA and ML-DSA certificate signatures through a PKCS #11 module, through certval's
hashing and verification interfaces. Uses a public session only, so no PIN is needed. Tested against
SoftHSM. MSRV 1.89.
