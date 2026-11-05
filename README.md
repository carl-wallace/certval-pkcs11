# certval-pkcs11

A PKCS #11 crypto provider for [certval](https://github.com/carl-wallace/rust-pki). It supplies
implementations of the hashing and signature verification callbacks that a `PkiEnvironment` dispatches
through, so certification path validation can be performed using the cryptographic implementation a
deployment is obliged to use rather than the in-process software one.

Only public-key operations are involved. Verification and hashing operate entirely on public data, so
the session is a public session and no `C_Login` is performed; a token PIN is neither required nor
accepted. Signing and decryption are outside this crate's scope.

```rust
use certval::PkiEnvironment;
use certval_pkcs11::Pkcs11Crypto;
use std::sync::Arc;

let crypto = Arc::new(Pkcs11Crypto::open("/usr/lib/softhsm/libsofthsm2.so", None)?);

let mut pe = PkiEnvironment::default();

// Registering before populate_5280_pki_environment puts the module ahead of the software
// implementations, so it is consulted first and software answers only what it declined.
pe.add_verify_signature_message_callback(crypto.clone());
pe.add_verify_signature_digest_callback(crypto.clone());
pe.add_calculate_hash_callback(crypto);

pe.populate_5280_pki_environment();
```

One value implements all three interfaces, because they share a session, a key cache and the algorithm
table; register the same value in each role rather than opening the module three times.

## Registration is additive

`PkiEnvironment` consults registered implementations in order and stops at the first verdict. The
provider reports a rejection only when the token judged the signature invalid; anything else it
declines, and a declined verification falls through to the next implementation. That is what lets a
module answer for the algorithms it offers while software covers the rest.

It also means registering this provider does not by itself guarantee that every verification reaches
the module. A caller who requires that must make the registration exclusive:

```rust
pe.populate_5280_pki_environment();
pe.clear_verify_signature_message_callbacks();
pe.clear_verify_signature_digest_callbacks();
pe.add_verify_signature_message_callback(crypto.clone());
pe.add_verify_signature_digest_callback(crypto);
```

Note also that a `SignatureVerificationCache`, if one is registered, short-circuits repeat
verifications before any callback runs. It is not installed by `populate_5280_pki_environment`, so a
caller wanting every verification to reach the module simply does not add one.

## Algorithm coverage

| Signature algorithm | Message interface | Digest interface |
|---|---|---|
| RSA PKCS #1 v1.5, SHA-224/256/384/512 | `CKM_SHA*_RSA_PKCS` | `CKM_RSA_PKCS` |
| RSASSA-PSS, SHA-256/384/512 | `CKM_SHA*_RSA_PKCS_PSS` | `CKM_RSA_PKCS_PSS` |
| ECDSA, SHA-224/256/384/512 | `CKM_ECDSA_SHA*` | `CKM_ECDSA` |
| ML-DSA 44/65/87 | `CKM_ML_DSA` | not applicable |

Anything else is declined, and software answers it.

PSS with SHA-224 has no hash-and-verify mechanism in PKCS #11, so it has no message form here.
ML-DSA signs the message itself and has no digest-only form, so a caller holding only a digest cannot
verify one — its absence from the digest column is by definition rather than by omission.

Three encoding differences between X.509 and PKCS #11 are bridged internally, and each is a place
where a provider that ignored it would appear to work and then reject valid signatures:

- an EC point travels in a certificate as raw `BIT STRING` bytes, while `CKA_EC_POINT` wants it
  wrapped in a DER `OCTET STRING`;
- an ECDSA signature travels as `SEQUENCE { r, s }`, while PKCS #11 uses fixed-width `r‖s`;
- `CKM_RSA_PKCS` verifies a `DigestInfo`, while certval's digest interface supplies a bare hash.

## Cost, and the key cache

certval hands a verification callback a raw `SubjectPublicKeyInfo`, whereas PKCS #11 verifies against
a key object. Importing a key per signature would mean `C_CreateObject`, `C_VerifyInit` + `C_Verify`
and `C_DestroyObject` on every call. Path validation repeatedly verifies certificates issued under the
same handful of CA keys, so imported keys are cached by a hash of the encoded key, which collapses
that to a single round trip for every repeat issuer. `Pkcs11Crypto::cached_key_count` reports the
cache size and `clear_key_cache` empties it, for a long-lived process seeing an unbounded set of
issuers.

## CMS

With the `cms` feature, a private key on a token serves as a
[certval-cms](https://github.com/carl-wallace/certval-cms) credential. A `Pkcs11Token` is a
logged-in session; `Pkcs11RecipientKey` decrypts with a key on it and `Pkcs11SigningKey` signs, and
`TokenIdentities` finds both among the token's certificates, each paired with the private key that
has the same `CKA_ID`: a decryption key by the recipient identifier a message contains, and signing
keys by signer identifier, email address or subject.

```rust
use certval_cms::CmsEnvironment;
use certval_pkcs11::{Pkcs11Token, TokenIdentities};
use cryptoki::types::AuthPin;
use std::sync::Arc;

let pin = AuthPin::new("1234".into());
let token = Arc::new(Pkcs11Token::open("/usr/lib/softhsm/libsofthsm2.so", Some("certval"), &pin)?);
let mut env = CmsEnvironment::new();
env.add_recipient_credential_source(TokenIdentities::new(token.clone()));
env.add_signing_credential_source(TokenIdentities::new(token));
```

| Operation | Mechanism |
|---|---|
| RSAES-PKCS1-v1_5 key transport | `CKM_RSA_X_509`, unpadded in constant time by certval-cms; `CKM_RSA_PKCS` where the token offers no raw RSA |
| RSAES-OAEP key transport | `CKM_RSA_PKCS_OAEP` with SHA-1/256/384/512 |
| Key agreement | `CKM_ECDH1_DERIVE` with no KDF; certval-cms's X9.63 KDF and AES key unwrap |
| KEM | `C_DecapsulateKey` with `CKM_ML_KEM`; certval-cms's HKDF and AES key unwrap |
| Signing | the mechanism the signature algorithm calls for, over the message where the token hashes and over the digest otherwise: RSA PKCS #1 v1.5 and RSASSA-PSS, ECDSA, ML-DSA |

Raw RSA keeps the token's padding check from becoming an oracle: certval-cms removes the padding in
constant time, and a failed key transport goes on with a random content-encryption key (RFC 3218).
For key agreement and KEM the token returns the shared secret, which therefore leaves it; the
key-encryption key is derived outside.

A mechanism the token does not offer is the credential declining, which a decryption reports as
`Unrecognized`. SoftHSM 2.7, for one, offers RSAES-OAEP only with SHA-1 and has no ML-KEM or
ML-DSA.

PKCS #11 logs a user in for the whole process, so opening a second `Pkcs11Token` on the same token
finds the user already logged in, which is not an error, and nothing logs out, since that would end
the login for every session.

## Testing

The tests verify a collection of certificates through a module and compare the result against certval's
software implementation. **No certificates are carried in this repository**: the test suites are named by
environment variables, so a PKITS-shaped tree that already exists elsewhere is used where it lies.

| Variable | Meaning |
|---|---|
| `CERTVAL_PKCS11_MODULE` | path to the PKCS #11 module; when unset every module test reports that it skipped and passes |
| `CERTVAL_PKCS11_TOKEN_LABEL` | token to use when the module exposes more than one; the first slot with a token present is used otherwise |
| `CERTVAL_PKCS11_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_PKCS11_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_PKCS11_MLDSA_CERTS` | directory of ML-DSA-signed certificates |
| `CERTVAL_PKCS11_USER_PIN` | the user PIN, for the CMS tests; when unset they report that they skipped and pass |

Each directory is read for anything that parses as a certificate; every certificate is paired with
every certificate whose subject matches its issuer, and both are verified. A collection assembled to
exercise a path validator contains signatures that are supposed to fail, and those carry as much
weight here as the ones that pass — a provider that accepted everything would satisfy a positive-only
test. Runs are capped at 512 pairs per collection, and a run that hits the cap says so.

The assertion in each case is **agreement**, not success. Software having no opinion is tracked
separately from software disagreeing, because certval's digest implementation covers RSA only and a
module that verifies an ECDSA digest is adding capability rather than contradicting anything.

```sh
export SOFTHSM2_CONF=$PWD/softhsm2.conf
softhsm2-util --init-token --slot 0 --label certval --so-pin 1234 --pin 1234

export CERTVAL_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export EX=../rust-pki/certval/tests/examples
export CERTVAL_PKCS11_RSA_CERTS=$EX/PKITS_data_2048/certs
export CERTVAL_PKCS11_ECDSA_CERTS=$EX/PKITS_data_p256/certs
export CERTVAL_PKCS11_MLDSA_CERTS=$EX/pkits_ml_dsa_44/certs

export CERTVAL_PKCS11_USER_PIN=1234
cargo test --features pqc,cms -- --nocapture
```

With the `cms` feature, the CMS tests generate each key on the token, so its private half never
leaves it, and store a certificate for it beside it, issued by a CA in software. certval-cms's
RustCrypto software builds messages to the certificate and verifies the signatures; the token's
credential decrypts and signs. They cover key transport with every algorithm, ECDH on P-256, P-384
and P-521 with each KDF hash and AES key wrap, ML-KEM-512/768/1024 with each KDF and wrap, signing
with RSA PKCS #1 v1.5 and RSASSA-PSS, ECDSA and ML-DSA, and the credentials found through
`TokenIdentities`. A case the token does not offer is skipped, and the test says so.

The `pqc` feature is needed only for the ML-DSA tests: it enables certval's software ML-DSA
implementation so there is something to compare the module against. The provider itself needs nothing
from it, so it is off by default.

A released SoftHSM implements no ML-DSA mechanism, so against one the ML-DSA collection exercises the
fall-through path rather than the module: the provider declines and software answers. That is a
result worth having — "try hardware, fall back for unsupported algorithms" is the behaviour most
deployments actually want. ML-DSA landed on SoftHSM's `main` branch after 2.7.0, so a build from
source against OpenSSL 3.5 or later does implement it, and the ML-DSA collection then exercises the
module as the others do.

## Status

Tested against SoftHSM only (see [Testing](#testing)); it has not yet been run against a hardware
module, whose mechanism support, session limits and initialization behaviour can differ.

With the `cms` feature, every CMS test passes against SoftHSM built from `main`, none skipped. Against
SoftHSM 2.7.0 they pass with ML-KEM, ML-DSA and RSAES-OAEP with SHA-2 skipped.

certval-cms is not on crates.io yet, so `Cargo.toml`'s `[patch.crates-io]` takes it from a
neighboring checkout (`../certval-cms`), and CI checks it out there. Both go when it publishes, and
this crate cannot publish before it does.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
