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

`PkiEnvironment` consults registered implementations in order and takes the first success, so an
implementation that declines — or that rejects a signature — falls through to the next. That is what
lets a module answer for the algorithms it offers while software covers the rest.

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

Each directory is read for anything that parses as a certificate; every certificate is paired with
every certificate whose subject matches its issuer, and both are verified. A collection assembled to
exercise a path validator contains signatures that are supposed to fail, and those carry as much
weight here as the ones that pass — a provider that accepted everything would satisfy a positive-only
test. Runs are capped at 400 pairs per collection, and a run that hits the cap says so.

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

cargo test --features pqc -- --nocapture
```

The `pqc` feature is needed only for the ML-DSA tests: it enables certval's software ML-DSA
implementation so there is something to compare the module against. The provider itself needs nothing
from it, and it is off by default because certval's `pqc` feature carries a git dependency.

A released SoftHSM implements no ML-DSA mechanism, so against one the ML-DSA collection exercises the
fall-through path rather than the module: the provider declines and software answers. That is a
result worth having — "try hardware, fall back for unsupported algorithms" is the behaviour most
deployments actually want. ML-DSA landed on SoftHSM's `main` branch after 2.7.0, so a build from
source against OpenSSL 3.5 or later does implement it, and the ML-DSA collection then exercises the
module as the others do.

## Status

certval is consumed from rust-pki as a git dependency, pinned to a revision rather than to a branch:
the crate is unpublished and stays at 0.1.0 whatever changes, so tracking a branch would take
interface changes silently on the next `cargo update`. Bump the revision deliberately. It becomes a
crates.io dependency once certval publishes. A commented `[patch]` stanza in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

The `[patch.crates-io]` entry for `x509-ocsp` is inherited from certval and is needed by any consumer
of it until x509-ocsp 0.3 publishes.

## License

Apache-2.0 OR MIT.
