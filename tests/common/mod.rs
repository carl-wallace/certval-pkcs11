//! Shared harness for the collection tests.
//!
//! Everything the tests operate on is named by an environment variable, so no certificates are
//! carried in this repository. That keeps a copy of a PKITS-shaped collection from being duplicated
//! here purely to test a crate whose interest in those certificates begins and ends at "a signature
//! over some bytes by a key".

use certval::*;
use certval_pkcs11::Pkcs11Crypto;
use der::Decode;
use std::path::PathBuf;
use std::sync::Arc;
use x509_cert::Certificate;

/// Path to the PKCS #11 module under test.
pub const MODULE: &str = "CERTVAL_PKCS11_MODULE";
/// Label of the token to use, when the module exposes more than one.
pub const TOKEN_LABEL: &str = "CERTVAL_PKCS11_TOKEN_LABEL";
/// Directory of RSA-signed certificates.
pub const RSA_CERTS: &str = "CERTVAL_PKCS11_RSA_CERTS";
/// Directory of ECDSA-signed certificates.
pub const ECDSA_CERTS: &str = "CERTVAL_PKCS11_ECDSA_CERTS";
/// Directory of ML-DSA-signed certificates.
pub const MLDSA_CERTS: &str = "CERTVAL_PKCS11_MLDSA_CERTS";

/// The largest number of certificate pairs a single collection run will exercise. The PKITS-shaped
/// trees the harness points at by default yield 463 to 468 pairs, so the cap sits clear of them and
/// every pair is covered. Keeping it clear matters, because `pairs` walks the collection in
/// `read_dir` order and stops once the cap is reached: what a biting cap drops is a deterministic
/// tail of the filesystem, so coverage would silently exclude the same certificates on every run.
/// When it does bite, the run says so.
pub const MAX_PAIRS: usize = 512;

/// Reads an environment variable, returning `None` when it is unset or empty.
pub fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Opens the module named by the environment, or reports why the caller should skip.
pub fn open_provider() -> std::result::Result<Arc<Pkcs11Crypto>, String> {
    let module = env(MODULE).ok_or_else(|| format!("{MODULE} is not set"))?;
    let label = env(TOKEN_LABEL);
    Pkcs11Crypto::open(&module, label.as_deref())
        .map(Arc::new)
        .map_err(|e| format!("could not open {module}: {e}"))
}

/// Loads every certificate in `dir`, ignoring files that do not parse as one.
pub fn load_certs(dir: &str) -> std::result::Result<Vec<Certificate>, String> {
    let path = PathBuf::from(dir);
    let entries =
        std::fs::read_dir(&path).map_err(|e| format!("could not read {}: {e}", path.display()))?;

    let mut certs = vec![];
    let mut unparsed = 0usize;
    for entry in entries.flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        match Certificate::from_der(bytes.as_slice()) {
            Ok(cert) => certs.push(cert),
            Err(_) => unparsed += 1,
        }
    }

    if certs.is_empty() {
        return Err(format!(
            "{} holds no parseable certificates ({unparsed} files skipped)",
            path.display()
        ));
    }
    Ok(certs)
}

/// A certificate together with a certificate whose subject matches its issuer, which is the unit a
/// verification callback is handed.
pub struct Pair {
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
    pub alg: spki::AlgorithmIdentifierOwned,
    pub issuer_spki: spki::SubjectPublicKeyInfoOwned,
}

/// Builds the verifiable pairs present in a set of certificates.
///
/// Every issuer whose subject matches is paired, including a self-signed certificate with itself,
/// and including pairings that will not verify - a collection built to exercise a path validator
/// contains deliberately bad signatures, and those are the more interesting half of the comparison.
pub fn pairs(certs: &[Certificate]) -> (Vec<Pair>, bool) {
    use der::Encode;

    let mut out = vec![];
    let mut capped = false;

    'outer: for cert in certs {
        for candidate in certs {
            if cert.tbs_certificate().issuer() != candidate.tbs_certificate().subject() {
                continue;
            }
            let (Ok(tbs), Ok(signature)) = (
                cert.tbs_certificate().to_der(),
                cert.signature().as_bytes().ok_or(()),
            ) else {
                continue;
            };
            out.push(Pair {
                tbs,
                signature: signature.to_vec(),
                alg: cert.signature_algorithm().clone(),
                issuer_spki: candidate
                    .tbs_certificate()
                    .subject_public_key_info()
                    .clone(),
            });
            if out.len() >= MAX_PAIRS {
                capped = true;
                break 'outer;
            }
        }
    }

    (out, capped)
}

/// The three environments a collection run compares.
pub struct Environments {
    /// Software only, which supplies the expected answer.
    pub software: PkiEnvironment,
    /// The module first, with software still registered behind it.
    pub with_module: PkiEnvironment,
    /// The module only, which reveals whether the module actually answered.
    pub module_only: PkiEnvironment,
}

impl Environments {
    pub fn build(crypto: &Arc<Pkcs11Crypto>) -> Self {
        let mut software = PkiEnvironment::default();
        software.populate_5280_pki_environment();

        // Registration is additive and ordered, so registering the module before calling
        // populate_5280_pki_environment is what puts it ahead of the software implementations while
        // still leaving the complete software set behind it. Clearing and re-adding by name would
        // work too, but it silently drops whichever software implementations the enabled feature
        // set happens to have installed.
        let mut with_module = PkiEnvironment::default();
        with_module.add_verify_signature_message_callback(crypto.clone());
        with_module.add_verify_signature_digest_callback(crypto.clone());
        with_module.populate_5280_pki_environment();

        let mut module_only = PkiEnvironment::default();
        module_only.populate_5280_pki_environment();
        module_only.clear_verify_signature_message_callbacks();
        module_only.clear_verify_signature_digest_callbacks();
        module_only.add_verify_signature_message_callback(crypto.clone());
        module_only.add_verify_signature_digest_callback(crypto.clone());

        Environments {
            software,
            with_module,
            module_only,
        }
    }
}

/// What the software implementation made of a signature.
///
/// The third case is not a failure and must not be compared against: certval's digest interface covers
/// only RSA, for instance, so it has nothing to say about an ECDSA signature. A module that answers
/// where software cannot is doing its job, not disagreeing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SoftwareVerdict {
    Accept,
    Reject,
    NoOpinion,
}

impl SoftwareVerdict {
    fn of(result: certval::Result<()>) -> Self {
        match result {
            Ok(()) => SoftwareVerdict::Accept,
            Err(Error::Unrecognized) => SoftwareVerdict::NoOpinion,
            Err(_) => SoftwareVerdict::Reject,
        }
    }
}

/// What a collection run observed.
#[derive(Default, Debug)]
pub struct Tally {
    /// Pairs exercised.
    pub pairs: usize,
    /// Pairs the software implementation accepted.
    pub software_accepted: usize,
    /// Pairs the software implementation had no opinion on, because it does not cover the
    /// algorithm. These are excluded from the comparison.
    pub software_no_opinion: usize,
    /// Pairs the module itself answered, with software unavailable to cover for it.
    pub module_answered: usize,
    /// Pairs the module declined, leaving software to answer.
    pub module_declined: usize,
    /// Pairs the module verified that software could not have, which is capability the module adds
    /// rather than merely relocating.
    pub module_only_capability: usize,
    /// Pairs where the module and software both had an opinion and those differed. Must be zero.
    pub disagreements: usize,
}

impl Tally {
    pub fn report(&self, family: &str, interface: &str) {
        println!(
            "{family} / {interface}: {} pairs | software accepted {}, no opinion {} | module answered {}, declined {}, answered where software could not {} | disagreements {}",
            self.pairs,
            self.software_accepted,
            self.software_no_opinion,
            self.module_answered,
            self.module_declined,
            self.module_only_capability,
            self.disagreements
        );
        if self.module_answered == 0 && self.pairs > 0 {
            println!(
                "{family} / {interface}: the module answered nothing, so every verification fell through \
                 to software. This is the expected result for an algorithm the token does not implement."
            );
        }
    }
}

/// The software verdict on a message, taken from the implementations directly rather than through a
/// [`PkiEnvironment`], because the environment reports "everything declined" and "the signature is
/// bad" with the same error and the difference is the whole point here.
fn software_message(pe: &PkiEnvironment, pair: &Pair) -> SoftwareVerdict {
    let verdict = SoftwareVerdict::of(verify_signature_message_rust_crypto(
        pe,
        &pair.tbs,
        &pair.signature,
        &pair.alg,
        &pair.issuer_spki,
    ));

    #[cfg(feature = "pqc")]
    if verdict == SoftwareVerdict::NoOpinion {
        return SoftwareVerdict::of(verify_signature_message_rustcrypto(
            pe,
            &pair.tbs,
            &pair.signature,
            &pair.alg,
            &pair.issuer_spki,
        ));
    }

    verdict
}

/// The software verdict on a digest. certval's digest implementation covers RSA only, so an ECDSA
/// signature reaches it as `NoOpinion`.
fn software_digest(pe: &PkiEnvironment, pair: &Pair, digest: &[u8]) -> SoftwareVerdict {
    SoftwareVerdict::of(verify_signature_digest_rust_crypto(
        pe,
        digest,
        &pair.signature,
        &pair.alg,
        &pair.issuer_spki,
    ))
}

/// Folds one pair's three observations into the tally.
fn record(tally: &mut Tally, software: SoftwareVerdict, combined: bool, alone: bool) {
    tally.pairs += 1;
    match software {
        SoftwareVerdict::Accept => {
            tally.software_accepted += 1;
            if !combined {
                tally.disagreements += 1;
            }
        }
        SoftwareVerdict::Reject => {
            if combined {
                tally.disagreements += 1;
            }
        }
        SoftwareVerdict::NoOpinion => {
            tally.software_no_opinion += 1;
            if alone {
                tally.module_only_capability += 1;
            }
        }
    }

    if alone {
        tally.module_answered += 1;
    } else if software == SoftwareVerdict::Accept {
        // Software could verify it and the module could not, so the module declined and software
        // covered for it.
        tally.module_declined += 1;
    }
}

/// Exercises the message interface over a set of pairs.
pub fn run_message_tests(envs: &Environments, pairs: &[Pair]) -> Tally {
    let mut tally = Tally::default();
    for pair in pairs {
        let software = software_message(&envs.software, pair);

        let combined = envs
            .with_module
            .verify_signature_message(
                &envs.with_module,
                &pair.tbs,
                &pair.signature,
                &pair.alg,
                &pair.issuer_spki,
            )
            .is_ok();

        let alone = envs
            .module_only
            .verify_signature_message(
                &envs.module_only,
                &pair.tbs,
                &pair.signature,
                &pair.alg,
                &pair.issuer_spki,
            )
            .is_ok();

        record(&mut tally, software, combined, alone);
    }
    tally
}

/// Exercises the digest interface over a set of pairs, hashing with software so the comparison isolates
/// verification.
pub fn run_digest_tests(envs: &Environments, pairs: &[Pair]) -> Tally {
    let mut tally = Tally::default();
    for pair in pairs {
        let Some(hash_alg) = hash_alg_for(&pair.alg) else {
            continue;
        };
        let Ok(digest) = envs
            .software
            .calculate_hash(&envs.software, &hash_alg, &pair.tbs)
        else {
            continue;
        };

        let software = software_digest(&envs.software, pair, &digest);

        let combined = envs
            .with_module
            .verify_signature_digest(
                &envs.with_module,
                &digest,
                &pair.signature,
                &pair.alg,
                &pair.issuer_spki,
            )
            .is_ok();

        let alone = envs
            .module_only
            .verify_signature_digest(
                &envs.module_only,
                &digest,
                &pair.signature,
                &pair.alg,
                &pair.issuer_spki,
            )
            .is_ok();

        record(&mut tally, software, combined, alone);
    }
    tally
}

/// The hash a signature algorithm digests with, for the algorithms that have a digest interface at all.
fn hash_alg_for(alg: &spki::AlgorithmIdentifierOwned) -> Option<spki::AlgorithmIdentifierOwned> {
    let oid = match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA224 => PKIXALG_SHA224,
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA256 => PKIXALG_SHA256,
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA384 => PKIXALG_SHA384,
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION | PKIXALG_ECDSA_WITH_SHA512 => PKIXALG_SHA512,
        _ => return None,
    };
    Some(spki::AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    })
}
