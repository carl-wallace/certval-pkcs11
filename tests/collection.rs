//! Verifies a collection of certificates through a PKCS #11 module and compares the result against the
//! software implementation certval ships with.
//!
//! The collections are named by environment variables rather than carried here; see `README.md`. A test
//! whose collection is not configured reports that and passes, so the suite is green on a machine with
//! no module installed, and covers what it says it covers on one that has.
//!
//! The assertion that matters in every case is **agreement**: for every certificate, the module and
//! software must reach the same verdict. A collection assembled to exercise a path validator contains
//! signatures that are supposed to fail, and those carry as much weight here as the ones that pass -
//! a provider that accepted everything would satisfy a positive-only test.

mod common;

use certval::*;
use common::*;
use std::sync::Arc;

/// Reports what the environment has configured, so a run that covers little says so plainly rather
/// than passing quietly.
#[test]
fn harness_configuration_is_reported() {
    println!("{MODULE} = {:?}", env(MODULE));
    println!("{TOKEN_LABEL} = {:?}", env(TOKEN_LABEL));
    println!("{RSA_CERTS} = {:?}", env(RSA_CERTS));
    println!("{ECDSA_CERTS} = {:?}", env(ECDSA_CERTS));
    println!("{MLDSA_CERTS} = {:?}", env(MLDSA_CERTS));

    match open_provider() {
        Ok(crypto) => println!("token label = {:?}", crypto.token_label()),
        Err(why) => println!("no module: {why}"),
    }
}

/// Runs one family through both interfaces. Returns the number of pairs the module answered itself, so
/// the caller can tell whether the module was exercised or merely bypassed.
fn run_family(family: &str, dir_var: &str) -> usize {
    let Some(dir) = env(dir_var) else {
        println!("{family}: skipped, {dir_var} is not set");
        return 0;
    };
    let crypto = match open_provider() {
        Ok(c) => c,
        Err(why) => {
            println!("{family}: skipped, {why}");
            return 0;
        }
    };

    let certs = load_certs(&dir).unwrap_or_else(|e| panic!("{family}: {e}"));
    let (pairs, capped) = pairs(&certs);
    if capped {
        println!(
            "{family}: capped at {MAX_PAIRS} pairs; {} certificates in the collection yield more",
            certs.len()
        );
    }
    assert!(
        !pairs.is_empty(),
        "{family}: {} certificates yielded no issuer/subject pairs, so nothing was verified",
        certs.len()
    );

    let envs = Environments::build(&crypto);

    let message = run_message_tests(&envs, &pairs);
    message.report(family, "message");
    assert_eq!(
        message.disagreements, 0,
        "{family}: the module and software disagreed on {} of {} certificates in the message interface",
        message.disagreements, message.pairs
    );

    let digest = run_digest_tests(&envs, &pairs);
    digest.report(family, "digest");
    assert_eq!(
        digest.disagreements, 0,
        "{family}: the module and software disagreed on {} of {} certificates in the digest interface",
        digest.disagreements, digest.pairs
    );

    println!(
        "{family}: {} distinct issuer keys held in the module's key cache",
        crypto.cached_key_count()
    );

    message.module_answered + digest.module_answered
}

#[test]
fn rsa_module_agrees_with_software() {
    run_family("RSA", RSA_CERTS);
}

#[test]
fn ecdsa_module_agrees_with_software() {
    run_family("ECDSA", ECDSA_CERTS);
}

#[test]
fn ml_dsa_module_agrees_with_software() {
    run_family("ML-DSA", MLDSA_CERTS);
}

/// The end-to-end assertion the crate exists to make: with a module configured and at least one
/// collection pointed at, the module must actually verify something. Without this a run in which every
/// verification quietly fell through to software would look identical to a working one.
#[test]
fn module_is_not_silently_bypassed() {
    if open_provider().is_err() {
        println!("skipped, no module configured");
        return;
    }
    let configured: Vec<&str> = [RSA_CERTS, ECDSA_CERTS, MLDSA_CERTS]
        .into_iter()
        .filter(|v| env(v).is_some())
        .collect();
    if configured.is_empty() {
        println!("skipped, no collection configured");
        return;
    }

    let answered: usize = [("RSA", RSA_CERTS), ("ECDSA", ECDSA_CERTS)]
        .into_iter()
        .filter(|(_, v)| env(v).is_some())
        .map(|(family, v)| run_family(family, v))
        .sum();

    // ML-DSA is deliberately excluded from this assertion. No widely available token implements it
    // yet, so requiring the module to answer it would make the test a statement about the token
    // rather than about this crate; the ML-DSA collection test still asserts agreement.
    if [RSA_CERTS, ECDSA_CERTS].iter().any(|v| env(v).is_some()) {
        assert!(
            answered > 0,
            "a module is configured and an RSA or ECDSA collection was supplied, but the module \
             answered no verification at all - every one fell through to software"
        );
    }
}

/// The key cache is what keeps verification to one token round trip per issuer instead of three per
/// signature, so its behaviour is asserted rather than assumed.
#[test]
fn key_cache_holds_one_entry_per_issuer() {
    let Some(dir) = env(RSA_CERTS).or_else(|| env(ECDSA_CERTS)) else {
        println!("skipped, no collection configured");
        return;
    };
    let Ok(crypto) = open_provider() else {
        println!("skipped, no module configured");
        return;
    };

    let certs = load_certs(&dir).unwrap_or_else(|e| panic!("{e}"));
    let (pairs, _) = pairs(&certs);

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.clear_verify_signature_message_callbacks();
    pe.add_verify_signature_message_callback(Arc::clone(&crypto));

    let mut distinct = std::collections::BTreeSet::new();
    for pair in &pairs {
        use der::Encode;
        let _ = pe.verify_signature_message(
            &pe,
            &pair.tbs,
            &pair.signature,
            &pair.alg,
            &pair.issuer_spki,
        );
        if let Ok(encoded) = pair.issuer_spki.to_der() {
            distinct.insert(encoded);
        }
    }

    let cached = crypto.cached_key_count();
    println!("{} distinct issuer keys, {cached} cached", distinct.len());
    assert!(
        cached <= distinct.len(),
        "the cache holds {cached} entries for {} distinct issuer keys, so keys are being imported \
         more than once",
        distinct.len()
    );

    crypto.clear_key_cache();
    assert_eq!(crypto.cached_key_count(), 0);
}
