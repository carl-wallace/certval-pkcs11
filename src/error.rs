//! Errors surfaced while opening or using a PKCS #11 module.
//!
//! These are returned by the constructors. They are deliberately absent from the callback
//! implementations, which return [`certval::Error`] because that is what the interfaces they implement
//! require; a callback that cannot proceed reports `certval::Error::Unrecognized` so the environment
//! falls through to the next registered implementation.

use core::fmt;

/// Result alias for the fallible operations in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur while opening a PKCS #11 module or preparing a session.
#[derive(Debug)]
pub enum Error {
    /// The module could not be loaded, initialized or queried.
    Pkcs11(cryptoki::error::Error),

    /// The module exposes no slot with a token present, so no session can be opened.
    NoTokenPresent,

    /// A token label was requested but no slot with a token of that label was found. The label
    /// sought is included.
    TokenNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pkcs11(e) => write!(f, "PKCS #11 module error: {e}"),
            Error::NoTokenPresent => write!(f, "the module exposes no slot with a token present"),
            Error::TokenNotFound(label) => {
                write!(f, "no slot holds a token labelled \"{label}\"")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Pkcs11(e) => Some(e),
            _ => None,
        }
    }
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        Error::Pkcs11(e)
    }
}
