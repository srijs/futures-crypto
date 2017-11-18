//! Utilities for `futures`-based asynchronous cryptography.

#![deny(warnings, missing_docs, missing_debug_implementations)]

extern crate bytes;
extern crate futures;
extern crate futures_cpupool;
extern crate hex;
extern crate openssl;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

mod error;
pub use self::error::Error;

pub mod cipher;
pub mod random;
pub mod hash;
