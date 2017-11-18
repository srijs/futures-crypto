//! This crate aims to provide high-level asychronous APIs for cryptographic
//! functions such as symmetric encryption, hashing and random number generation.
//!
//! The APIs provided are based on abstractions from the [`futures`](https://docs.rs/futures)
//! crate.
//!
//! The underlying crytographic operations are provided by OpenSSL.

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
