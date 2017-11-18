# cryptonite [![Build Status](https://travis-ci.org/srijs/rust-cryptonite.svg?branch=master)](https://travis-ci.org/srijs/rust-cryptonite)

This crate aims to provide high-level asychronous APIs for cryptographic
functions such as symmetric encryption, hashing and random number generation.

The APIs provided are based on abstractions from the [`futures`](https://docs.rs/futures)
crate.

The underlying crytographic operations are provided by OpenSSL.
