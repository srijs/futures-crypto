extern crate bytes;
extern crate futures;
extern crate openssl;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub mod cipher;
pub mod hash;

#[derive(Clone, Debug)]
pub struct Error(openssl::error::ErrorStack);
