extern crate bytes;
extern crate futures;
extern crate openssl;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub mod cipher;

#[derive(Clone, Debug)]
pub struct Error(openssl::error::ErrorStack);
