//! Hash algorithms for computing digests of streams.

use futures::{Async, Poll, Stream};
use hex::ToHex;
use openssl;

use super::Error;

/// Stream adapter that computes a hash over the data while forwarding it.
pub struct ForwardHash<S> {
    inner: S,
    hasher: openssl::hash::Hasher
}

impl<S> ForwardHash<S> {
    /// Given an algorithm, create a new stream adapter.
    pub fn new(inner: S, algo: Algorithm) -> Result<ForwardHash<S>, Error> {
        let hasher = openssl::hash::Hasher::new(algo.into_message_digest())
            .map_err(Error)?;
        Ok(ForwardHash { inner, hasher })
    }

    /// Compute the hash digest and reset the internal hashing state.
    pub fn digest(&mut self) -> Result<Digest, Error> {
        self.hasher.finish2().map(Digest).map_err(Error)
    }

    /// Extract the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Stream> Stream for ForwardHash<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<S::Item>, S::Error> {
        match self.inner.poll()? {
            Async::NotReady => Ok(Async::NotReady),
            Async::Ready(None) => Ok(Async::Ready(None)),
            Async::Ready(Some(item)) => {
                self.hasher.update(item.as_ref()).map_err(Error)?;
                Ok(Async::Ready(Some(item)))
            }
        }
    }
}

/// Stack-allocated binary hash digest.
///
/// Can be converted to a hexadecimal representation using `.to_string()`.
pub struct Digest(openssl::hash::DigestBytes);

impl ToString for Digest {
    fn to_string(&self) -> String {
        self.0.to_hex()
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

/// Algorithm that can be used to hash data.
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,

    #[doc(hidden)]
    _Donotmatch
}

impl Algorithm {
    fn into_message_digest(self) -> openssl::hash::MessageDigest {
        match self {
            Algorithm::Md5 => openssl::hash::MessageDigest::md5(),
            Algorithm::Sha1 => openssl::hash::MessageDigest::sha1(),
            Algorithm::Sha224 => openssl::hash::MessageDigest::sha224(),
            Algorithm::Sha256 => openssl::hash::MessageDigest::sha256(),
            Algorithm::Sha384 => openssl::hash::MessageDigest::sha384(),
            Algorithm::Sha512 => openssl::hash::MessageDigest::sha512(),
            Algorithm::_Donotmatch => unreachable!()
        }
    }
}
