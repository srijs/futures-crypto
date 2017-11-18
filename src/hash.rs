//! Hash algorithms for computing digests of streams.

use std::fmt::{Debug, Formatter, Result as FmtResult};

use futures::{Async, Poll, Stream};
use hex::ToHex;
use openssl;

use super::Error;

/// Stream adapter that computes a hash over the data while forwarding it.
pub struct Hash<S> {
    inner: S,
    hasher: openssl::hash::Hasher
}

impl<S: Debug> Debug for Hash<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("StreamHasher")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Stream> Hash<S> {
    /// Given an algorithm, create a new stream adapter.
    pub fn new(algo: Algorithm, inner: S) -> Result<Self, Error> {
        let hasher = openssl::hash::Hasher::new(algo.into_message_digest())
            .map_err(Error)?;
        Ok(Hash { inner, hasher })
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

impl<S: Stream> Stream for Hash<S>
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
#[derive(Debug)]
pub struct Digest(openssl::hash::DigestBytes);

impl Digest {
    /// Convert the digest into a hex-encoded string.
    pub fn to_hex_string(&self) -> String {
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
    /// MD-5
    Md5,
    /// SHA-1
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
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

#[cfg(test)]
mod test {
    use futures::Stream;
    use futures::stream::iter_ok;

    use super::{Algorithm, Error,  Hash};

    #[test]
    fn stream_sha1() {
        let input = iter_ok::<_, Error>(vec!["foo", "bar", "baz", "quux"]);
        let mut hash = Hash::new(Algorithm::Sha1, input).unwrap();
        let output = hash.by_ref().wait().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(output, vec!["foo", "bar", "baz", "quux"]);
        let digest = hash.digest().unwrap();
        assert_eq!(digest.to_hex_string(), "d663229325c61c5e5fd52f503961aab83e902313");
    }
}
