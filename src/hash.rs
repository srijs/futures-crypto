//! Hash algorithms for computing digests of streams.

use std::fmt::{Debug, Formatter, Result as FmtResult};

use futures::{Async, Future, Poll, Stream};
use futures::sync::oneshot;
use hex::ToHex;
use openssl;

use super::Error;

/// Stream adapter that computes a hash over the data while forwarding it.
#[derive(Debug)]
pub struct Hash<S> {
    inner: HashInner<S>
}

impl<S: Stream> Hash<S> {
    /// Given an algorithm, create a new stream adapter.
    pub fn new(algo: Algorithm, inner: S) -> Result<Self, Error> {
        Ok(Hash { inner: HashInner::new(algo, inner)? })
    }

    /// Compute the hash digest and reset the internal hashing state.
    pub fn digest(&mut self) -> Result<Digest, Error> {
        self.inner.digest()
    }

    /// Split the stream adapter into two halves, one to receive the computed digest,
    /// and one to compute the hash over the stream.
    ///
    /// This is very useful for situations where ownership of the stream carrying the data
    /// needs to be transferred to a place that does not return it,
    /// such as a [hyper](https://hyper.rs/) client request or server response.
    ///
    /// The receiving half (`SplitDigest`) is a future that resolves with the digest
    /// as soon as the stream has been fully processed by the computing half.
    ///
    /// The computing half (`SplitHash`), similar to `Hash` itself, is a stream adapter
    /// that computes the hash over the data of its underlying stream.
    pub fn split(self) -> (SplitDigest, SplitHash<S>) {
        let (tx, rx) = oneshot::channel();
        let receive = SplitDigest { receiver: rx };
        let compute = SplitHash { inner: self.inner, sender: Some(tx) };
        (receive, compute)
    }

    /// Extract the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S: Stream> Stream for Hash<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<S::Item>, S::Error> {
        self.inner.poll()
    }
}

/// The receiving half of a split hashing process.
///
/// This is a future that resolves with the digest as soon as the stream
/// has been fully consumed.
/// It resolves with `None` when the computing half is dropped prematurely.
///
/// See [`Hash::split`](struct.Hash.html#method.split) for more information.
#[derive(Debug)]
pub struct SplitDigest {
    receiver: oneshot::Receiver<Result<Digest, Error>>
}

impl Future for SplitDigest {
    type Item = Option<Digest>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.receiver.poll() {
            Err(_) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(result)) => result.map(|digest| Async::Ready(Some(digest)))
        }
    }
}

/// The computing half of a split hashing process.
///
/// See [`Hash::split`](struct.Hash.html#method.split) for more information.
#[derive(Debug)]
pub struct SplitHash<S> {
    inner: HashInner<S>,
    sender: Option<oneshot::Sender<Result<Digest, Error>>>
}

impl<S: Stream> SplitHash<S> {
    /// Extract the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S: Stream> Stream for SplitHash<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.inner.poll() {
            Err(err) => Err(err),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(Some(item))) => Ok(Async::Ready(Some(item))),
            Ok(Async::Ready(None)) => {
                if let Some(sender) = self.sender.take() {
                    sender.send(self.inner.digest()).ok();
                }
                Ok(Async::Ready(None))
            }
        }
    }
}

struct HashInner<S> {
    inner: S,
    hasher: openssl::hash::Hasher,
    algorithm: Algorithm
}

impl<S: Debug> Debug for HashInner<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("HashInner")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Stream> HashInner<S> {
    fn new(algorithm: Algorithm, inner: S) -> Result<Self, Error> {
        let hasher = openssl::hash::Hasher::new(algorithm.into_message_digest())
            .map_err(Error)?;
        Ok(HashInner { inner, hasher, algorithm })
    }

    fn digest(&mut self) -> Result<Digest, Error> {
        self.hasher.finish2().map(|bytes| {
            Digest {
                bytes: bytes,
                algorithm: self.algorithm
            }
        }).map_err(Error)
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Stream> Stream for HashInner<S>
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
pub struct Digest {
    bytes: openssl::hash::DigestBytes,
    algorithm: Algorithm
}

impl Digest {
    /// Get the algorithm that was used to compute the digest.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Convert the digest into a hex-encoded string.
    pub fn to_hex_string(&self) -> String {
        self.bytes.to_hex()
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &*self.bytes
    }
}

/// Algorithm that can be used to hash data.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    use futures::{Future, Stream};
    use futures::stream::iter_ok;

    use super::{Algorithm, Error,  Hash};

    #[test]
    fn sha1() {
        let input = iter_ok::<_, Error>(vec!["foo", "bar", "baz", "quux"]);
        let mut hash = Hash::new(Algorithm::Sha1, input).unwrap();
        let output = hash.by_ref().wait().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(output, vec!["foo", "bar", "baz", "quux"]);
        let digest = hash.digest().unwrap();
        assert_eq!(digest.algorithm(), Algorithm::Sha1);
        assert_eq!(digest.to_hex_string(), "d663229325c61c5e5fd52f503961aab83e902313");
    }

    #[test]
    fn split_sha1() {
        let input = iter_ok::<_, Error>(vec!["foo", "bar", "baz", "quux"]);
        let (split_digest, split_hash) = Hash::new(Algorithm::Sha1, input).unwrap().split();
        let output = split_hash.wait().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(output, vec!["foo", "bar", "baz", "quux"]);
        let digest = split_digest.wait().unwrap().unwrap();
        assert_eq!(digest.algorithm(), Algorithm::Sha1);
        assert_eq!(digest.to_hex_string(), "d663229325c61c5e5fd52f503961aab83e902313");
    }

    #[test]
    fn split_drop() {
        let input = iter_ok::<_, Error>(vec!["foo", "bar", "baz", "quux"]);
        let (split_digest, split_hash) = Hash::new(Algorithm::Sha1, input).unwrap().split();
        drop(split_hash);
        assert!(split_digest.wait().unwrap().is_none());
    }
}
