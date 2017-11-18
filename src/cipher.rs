//! Symmetric ciphers for encryption and decryption of streams.

use std::fmt::{Debug, Formatter, Result as FmtResult};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{Async, Poll, Stream};
use openssl;

use super::Error;

/// Configuration for stream adapters.
#[derive(Clone, Debug)]
pub struct Config {
    algo: Algorithm,
    key: [u8; MAX_KEY_LEN],
    iv: [u8; MAX_IV_LEN]
}

impl Config {
    /// Initialize a config given an algorithm.
    pub fn new(algo: Algorithm) -> Config {
        Config {
            algo, key: [0u8; MAX_KEY_LEN], iv: [0u8; MAX_IV_LEN]
        }
    }

    /// Get a mutable slice of bytes to set the encryption key
    /// to be used for the cipher.
    pub fn key_mut(&mut self) -> &mut [u8] {
        let key_len = self.algo.key_len();
        &mut self.key[..key_len]
    }

    /// Get a mutable slice of bytes to set the [initialization vector]
    /// (https://en.wikipedia.org/wiki/Initialization_vector)
    /// to be used for the cipher.
    ///
    /// Returns `None` if the selected algorithm does not require an IV.
    pub fn iv_mut(&mut self) -> Option<&mut [u8]> {
        match self.algo.iv_len() {
            None => None,
            Some(iv_len) => Some(&mut self.iv[..iv_len])
        }
    }

    fn stream<S>(&self, inner: S, mode: openssl::symm::Mode) -> Result<CipherStream<S>, Error> {
        let cipher = self.algo.into_cipher();
        let block_size = cipher.block_size();
        let iv = cipher.iv_len().map(|iv_len| &self.iv[..iv_len]);
        let key = &self.key[..cipher.key_len()];
        let crypter = openssl::symm::Crypter::new(cipher, mode, key, iv)
            .map_err(Error)?;
        Ok(CipherStream { inner, crypter, block_size, finalized: false })
    }
}

/// Stream adapter that transparently encrypts the data from the underlying stream.
#[derive(Debug)]
pub struct Encrypt<S>(CipherStream<S>);

impl<S: Stream> Encrypt<S> {
    /// Create an encrypting stream adapter.
    pub fn new(config: &Config, inner: S) -> Result<Self, Error> {
        config.stream(inner, openssl::symm::Mode::Encrypt).map(Encrypt)
    }
}

impl<S: Stream> Stream for Encrypt<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = Bytes;
    type Error = S::Error; 

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}

/// Stream adapter that transparently decrypts the data from the underlying stream.
#[derive(Debug)]
pub struct Decrypt<S>(CipherStream<S>);

impl<S: Stream> Decrypt<S> {
    /// Create a decrypting stream adapter.
    pub fn new(config: &Config, inner: S) -> Result<Self, Error> {
        config.stream(inner, openssl::symm::Mode::Decrypt).map(Decrypt)
    }
}

impl<S: Stream> Stream for Decrypt<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = Bytes;
    type Error = S::Error; 

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}

struct CipherStream<S> {
    inner: S,
    finalized: bool,
    crypter: openssl::symm::Crypter,
    block_size: usize
}

impl<S: Debug> Debug for CipherStream<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("CipherStream")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Stream> Stream for CipherStream<S>
    where S::Item: AsRef<[u8]>,
          S::Error: From<Error>
{
    type Item = Bytes;
    type Error = S::Error; 

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.finalized {
            return Ok(Async::Ready(None));
        }
        match self.inner.poll()? {
            Async::NotReady => Ok(Async::NotReady),
            Async::Ready(None) => {
                self.finalized = true;
                let mut output = BytesMut::with_capacity(self.block_size);
                unsafe {
                    let len = self.crypter.finalize(output.bytes_mut())
                        .map_err(|err| Error(err).into())?;
                    output.advance_mut(len);
                }
                Ok(Async::Ready(Some(output.freeze())))
            },
            Async::Ready(Some(item)) => {
                let input = item.as_ref();
                let mut output = BytesMut::with_capacity(input.len() + self.block_size);
                unsafe {
                    let len = self.crypter.update(input, output.bytes_mut())
                        .map_err(|err| Error(err).into())?;
                    output.advance_mut(len);
                }
                Ok(Async::Ready(Some(output.freeze())))
            }
        }
    }
}

const MAX_IV_LEN: usize = 16;
const MAX_KEY_LEN: usize = 32;

/// Algorithm that can be used to encrypt or decrypt data.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    /// AES algorithm with 128-bit keys in Electronic Codebook mode.
    Aes128Ecb,
    /// AES algorithm with 128-bit keys in Cipher Block Chaining mode.
    Aes128Cbc,
    /// AES algorithm with 128-bit keys in Counter mode.
    Aes128Ctr,
    /// AES algorithm with 128-bit keys in Cipher Feedback mode with 1-bit feedback.
    Aes128Cfb1,
    /// AES algorithm with 128-bit keys in Cipher Feedback mode with 128-bit feedback.
    Aes128Cfb128,
    /// AES algorithm with 128-bit keys in Cipher Feedback mode with 8-bit feedback.
    Aes128Cfb8,
    /// AES algorithm with 256-bit keys in Electronic Codebook mode.
    Aes256Ecb,
    /// AES algorithm with 256-bit keys in Cipher Block Chaining mode.
    Aes256Cbc,
    /// AES algorithm with 256-bit keys in Counter mode.
    Aes256Ctr,
    /// AES algorithm with 256-bit keys in Cipher Feedback mode with 1-bit feedback.
    Aes256Cfb1,
    /// AES algorithm with 256-bit keys in Cipher Feedback mode with 128-bit feedback.
    Aes256Cfb128,
    /// AES algorithm with 256-bit keys in Cipher Feedback mode with 8-bit feedback.
    Aes256Cfb8,

    #[doc(hidden)]
    _Donotmatch
}

impl Algorithm {
    fn into_cipher(self) -> openssl::symm::Cipher {
        use openssl::symm::Cipher;
        use self::Algorithm::*;
        match self {
            Aes128Ecb => Cipher::aes_128_ecb(),
            Aes128Cbc => Cipher::aes_128_cbc(),
            Aes128Ctr => Cipher::aes_128_ctr(),
            Aes128Cfb1 => Cipher::aes_128_cfb1(),
            Aes128Cfb128 => Cipher::aes_128_cfb128(),
            Aes128Cfb8 => Cipher::aes_128_cfb8(),
            Aes256Ecb => Cipher::aes_256_ecb(),
            Aes256Cbc => Cipher::aes_256_cbc(),
            Aes256Ctr => Cipher::aes_256_ctr(),
            Aes256Cfb1 => Cipher::aes_256_cfb1(),
            Aes256Cfb128 => Cipher::aes_256_cfb128(),
            Aes256Cfb8 => Cipher::aes_256_cfb8(),
            _Donotmatch => unreachable!()
        }
    }

    /// Get the required key length for the algorithm.
    pub fn key_len(self) -> usize  {
        self.into_cipher().key_len()
    }

    /// Get the required IV length for the algorithm.
    ///
    /// Returns `None` if the algorithm does not require an IV.
    pub fn iv_len(self) -> Option<usize> {
        self.into_cipher().iv_len()
    }
}

#[cfg(test)]
mod test {
    extern crate itertools;

    use bytes::Bytes;
    use futures::Stream;
    use self::itertools::Itertools;
    use quickcheck::{Arbitrary, Gen};
    use super::{Algorithm, Config, Error, Encrypt, Decrypt, MAX_KEY_LEN, MAX_IV_LEN};

    const ALL_ALGOS: [Algorithm; 12] = [
        Algorithm::Aes128Ecb,
        Algorithm::Aes128Cbc,
        Algorithm::Aes128Ctr,
        Algorithm::Aes128Cfb1,
        Algorithm::Aes128Cfb128,
        Algorithm::Aes128Cfb8,
        Algorithm::Aes256Ecb,
        Algorithm::Aes256Cbc,
        Algorithm::Aes256Ctr,
        Algorithm::Aes256Cfb1,
        Algorithm::Aes256Cfb128,
        Algorithm::Aes256Cfb8,
    ];

    impl Arbitrary for Config {
        fn arbitrary<G: Gen>(g: &mut G) -> Config {
            let algo = *g.choose(&ALL_ALGOS).unwrap();
            let mut config = Config::new(algo);
            g.fill_bytes(config.key_mut());
            config.iv_mut().map(|iv| g.fill_bytes(iv));
            config
        }
    }

    quickcheck! {
        fn roundtrip(config: Config, chunks: Vec<Vec<u8>>) -> bool {
            let inner = ::futures::stream::iter_ok::<_, Error>(chunks.clone());
            let encrypt = Encrypt::new(&config, inner)
                .expect("encrypt build failed");
            let decrypt = Decrypt::new(&config, encrypt)
                .expect("decrypt build failed");
            let roundtrip_chunks: Vec<Bytes> = decrypt.wait().collect::<Result<Vec<_>, Error>>()
                .expect("rountrip collect failed");
            let roundtrip_data = roundtrip_chunks.into_iter().concat();
            let data: Vec<u8> = chunks.into_iter().concat();
            data.as_slice() == roundtrip_data.as_ref()
        }
    }

    #[test]
    fn max_key_len() {
        let max_key_len = ALL_ALGOS.iter().map(|algo| algo.key_len()).max().unwrap();
        assert_eq!(max_key_len, MAX_KEY_LEN);
    }

    #[test]
    fn max_iv_len() {
        let max_iv_len = ALL_ALGOS.iter().filter_map(|algo| algo.iv_len()).max().unwrap();
        assert_eq!(max_iv_len, MAX_IV_LEN);
    }
}
