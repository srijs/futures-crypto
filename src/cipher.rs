use std::fmt::{Debug, Formatter, Result as FmtResult};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{Async, Poll, Stream};
use openssl;

use super::Error;

pub struct Builder {
    algo: Algorithm,
    key: Vec<u8>,
    iv: Option<Vec<u8>>
}

impl Builder {
    pub fn new(algo: Algorithm, key: &[u8]) -> Builder {
        Builder {
            algo, key: key.to_vec(), iv: None
        }
    }

    pub fn with_iv(mut self, iv: Option<&[u8]>) -> Builder {
        self.iv = iv.map(|iv| iv.to_vec());
        self
    }

    fn stream<S>(self, inner: S, mode: openssl::symm::Mode) -> Result<CipherStream<S>, (S, Error)> {
        let cipher = self.algo.into_cipher();
        let block_size = cipher.block_size();
        let iv = self.iv.as_ref().map(|iv| iv.as_slice());
        match openssl::symm::Crypter::new(cipher, mode, &self.key, iv) {
            Err(err) => Err((inner, Error(err))),
            Ok(crypter) => Ok(CipherStream { inner, crypter, block_size, finalized: false })
        }
    }

    pub fn encrypt<S>(self, inner: S) -> Result<Encrypt<S>, (S, Error)> {
        self.stream(inner, openssl::symm::Mode::Encrypt).map(Encrypt)
    }

    pub fn decrypt<S>(self, inner: S) -> Result<Decrypt<S>, (S, Error)> {
        self.stream(inner, openssl::symm::Mode::Decrypt).map(Decrypt)
    }
}

#[derive(Debug)]
pub struct Encrypt<S>(CipherStream<S>);

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

#[derive(Debug)]
pub struct Decrypt<S>(CipherStream<S>);

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

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Aes128Ecb,
    Aes128Cbc,
    Aes128Ctr,
    Aes128Cfb1,
    Aes128Cfb128,
    Aes128Cfb8,
    Aes256Ecb,
    Aes256Cbc,
    Aes256Ctr,
    Aes256Cfb1,
    Aes256Cfb128,
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

    pub fn key_len(self) -> usize  {
        self.into_cipher().key_len()
    }

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
    use super::{Algorithm, Builder, Error};

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

    #[derive(Clone, Debug)]
    struct CipherParts {
        algo: Algorithm,
        key: Vec<u8>,
        iv: Option<Vec<u8>>
    }

    impl Arbitrary for CipherParts {
        fn arbitrary<G: Gen>(g: &mut G) -> CipherParts {
            let algo = *g.choose(&ALL_ALGOS).unwrap();
            let key = g.gen_iter().take(algo.key_len()).collect::<Vec<u8>>();
            let iv = algo.iv_len().map(|iv_len| g.gen_iter().take(iv_len).collect::<Vec<u8>>());
            CipherParts { algo, key, iv }
        }
    }

    quickcheck! {
        fn roundtrip(parts: CipherParts, chunks: Vec<Vec<u8>>) -> bool {
            let inner = ::futures::stream::iter_ok::<_, Error>(chunks.clone());
            let iv = parts.iv.as_ref().map(|iv| iv.as_slice());
            let encrypt = Builder::new(parts.algo, &parts.key)
                .with_iv(iv.clone())
                .encrypt(inner)
                .expect("encrypt build failed");
            let decrypt = Builder::new(parts.algo, &parts.key)
                .with_iv(iv.clone())
                .decrypt(encrypt)
                .expect("decrypt build failed");
            let roundtrip_chunks: Vec<Bytes> = decrypt.wait().collect::<Result<Vec<_>, Error>>()
                .expect("rountrip collect failed");
            let roundtrip_data = roundtrip_chunks.into_iter().concat();
            let data: Vec<u8> = chunks.into_iter().concat();
            data.as_slice() == roundtrip_data.as_ref()
        }
    }
}
