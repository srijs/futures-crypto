use std::error::{Error as StdError};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{Error as IoError};

use openssl;

#[derive(Debug)]
pub struct Error(pub(crate) openssl::error::ErrorStack);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        self.0.fmt(f)
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        self.0.description()
    }
}

impl From<Error> for IoError {
    fn from(err: Error) -> IoError {
        err.0.into()
    }
}
