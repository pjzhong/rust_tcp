use std::io::Error;

use etherparse::{ValueError, WriteError};
#[derive(Debug)]
pub enum TcpErr {
    Io(Error),
    EtherParseErr(WriteError),
    ValueError(ValueError),
}

impl From<Error> for TcpErr {
    fn from(value: Error) -> Self {
        Self::Io(value)
    }
}

impl From<WriteError> for TcpErr {
    fn from(value: WriteError) -> Self {
        Self::EtherParseErr(value)
    }
}

impl From<ValueError> for TcpErr {
    fn from(value: ValueError) -> Self {
        Self::ValueError(value)
    }
}
