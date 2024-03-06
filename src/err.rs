use std::{io::Error, sync::mpsc::RecvError};

use etherparse::{ValueError, WriteError};

#[derive(Debug)]
pub enum TcpErr {
    Io(Error),
    EtherParseErr(WriteError),
    ValueError(ValueError),
    RecvError(RecvError),
    NixError(nix::Error),
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

impl From<RecvError> for TcpErr {
    fn from(value: RecvError) -> Self {
        Self::RecvError(value)
    }
}

impl From<nix::Error> for TcpErr {
    fn from(value: nix::Error) -> Self {
        Self::NixError(value)
    }
}
