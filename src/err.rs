use std::io::Error;

use etherparse::WriteError;
#[derive(Debug)]
pub enum TcpErr {
    Io(Error),
    EtherParseErr(WriteError),
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
