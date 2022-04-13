use std::fmt;
use std::io;
use std::error::Error as traitError;

#[derive(Debug)]
pub enum Error {
  IoError(io::Error),
  Underflow,
  ParsingError,
  InvalidFormat(&'static str),
  ConversionError(&'static str),
  ProtocolUnknown
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            Error::Underflow => "Underflow error",
            Error::ParsingError => "Parsing error",
            Error::ProtocolUnknown => "ProtocolUnknown",
            Error::InvalidFormat(val) => val,
            Error::ConversionError(val) => val,
            Error::IoError(ref val) => val.description()
        };
        write!(f, "{}", description)
    }
}


impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}
