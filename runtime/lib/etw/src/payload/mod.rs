use thiserror::Error;

pub mod dns;
pub mod file;
pub mod network;
pub mod process;
pub mod registry;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Out of bounds access: {0}")]
    Bounds(&'static str),
    #[error("Invalid field value: {0}")]
    InvalidValue(&'static str),
    #[error("Encoding error: {0}")]
    Encoding(#[from] std::string::FromUtf8Error),
    #[error("Utf16 error")]
    Utf16,
    #[error("Invalid SID")]
    Sid,
    #[error("UTF-8 Error: {0}")]
    Utf8(&'static str),
}

trait WithField<T> {
    fn with_field(self, name: &'static str) -> Result<T, ParseError>;
}

impl<T> WithField<T> for Option<T> {
    fn with_field(self, name: &'static str) -> Result<T, ParseError> {
        self.ok_or(ParseError::Bounds(name))
    }
}

impl<T> WithField<T> for Result<T, ParseError> {
    fn with_field(self, name: &'static str) -> Result<T, ParseError> {
        self.map_err(|e| match e {
            ParseError::Bounds(_) => ParseError::Bounds(name),
            _ => e,
        })
    }
}
