use crate::payload::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum LoonaroETWError {
    #[error("Failed to parse process event payload: {0}")]
    ProcessPayloadParse(#[from] ParseError),
}
