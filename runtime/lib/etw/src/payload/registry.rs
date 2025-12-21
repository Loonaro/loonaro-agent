//! Registry ETW event payload parser.
//!
//! see: https://learn.microsoft.com/en-us/windows/win32/etw/registry

use crate::helpers;
use crate::payload::ParseError;

#[derive(Debug, Default)]
pub struct RegistryEventPayload {
    pub key_name: String,
}

impl RegistryEventPayload {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Heuristic: Registry events also have headers.
        // Assuming ~24 bytes.
        let offset = if data.len() > 24 { 24 } else { 0 };
        let tail = &data[offset..];

        let (key_name, _) = helpers::take_utf16le_z(tail).or_else(|_| {
            Ok::<(String, &[u8]), ParseError>((String::from("<parsing_error>"), tail))
        })?;
        Ok(Self { key_name })
    }
}
