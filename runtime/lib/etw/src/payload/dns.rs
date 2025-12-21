//! Microsoft-Windows-DNS-Client ETW event payload parser.
//!
//! provider guid: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}

use crate::helpers::take_utf16le_z;
use crate::payload::{ParseError, WithField};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEventPayload {
    pub query_name: String,
    pub query_type: u16,
    pub query_options: u64,
}

impl DnsEventPayload {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Attempt to parse QueryName (Unicode Z-String) from start
        // This assumes the layout starts with the string.
        let (query_name, rem) = take_utf16le_z(data).with_field("QueryName")?;

        // Attempt to read QueryType (u32 or u16)
        // Microsoft-Windows-DNS-Client 3019: QueryName, QueryType (u32), QueryOptions (u64), Status (u32)
        let query_type = if rem.len() >= 4 {
            u32::from_le_bytes(rem[0..4].try_into().unwrap()) as u16
        } else if rem.len() >= 2 {
            u16::from_le_bytes(rem[0..2].try_into().unwrap())
        } else {
            0
        };

        // QueryOptions
        let query_options = if rem.len() >= 12 {
            // 4 bytes type + 8 bytes options
            u64::from_le_bytes(rem[4..12].try_into().unwrap())
        } else {
            0
        };

        Ok(Self {
            query_name,
            query_type,
            query_options,
        })
    }
}
