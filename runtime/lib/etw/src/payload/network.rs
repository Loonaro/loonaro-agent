//! TcpIp ETW event payload parser.
//!
//! see: https://learn.microsoft.com/en-us/windows/win32/etw/tcpip

use crate::payload::ParseError;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEventPayload {
    pub dest_ip: String,
    pub dest_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub size: u32,
}

impl NetworkEventPayload {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Assume IPv4 Connect (Event 12) layout:
        // Offset 0: PID (u32)
        // Offset 4: Size (u32)
        // Offset 8: daddr (u32) - IPv4
        // Offset 12: saddr (u32) - IPv4
        // Offset 16: dport (u16)
        // Offset 18: sport (u16)

        if data.len() < 20 {
            return Err(ParseError::Bounds(
                "Network payload too short for IPv4 Connect",
            ));
        }

        // Size
        let size = u32::from_le_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| ParseError::Bounds("size"))?,
        );

        // Dest IP
        let d0 = data[8];
        let d1 = data[9];
        let d2 = data[10];
        let d3 = data[11];
        let dest_ip = Ipv4Addr::new(d0, d1, d2, d3).to_string();

        // Src IP
        let s0 = data[12];
        let s1 = data[13];
        let s2 = data[14];
        let s3 = data[15];
        let src_ip = Ipv4Addr::new(s0, s1, s2, s3).to_string();

        // Ports (Network Byte Order = Big Endian)
        let dport = u16::from_be_bytes(
            data[16..18]
                .try_into()
                .map_err(|_| ParseError::Bounds("dport"))?,
        );
        let sport = u16::from_be_bytes(
            data[18..20]
                .try_into()
                .map_err(|_| ParseError::Bounds("sport"))?,
        );

        Ok(Self {
            dest_ip,
            dest_port: dport,
            src_ip,
            src_port: sport,
            size,
        })
    }
}
