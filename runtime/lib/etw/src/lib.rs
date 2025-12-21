mod error;
pub mod helpers;
pub mod payload;

use crate::payload::process::ProcessEventPayload;
use minicbor::{Decode, Encode};
use one_collect::etw::AncillaryData;

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum EtwEvent {
    #[n(0)]
    SystemProcess(#[n(0)] ProcessEvent),
    #[n(1)]
    Sysmon,
    #[n(2)]
    File(#[n(0)] FileEvent),
    #[n(3)]
    Registry(#[n(0)] RegistryEvent),
    #[n(4)]
    Network(#[n(0)] NetworkEvent),
    #[n(5)]
    Dns(#[n(0)] DnsEvent),
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum ProcessEvent {
    #[n(0)]
    ProcessCreate,
    #[n(1)]
    ProcessTerminate,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum FileEvent {
    #[n(0)]
    Create,
    #[n(1)]
    Write,
    #[n(2)]
    Delete,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum RegistryEvent {
    #[n(0)]
    SetValue,
    #[n(1)]
    DeleteValue,
    #[n(2)]
    CreateKey,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum NetworkEvent {
    #[n(0)]
    Connect,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
pub enum DnsEvent {
    #[n(0)]
    Query,
}

#[derive(Debug)]
pub enum EventPayload {
    Process(ProcessEventPayload),
    File(payload::file::FileCreatePayload),
    Registry(payload::registry::RegistryEventPayload),
    Network(payload::network::NetworkEventPayload),
    Dns(payload::dns::DnsEventPayload),
}

#[derive(Encode, Decode, Debug, PartialEq, Eq)]
pub struct EventHeader {
    #[n(0)]
    event_type: EtwEvent,
    #[n(1)]
    timestamp: u64,
    #[n(2)]
    pid: u32,
    #[n(3)]
    tid: u32,
}
impl EventHeader {
    pub fn from_ancillary(value: &AncillaryData, event_type: EtwEvent) -> Self {
        Self {
            event_type,
            timestamp: value.time(),
            pid: value.pid(),
            tid: value.tid(),
        }
    }

    pub fn event_type(&self) -> &EtwEvent {
        &self.event_type
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

#[derive(Debug)]
pub struct Event {
    header: EventHeader,
    payload: EventPayload,
}

impl Event {
    pub fn new(event_header: EventHeader, payload: EventPayload) -> Self {
        Self {
            header: event_header,
            payload,
        }
    }

    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    pub fn header(&self) -> &EventHeader {
        &self.header
    }
}
