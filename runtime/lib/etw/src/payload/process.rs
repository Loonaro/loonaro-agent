//! Process ETW event payload parser.
//!
//! see: https://learn.microsoft.com/en-us/windows/win32/etw/process

use crate::helpers;
use crate::helpers::{read_u32, read_u64};
use crate::payload::{ParseError, WithField};

// Process payload parsing using constant offsets and a simple dynamic tail walk.
// Static layout (bytes, little-endian):
//   0..=7   UniqueProcessKey: u64
//   8..=11  ProcessId: u32
//   12..=15 ParentId: u32
//   16..=19 SessionId: u32
//   20..=23 ExitStatus: i32
//   24..=31 DirectoryTableBase: u64
//   32..=35 Flags: u32 (unused)
//   36..    Dynamic tail: SID | ImageFileName (C string) | CommandLine (UTF-16LE string)
const OFF_UNIQUE_KEY: usize = 0;
const OFF_PID: usize = 8;
const OFF_PPID: usize = 12;
const OFF_SESSION: usize = 16;
const OFF_EXIT: usize = 20;
const OFF_DTB: usize = 24;
// const OFF_FLAGS: usize = 32; // currently unused
const OFF_DYNAMIC: usize = 36;

#[derive(Debug, Default)]
pub struct ProcessEventPayload {
    process_id: u32,
    parent_process_id: u32,
    session_id: u32,
    exit_status: i32,
    directory_table_base: u64,
    image_file_name: String, // decoded UTF-8
    command_line: String,    // decoded UTF-16LE
}

impl ProcessEventPayload {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < OFF_DYNAMIC {
            return Err(ParseError::Bounds("static header"));
        }

        let _unique_process_key = read_u64(data, OFF_UNIQUE_KEY).with_field("UniqueProcessKey")?;
        let process_id = read_u32(data, OFF_PID).with_field("ProcessId")?;
        let parent_process_id = read_u32(data, OFF_PPID).with_field("ParentId")?;
        let session_id = read_u32(data, OFF_SESSION).with_field("SessionId")?;
        let exit_status = read_u32(data, OFF_EXIT).with_field("ExitStatus")? as i32;
        let directory_table_base = read_u64(data, OFF_DTB).with_field("DirectoryTableBase")?;

        let mut tail = data
            .get(OFF_DYNAMIC..)
            .ok_or(ParseError::Bounds("dynamic tail"))?;

        // skip sid
        let (_sid_view, rest) = helpers::take_sid(tail)?;
        tail = rest;

        // ImageFileName is a cstring.
        let (image_file_name, rest) = helpers::take_utf8_string(tail)?;
        tail = rest;

        let (command_line, _rest) = helpers::take_utf16le_z(tail)?;

        Ok(Self {
            process_id,
            parent_process_id,
            session_id,
            exit_status,
            directory_table_base,
            image_file_name,
            command_line,
        })
    }

    pub fn pid(&self) -> u32 {
        self.process_id
    }
    pub fn ppid(&self) -> u32 {
        self.parent_process_id
    }
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    pub fn exit_status(&self) -> i32 {
        self.exit_status
    }
    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }
    pub fn image(&self) -> &str {
        &self.image_file_name
    }
    pub fn cmd(&self) -> &str {
        &self.command_line
    }
}
