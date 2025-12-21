//! FileIO ETW event payload parser.
//!
//! see: https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create

use crate::helpers::{read_u32, read_u64, take_utf16le_z};
use crate::payload::{ParseError, WithField};

// FileIo_Create layout (64-bit):
//   WmiDataId(1): IrpPtr - Pointer (8 bytes on x64)
//   WmiDataId(2): TTID - Pointer (8 bytes on x64)
//   WmiDataId(3): FileObject - Pointer (8 bytes on x64)
//   WmiDataId(4): CreateOptions - u32
//   WmiDataId(5): FileAttributes - u32
//   WmiDataId(6): ShareAccess - u32
//   WmiDataId(7): OpenPath - null-terminated utf16 string
const OFF_IRP_PTR: usize = 0;
const OFF_TTID: usize = 8;
const OFF_FILE_OBJECT: usize = 16;
const OFF_CREATE_OPTIONS: usize = 24;
const OFF_FILE_ATTRIBUTES: usize = 28;
const OFF_SHARE_ACCESS: usize = 32;
const OFF_OPEN_PATH: usize = 36;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileCreatePayload {
    pub irp_ptr: u64,
    pub thread_id: u64,
    pub file_object: u64,
    pub create_options: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub open_path: String,
}

impl FileCreatePayload {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < OFF_OPEN_PATH {
            return Err(ParseError::Bounds("file payload header"));
        }

        let irp_ptr = read_u64(data, OFF_IRP_PTR).with_field("IrpPtr")?;
        let thread_id = read_u64(data, OFF_TTID).with_field("TTID")?;
        let file_object = read_u64(data, OFF_FILE_OBJECT).with_field("FileObject")?;
        let create_options = read_u32(data, OFF_CREATE_OPTIONS).with_field("CreateOptions")?;
        let file_attributes = read_u32(data, OFF_FILE_ATTRIBUTES).with_field("FileAttributes")?;
        let share_access = read_u32(data, OFF_SHARE_ACCESS).with_field("ShareAccess")?;

        let path_data = data
            .get(OFF_OPEN_PATH..)
            .ok_or(ParseError::Bounds("OpenPath"))?;
        let (open_path, _) = take_utf16le_z(path_data).with_field("OpenPath")?;

        Ok(Self {
            irp_ptr,
            thread_id,
            file_object,
            create_options,
            file_attributes,
            share_access,
            open_path,
        })
    }

    pub fn path(&self) -> &str {
        &self.open_path
    }

    pub fn thread_id(&self) -> u64 {
        self.thread_id
    }

    pub fn file_object(&self) -> u64 {
        self.file_object
    }
}
