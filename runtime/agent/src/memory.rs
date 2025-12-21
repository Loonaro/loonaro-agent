use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

pub struct ProcessReader {
    handle: HANDLE,
}

impl ProcessReader {
    pub fn attach(pid: u32) -> Result<Self> {
        let handle =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)? };

        Ok(Self { handle })
    }

    pub fn read_memory(&self, base_address: u64, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        unsafe {
            ReadProcessMemory(
                self.handle,
                base_address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut bytes_read),
            )
            .ok()
            .context("ReadProcessMemory failed")?;
        }

        if bytes_read != size {
            // It's possible we read less than requested if we cross page boundaries into unmapped memory
            buffer.truncate(bytes_read);
        }

        Ok(buffer)
    }
}

impl Drop for ProcessReader {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
