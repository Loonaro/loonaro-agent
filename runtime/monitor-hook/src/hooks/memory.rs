use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

// ============================================================================
// Hook Function Types
// ============================================================================

type NtAllocateVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> NTSTATUS;

type NtWriteVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, usize, *mut usize) -> NTSTATUS;

type NtProtectVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> NTSTATUS;

// ============================================================================
// Original Function Pointers
// ============================================================================

static mut ORIGINAL_NT_ALLOCATE: Option<NtAllocateVirtualMemoryFn> = None;
static mut ORIGINAL_NT_WRITE: Option<NtWriteVirtualMemoryFn> = None;
static mut ORIGINAL_NT_PROTECT: Option<NtProtectVirtualMemoryFn> = None;

// ============================================================================
// Event Structures
// ============================================================================

#[derive(Serialize)]
struct MemoryAllocEvent {
    event_type: &'static str,
    process_handle: isize,
    base_address: usize,
    region_size: usize,
    allocation_type: u32,
    protect: u32,
}

#[derive(Serialize)]
struct MemoryWriteEvent {
    event_type: &'static str,
    process_handle: isize,
    base_address: usize,
    bytes_written: usize,
}

#[derive(Serialize)]
struct MemoryProtectEvent {
    event_type: &'static str,
    process_handle: isize,
    base_address: usize,
    region_size: usize,
    new_protect: u32,
    old_protect: u32,
}

// ============================================================================
// Detour Functions
// ============================================================================

unsafe extern "system" fn detour_nt_allocate(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let original = ORIGINAL_NT_ALLOCATE.expect("Original not set");
    let status = original(
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    );

    if status.0 >= 0 {
        let event = MemoryAllocEvent {
            event_type: "NtAllocateVirtualMemory",
            process_handle: process_handle.0 as isize,
            base_address: if !base_address.is_null() {
                *base_address as usize
            } else {
                0
            },
            region_size: if !region_size.is_null() {
                *region_size
            } else {
                0
            },
            allocation_type,
            protect,
        };
        send_event(&event);
    }
    status
}

unsafe extern "system" fn detour_nt_write(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    let original = ORIGINAL_NT_WRITE.expect("Original not set");
    let status = original(process_handle, base_address, buffer, size, bytes_written);

    if status.0 >= 0 {
        let event = MemoryWriteEvent {
            event_type: "NtWriteVirtualMemory",
            process_handle: process_handle.0 as isize,
            base_address: base_address as usize,
            bytes_written: if !bytes_written.is_null() {
                *bytes_written
            } else {
                size
            },
        };
        send_event(&event);
    }
    status
}

unsafe extern "system" fn detour_nt_protect(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    let original = ORIGINAL_NT_PROTECT.expect("Original not set");
    let status = original(
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect,
    );

    if status.0 >= 0 {
        let event = MemoryProtectEvent {
            event_type: "NtProtectVirtualMemory",
            process_handle: process_handle.0 as isize,
            base_address: if !base_address.is_null() {
                *base_address as usize
            } else {
                0
            },
            region_size: if !region_size.is_null() {
                *region_size
            } else {
                0
            },
            new_protect,
            old_protect: if !old_protect.is_null() {
                *old_protect
            } else {
                0
            },
        };
        send_event(&event);
    }
    status
}

// ============================================================================
// Installation
// ============================================================================

pub unsafe fn install_all() -> anyhow::Result<()> {
    let ntdll = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr()))
        .map_err(|e| anyhow::anyhow!("GetModuleHandleA(ntdll): {}", e))?;

    // NtAllocateVirtualMemory
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtAllocateVirtualMemory\0".as_ptr()))
    {
        let trampoline = MinHook::create_hook(addr as _, detour_nt_allocate as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook NtAllocateVirtualMemory: {:?}", e))?;
        ORIGINAL_NT_ALLOCATE = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtAllocateVirtualMemory: {:?}", e))?;
    }

    // NtWriteVirtualMemory
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtWriteVirtualMemory\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_nt_write as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook NtWriteVirtualMemory: {:?}", e))?;
        ORIGINAL_NT_WRITE = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtWriteVirtualMemory: {:?}", e))?;
    }

    // NtProtectVirtualMemory
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtProtectVirtualMemory\0".as_ptr()))
    {
        let trampoline = MinHook::create_hook(addr as _, detour_nt_protect as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook NtProtectVirtualMemory: {:?}", e))?;
        ORIGINAL_NT_PROTECT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtProtectVirtualMemory: {:?}", e))?;
    }

    Ok(())
}
