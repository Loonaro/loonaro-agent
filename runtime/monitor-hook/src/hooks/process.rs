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

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut c_void,
    HANDLE,
    *mut c_void,
    *mut c_void,
    u32,
    usize,
    usize,
    usize,
    *mut c_void,
) -> NTSTATUS;

type NtResumeThreadFn = unsafe extern "system" fn(HANDLE, *mut u32) -> NTSTATUS;

type NtSetContextThreadFn = unsafe extern "system" fn(HANDLE, *const c_void) -> NTSTATUS;

// ============================================================================
// Original Function Pointers
// ============================================================================

static mut ORIGINAL_NT_CREATE_THREAD_EX: Option<NtCreateThreadExFn> = None;
static mut ORIGINAL_NT_RESUME_THREAD: Option<NtResumeThreadFn> = None;
static mut ORIGINAL_NT_SET_CONTEXT_THREAD: Option<NtSetContextThreadFn> = None;

// ============================================================================
// Event Structures
// ============================================================================

#[derive(Serialize)]
struct ThreadCreateEvent {
    event_type: &'static str,
    target_process: isize,
    start_address: usize,
    create_flags: u32,
}

#[derive(Serialize)]
struct ThreadResumeEvent {
    event_type: &'static str,
    thread_handle: isize,
    previous_suspend_count: u32,
}

#[derive(Serialize)]
struct ThreadSetContextEvent {
    event_type: &'static str,
    thread_handle: isize,
}

// ============================================================================
// Detour Functions
// ============================================================================

unsafe extern "system" fn detour_nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: HANDLE,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    max_stack_size: usize,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let original = ORIGINAL_NT_CREATE_THREAD_EX.expect("Original not set");
    let status = original(
        thread_handle,
        desired_access,
        object_attributes,
        process_handle,
        start_routine,
        argument,
        create_flags,
        zero_bits,
        stack_size,
        max_stack_size,
        attribute_list,
    );

    if status.0 >= 0 {
        let event = ThreadCreateEvent {
            event_type: "NtCreateThreadEx",
            target_process: process_handle.0 as isize,
            start_address: start_routine as usize,
            create_flags,
        };
        send_event(&event);
    }
    status
}

unsafe extern "system" fn detour_nt_resume_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    let original = ORIGINAL_NT_RESUME_THREAD.expect("Original not set");
    let status = original(thread_handle, previous_suspend_count);

    if status.0 >= 0 {
        let event = ThreadResumeEvent {
            event_type: "NtResumeThread",
            thread_handle: thread_handle.0 as isize,
            previous_suspend_count: if !previous_suspend_count.is_null() {
                *previous_suspend_count
            } else {
                0
            },
        };
        send_event(&event);
    }
    status
}

unsafe extern "system" fn detour_nt_set_context_thread(
    thread_handle: HANDLE,
    context: *const c_void,
) -> NTSTATUS {
    let original = ORIGINAL_NT_SET_CONTEXT_THREAD.expect("Original not set");
    let status = original(thread_handle, context);

    if status.0 >= 0 {
        let event = ThreadSetContextEvent {
            event_type: "NtSetContextThread",
            thread_handle: thread_handle.0 as isize,
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

    // NtCreateThreadEx - Remote thread creation (common injection technique)
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtCreateThreadEx\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_nt_create_thread_ex as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook NtCreateThreadEx: {:?}", e))?;
        ORIGINAL_NT_CREATE_THREAD_EX = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtCreateThreadEx: {:?}", e))?;
    }

    // NtResumeThread - Process hollowing detection
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtResumeThread\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_nt_resume_thread as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook NtResumeThread: {:?}", e))?;
        ORIGINAL_NT_RESUME_THREAD = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtResumeThread: {:?}", e))?;
    }

    // NtSetContextThread - Thread hijacking detection
    if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtSetContextThread\0".as_ptr())) {
        let trampoline =
            MinHook::create_hook(addr as _, detour_nt_set_context_thread as *mut c_void)
                .map_err(|e| anyhow::anyhow!("create_hook NtSetContextThread: {:?}", e))?;
        ORIGINAL_NT_SET_CONTEXT_THREAD = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook NtSetContextThread: {:?}", e))?;
    }

    Ok(())
}
