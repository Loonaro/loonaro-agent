use crate::config::OsQueriesConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use std::sync::RwLock;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type GetUserNameAFn = unsafe extern "system" fn(*mut u8, *mut u32) -> i32;
type GetComputerNameAFn = unsafe extern "system" fn(*mut u8, *mut u32) -> i32;
type IsDebuggerPresentFn = unsafe extern "system" fn() -> i32;
type CheckRemoteDebuggerPresentFn = unsafe extern "system" fn(isize, *mut i32) -> i32;

static ORIG_GET_USER_NAME: RwLock<Option<GetUserNameAFn>> = RwLock::new(None);
static ORIG_GET_COMPUTER_NAME: RwLock<Option<GetComputerNameAFn>> = RwLock::new(None);
static ORIG_IS_DEBUGGER: RwLock<Option<IsDebuggerPresentFn>> = RwLock::new(None);
static ORIG_CHECK_REMOTE_DEBUGGER: RwLock<Option<CheckRemoteDebuggerPresentFn>> = RwLock::new(None);
static SPOOF_USER: RwLock<Option<String>> = RwLock::new(None);
static SPOOF_COMPUTER: RwLock<Option<String>> = RwLock::new(None);
static HIDE_DEBUGGER: RwLock<bool> = RwLock::new(false);

#[derive(Serialize)]
struct OsQueryEvent {
    event_type: &'static str,
    query: &'static str,
    spoofed: bool,
}

unsafe extern "system" fn det_get_user_name(buf: *mut u8, size: *mut u32) -> i32 {
    let spoof_guard = SPOOF_USER.read().unwrap();
    if let Some(ref spoof) = *spoof_guard {
        let bytes = spoof.as_bytes();
        let len = bytes.len().min((*size as usize).saturating_sub(1));
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len);
        *buf.add(len) = 0;
        *size = (len + 1) as u32;
        send_event(&OsQueryEvent {
            event_type: "os_query_spoofed",
            query: "GetUserNameA",
            spoofed: true,
        });
        return 1;
    }
    drop(spoof_guard);
    ORIG_GET_USER_NAME.read().unwrap().unwrap()(buf, size)
}

unsafe extern "system" fn det_get_computer_name(buf: *mut u8, size: *mut u32) -> i32 {
    let spoof_guard = SPOOF_COMPUTER.read().unwrap();
    if let Some(ref spoof) = *spoof_guard {
        let bytes = spoof.as_bytes();
        let len = bytes.len().min((*size as usize).saturating_sub(1));
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len);
        *buf.add(len) = 0;
        *size = len as u32;
        send_event(&OsQueryEvent {
            event_type: "os_query_spoofed",
            query: "GetComputerNameA",
            spoofed: true,
        });
        return 1;
    }
    drop(spoof_guard);
    ORIG_GET_COMPUTER_NAME.read().unwrap().unwrap()(buf, size)
}

unsafe extern "system" fn det_is_debugger() -> i32 {
    if *HIDE_DEBUGGER.read().unwrap() {
        send_event(&OsQueryEvent {
            event_type: "debugger_hidden",
            query: "IsDebuggerPresent",
            spoofed: true,
        });
        return 0;
    }
    ORIG_IS_DEBUGGER.read().unwrap().unwrap()()
}

unsafe extern "system" fn det_check_remote_debugger(handle: isize, result: *mut i32) -> i32 {
    let ret = ORIG_CHECK_REMOTE_DEBUGGER.read().unwrap().unwrap()(handle, result);
    if *HIDE_DEBUGGER.read().unwrap() && !result.is_null() {
        *result = 0;
        send_event(&OsQueryEvent {
            event_type: "debugger_hidden",
            query: "CheckRemoteDebuggerPresent",
            spoofed: true,
        });
    }
    ret
}

pub unsafe fn install(config: &OsQueriesConfig) -> anyhow::Result<()> {
    *SPOOF_USER.write().unwrap() = config.spoof_username.clone();
    *SPOOF_COMPUTER.write().unwrap() = config.spoof_computername.clone();
    *HIDE_DEBUGGER.write().unwrap() = config.hide_debugger;

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;
    let advapi32 = GetModuleHandleA(PCSTR::from_raw("advapi32.dll\0".as_ptr()))?;

    if SPOOF_USER.read().unwrap().is_some() {
        if let Some(addr) = GetProcAddress(advapi32, PCSTR::from_raw("GetUserNameA\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_get_user_name as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_GET_USER_NAME.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    if SPOOF_COMPUTER.read().unwrap().is_some() {
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GetComputerNameA\0".as_ptr()))
        {
            let t = MinHook::create_hook(addr as _, det_get_computer_name as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_GET_COMPUTER_NAME.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    if *HIDE_DEBUGGER.read().unwrap() {
        if let Some(addr) =
            GetProcAddress(kernel32, PCSTR::from_raw("IsDebuggerPresent\0".as_ptr()))
        {
            let t = MinHook::create_hook(addr as _, det_is_debugger as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_IS_DEBUGGER.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(
            kernel32,
            PCSTR::from_raw("CheckRemoteDebuggerPresent\0".as_ptr()),
        ) {
            let t = MinHook::create_hook(addr as _, det_check_remote_debugger as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_CHECK_REMOTE_DEBUGGER.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Ok(())
}
