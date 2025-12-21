use crate::config::OsObjectsConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const VM_MUTEXES: &[&str] = &[
    "VBoxTrayIPC",
    "VBoxMiniRdrDN",
    "VMwareUser",
    "VMwareDnD",
    "VBOX",
    "VMWARE",
    "Sandboxie_SingleInstanceMutex_Control",
];

const VM_DEVICES: &[&str] = &[
    "\\\\.\\VBoxMiniRdrDN",
    "\\\\.\\VBoxGuest",
    "\\\\.\\VBoxDevice",
    "\\\\.\\VMCIDevice",
    "\\\\.\\VMCI",
    "\\\\.\\pipe\\VBoxMiniRdDN",
    "\\\\.\\pipe\\VBoxTrayIPC",
];

type CreateMutexAFn = unsafe extern "system" fn(*const c_void, i32, *const u8) -> HANDLE;
type CreateMutexWFn = unsafe extern "system" fn(*const c_void, i32, *const u16) -> HANDLE;
type OpenMutexAFn = unsafe extern "system" fn(u32, i32, *const u8) -> HANDLE;
type CreateFileAFn =
    unsafe extern "system" fn(*const u8, u32, u32, *const c_void, u32, u32, HANDLE) -> HANDLE;
type CreateFileWFn =
    unsafe extern "system" fn(*const u16, u32, u32, *const c_void, u32, u32, HANDLE) -> HANDLE;

static mut ORIG_CREATE_MUTEX_A: Option<CreateMutexAFn> = None;
static mut ORIG_CREATE_MUTEX_W: Option<CreateMutexWFn> = None;
static mut ORIG_OPEN_MUTEX_A: Option<OpenMutexAFn> = None;
static mut ORIG_CREATE_FILE_A: Option<CreateFileAFn> = None;
static mut ORIG_CREATE_FILE_W: Option<CreateFileWFn> = None;
static mut HIDE_VM_DEVICES: bool = false;
static mut HIDE_MUTEXES: bool = false;

const ERROR_FILE_NOT_FOUND: isize = -1;

#[derive(Serialize)]
struct OsObjectEvent {
    event_type: &'static str,
    object_type: &'static str,
    name: String,
}

unsafe fn ansi_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string()
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

fn is_vm_mutex(name: &str) -> bool {
    let upper = name.to_uppercase();
    VM_MUTEXES.iter().any(|m| upper.contains(&m.to_uppercase()))
}

fn is_vm_device(name: &str) -> bool {
    let upper = name.to_uppercase();
    VM_DEVICES.iter().any(|d| upper.contains(&d.to_uppercase()))
}

unsafe extern "system" fn det_create_mutex_a(
    attrs: *const c_void,
    initial: i32,
    name: *const u8,
) -> HANDLE {
    if HIDE_MUTEXES {
        let name_str = ansi_to_string(name);
        if is_vm_mutex(&name_str) {
            send_event(&OsObjectEvent {
                event_type: "mutex_hidden",
                object_type: "CreateMutexA",
                name: name_str,
            });
            return HANDLE(ERROR_FILE_NOT_FOUND);
        }
    }
    ORIG_CREATE_MUTEX_A.unwrap()(attrs, initial, name)
}

unsafe extern "system" fn det_create_mutex_w(
    attrs: *const c_void,
    initial: i32,
    name: *const u16,
) -> HANDLE {
    if HIDE_MUTEXES {
        let name_str = wide_to_string(name);
        if is_vm_mutex(&name_str) {
            send_event(&OsObjectEvent {
                event_type: "mutex_hidden",
                object_type: "CreateMutexW",
                name: name_str,
            });
            return HANDLE(ERROR_FILE_NOT_FOUND);
        }
    }
    ORIG_CREATE_MUTEX_W.unwrap()(attrs, initial, name)
}

unsafe extern "system" fn det_open_mutex_a(access: u32, inherit: i32, name: *const u8) -> HANDLE {
    if HIDE_MUTEXES {
        let name_str = ansi_to_string(name);
        if is_vm_mutex(&name_str) {
            send_event(&OsObjectEvent {
                event_type: "mutex_hidden",
                object_type: "OpenMutexA",
                name: name_str,
            });
            return HANDLE(0);
        }
    }
    ORIG_OPEN_MUTEX_A.unwrap()(access, inherit, name)
}

unsafe extern "system" fn det_create_file_a(
    name: *const u8,
    access: u32,
    share: u32,
    security: *const c_void,
    disp: u32,
    flags: u32,
    template: HANDLE,
) -> HANDLE {
    if HIDE_VM_DEVICES {
        let name_str = ansi_to_string(name);
        if is_vm_device(&name_str) {
            send_event(&OsObjectEvent {
                event_type: "device_hidden",
                object_type: "CreateFileA",
                name: name_str,
            });
            return HANDLE(ERROR_FILE_NOT_FOUND);
        }
    }
    ORIG_CREATE_FILE_A.unwrap()(name, access, share, security, disp, flags, template)
}

unsafe extern "system" fn det_create_file_w(
    name: *const u16,
    access: u32,
    share: u32,
    security: *const c_void,
    disp: u32,
    flags: u32,
    template: HANDLE,
) -> HANDLE {
    if HIDE_VM_DEVICES {
        let name_str = wide_to_string(name);
        if is_vm_device(&name_str) {
            send_event(&OsObjectEvent {
                event_type: "device_hidden",
                object_type: "CreateFileW",
                name: name_str,
            });
            return HANDLE(ERROR_FILE_NOT_FOUND);
        }
    }
    ORIG_CREATE_FILE_W.unwrap()(name, access, share, security, disp, flags, template)
}

pub unsafe fn install(config: &OsObjectsConfig) -> anyhow::Result<()> {
    HIDE_VM_DEVICES = config.hide_vm_devices;
    HIDE_MUTEXES = config.hide_analysis_mutexes;

    if !HIDE_VM_DEVICES && !HIDE_MUTEXES {
        return Ok(());
    }

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if HIDE_MUTEXES {
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("CreateMutexA\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_create_mutex_a as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_CREATE_MUTEX_A = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("CreateMutexW\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_create_mutex_w as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_CREATE_MUTEX_W = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("OpenMutexA\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_open_mutex_a as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_OPEN_MUTEX_A = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    if HIDE_VM_DEVICES {
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("CreateFileA\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_create_file_a as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_CREATE_FILE_A = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("CreateFileW\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_create_file_w as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_CREATE_FILE_W = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Ok(())
}
