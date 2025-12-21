use crate::config::RegistryConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const VM_REGISTRY_KEYS: &[&str] = &[
    "VBOX",
    "VMWARE",
    "VIRTUAL",
    "QEMU",
    "XEN",
    "PARALLELS",
    "SOFTWARE\\Oracle\\VirtualBox",
    "SYSTEM\\ControlSet001\\Services\\VBox",
    "HARDWARE\\ACPI\\DSDT\\VBOX",
    "HARDWARE\\ACPI\\FADT\\VBOX",
    "SOFTWARE\\VMware",
    "SYSTEM\\ControlSet001\\Services\\vmci",
];

type RegOpenKeyExAFn = unsafe extern "system" fn(usize, *const u8, u32, u32, *mut HANDLE) -> i32;
type RegOpenKeyExWFn = unsafe extern "system" fn(usize, *const u16, u32, u32, *mut HANDLE) -> i32;

static mut ORIG_REG_OPEN_A: Option<RegOpenKeyExAFn> = None;
static mut ORIG_REG_OPEN_W: Option<RegOpenKeyExWFn> = None;
static mut HIDE_VM_KEYS: bool = false;

#[derive(Serialize)]
struct RegistryEvent {
    event_type: &'static str,
    key: String,
    hidden: bool,
}

fn key_is_vm_related(key: &str) -> bool {
    let upper = key.to_uppercase();
    VM_REGISTRY_KEYS
        .iter()
        .any(|k| upper.contains(&k.to_uppercase()))
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

unsafe extern "system" fn det_reg_open_a(
    hkey: usize,
    subkey: *const u8,
    options: u32,
    sam: u32,
    result: *mut HANDLE,
) -> i32 {
    let key_str = ansi_to_string(subkey);
    if HIDE_VM_KEYS && key_is_vm_related(&key_str) {
        send_event(&RegistryEvent {
            event_type: "registry_hidden",
            key: key_str,
            hidden: true,
        });
        return 2;
    }
    ORIG_REG_OPEN_A.unwrap()(hkey, subkey, options, sam, result)
}

unsafe extern "system" fn det_reg_open_w(
    hkey: usize,
    subkey: *const u16,
    options: u32,
    sam: u32,
    result: *mut HANDLE,
) -> i32 {
    let key_str = wide_to_string(subkey);
    if HIDE_VM_KEYS && key_is_vm_related(&key_str) {
        send_event(&RegistryEvent {
            event_type: "registry_hidden",
            key: key_str,
            hidden: true,
        });
        return 2;
    }
    ORIG_REG_OPEN_W.unwrap()(hkey, subkey, options, sam, result)
}

pub unsafe fn install(config: &RegistryConfig) -> anyhow::Result<()> {
    HIDE_VM_KEYS = config.hide_vm_keys;

    let advapi32 = GetModuleHandleA(PCSTR::from_raw("advapi32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(advapi32, PCSTR::from_raw("RegOpenKeyExA\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_reg_open_a as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_REG_OPEN_A = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(advapi32, PCSTR::from_raw("RegOpenKeyExW\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_reg_open_w as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_REG_OPEN_W = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
