use crate::config::FilesystemConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCWSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const INVALID_FILE_ATTRS: u32 = 0xFFFFFFFF;

const VM_FILES: &[&str] = &[
    "vmmouse.sys",
    "vmhgfs.sys",
    "vmci.sys",
    "vmusbmouse.sys",
    "vmx_svga.sys",
    "vboxmouse.sys",
    "vboxguest.sys",
    "vboxsf.sys",
    "vboxvideo.sys",
    "prl_fs.sys",
    "prl_mouse.sys",
    "prl_vid.sys",
    "vmware",
    "virtualbox",
    "vbox",
    "qemu",
    "xen",
];

const ANALYSIS_TOOLS: &[&str] = &[
    "wireshark",
    "fiddler",
    "procmon",
    "procexp",
    "regmon",
    "filemon",
    "ida",
    "ollydbg",
    "x64dbg",
    "windbg",
    "immunity",
    "pestudio",
    "processhacker",
    "tcpview",
    "autoruns",
    "apimonitor",
];

type GetFileAttributesWFn = unsafe extern "system" fn(PCWSTR) -> u32;
type GetFileAttributesAFn = unsafe extern "system" fn(*const u8) -> u32;

static mut ORIG_GET_FILE_ATTR_W: Option<GetFileAttributesWFn> = None;
static mut ORIG_GET_FILE_ATTR_A: Option<GetFileAttributesAFn> = None;
static mut HIDE_VM: bool = false;
static mut HIDE_TOOLS: bool = false;

#[derive(Serialize)]
struct FilesystemEvent {
    event_type: &'static str,
    path: String,
    hidden: bool,
}

fn path_contains_vm_indicator(path: &str) -> bool {
    let lower = path.to_lowercase();
    VM_FILES.iter().any(|v| lower.contains(v))
}

fn path_contains_analysis_tool(path: &str) -> bool {
    let lower = path.to_lowercase();
    ANALYSIS_TOOLS.iter().any(|t| lower.contains(t))
}

unsafe fn wide_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.0.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr.0, len))
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

unsafe extern "system" fn det_get_file_attr_w(path: PCWSTR) -> u32 {
    let path_str = wide_to_string(path);
    let hide = (HIDE_VM && path_contains_vm_indicator(&path_str))
        || (HIDE_TOOLS && path_contains_analysis_tool(&path_str));

    if hide {
        send_event(&FilesystemEvent {
            event_type: "filesystem_hidden",
            path: path_str,
            hidden: true,
        });
        return INVALID_FILE_ATTRS;
    }

    ORIG_GET_FILE_ATTR_W.unwrap()(path)
}

unsafe extern "system" fn det_get_file_attr_a(path: *const u8) -> u32 {
    let path_str = ansi_to_string(path);
    let hide = (HIDE_VM && path_contains_vm_indicator(&path_str))
        || (HIDE_TOOLS && path_contains_analysis_tool(&path_str));

    if hide {
        send_event(&FilesystemEvent {
            event_type: "filesystem_hidden",
            path: path_str,
            hidden: true,
        });
        return INVALID_FILE_ATTRS;
    }

    ORIG_GET_FILE_ATTR_A.unwrap()(path)
}

pub unsafe fn install(config: &FilesystemConfig) -> anyhow::Result<()> {
    HIDE_VM = config.hide_vm_files;
    HIDE_TOOLS = config.hide_analysis_tools;

    let kernel32 = GetModuleHandleA(windows::core::PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(
        kernel32,
        windows::core::PCSTR::from_raw("GetFileAttributesW\0".as_ptr()),
    ) {
        let t = MinHook::create_hook(addr as _, det_get_file_attr_w as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_GET_FILE_ATTR_W = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(
        kernel32,
        windows::core::PCSTR::from_raw("GetFileAttributesA\0".as_ptr()),
    ) {
        let t = MinHook::create_hook(addr as _, det_get_file_attr_a as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_GET_FILE_ATTR_A = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
