use crate::config::ProcessesConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use std::sync::Mutex;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const DEFAULT_HIDDEN_PROCESSES: &[&str] = &[
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "wireshark.exe",
    "fiddler.exe",
    "procmon.exe",
    "procexp.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "ida.exe",
    "ida64.exe",
    "windbg.exe",
    "processhacker.exe",
];

static HIDDEN_PROCS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

type Process32FirstWFn = unsafe extern "system" fn(isize, *mut u8) -> i32;
type Process32NextWFn = unsafe extern "system" fn(isize, *mut u8) -> i32;

static mut ORIG_PROCESS32_FIRST: Option<Process32FirstWFn> = None;
static mut ORIG_PROCESS32_NEXT: Option<Process32NextWFn> = None;

#[derive(Serialize)]
struct ProcessHiddenEvent {
    event_type: &'static str,
    process_name: String,
}

fn should_hide_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    let hidden = HIDDEN_PROCS.lock().unwrap();
    hidden.iter().any(|p| lower.contains(&p.to_lowercase()))
}

unsafe fn get_exe_name_from_pe(pe: *mut u8) -> String {
    let offset = 44;
    let ptr = pe.add(offset) as *const u16;
    let mut len = 0;
    while *ptr.add(len) != 0 && len < 260 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

unsafe extern "system" fn det_process32_first(snapshot: isize, pe: *mut u8) -> i32 {
    loop {
        let result = ORIG_PROCESS32_FIRST.unwrap()(snapshot, pe);
        if result == 0 {
            return 0;
        }
        let name = get_exe_name_from_pe(pe);
        if !should_hide_process(&name) {
            return result;
        }
        send_event(&ProcessHiddenEvent {
            event_type: "process_hidden",
            process_name: name,
        });
        return det_process32_next(snapshot, pe);
    }
}

unsafe extern "system" fn det_process32_next(snapshot: isize, pe: *mut u8) -> i32 {
    loop {
        let result = ORIG_PROCESS32_NEXT.unwrap()(snapshot, pe);
        if result == 0 {
            return 0;
        }
        let name = get_exe_name_from_pe(pe);
        if !should_hide_process(&name) {
            return result;
        }
        send_event(&ProcessHiddenEvent {
            event_type: "process_hidden",
            process_name: name,
        });
    }
}

pub unsafe fn install(config: &ProcessesConfig) -> anyhow::Result<()> {
    let mut hidden = HIDDEN_PROCS.lock().unwrap();
    if config.hide_analysis_processes {
        hidden.extend(DEFAULT_HIDDEN_PROCESSES.iter().map(|s| s.to_string()));
    }
    hidden.extend(config.hidden_process_names.iter().cloned());
    drop(hidden);

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("Process32FirstW\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_process32_first as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_PROCESS32_FIRST = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("Process32NextW\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_process32_next as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_PROCESS32_NEXT = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
