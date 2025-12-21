use crate::config::UiConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;

use std::sync::RwLock;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const VM_WINDOW_CLASSES: &[&str] = &[
    "VBoxTrayToolWndClass",
    "VBoxTrayToolWnd",
    "VMwareTrayWindow",
    "VMwareUserWindow",
];

type GetSystemMetricsFn = unsafe extern "system" fn(i32) -> i32;
type FindWindowAFn = unsafe extern "system" fn(*const u8, *const u8) -> HWND;
type FindWindowWFn = unsafe extern "system" fn(*const u16, *const u16) -> HWND;

static ORIG_GET_SYSTEM_METRICS: RwLock<Option<GetSystemMetricsFn>> = RwLock::new(None);
static ORIG_FIND_WINDOW_A: RwLock<Option<FindWindowAFn>> = RwLock::new(None);
static ORIG_FIND_WINDOW_W: RwLock<Option<FindWindowWFn>> = RwLock::new(None);

static SPOOF_WIDTH: RwLock<Option<u32>> = RwLock::new(None);
static SPOOF_HEIGHT: RwLock<Option<u32>> = RwLock::new(None);
static SPOOF_MONITORS: RwLock<Option<u32>> = RwLock::new(None);
static HIDE_VM_WINDOWS: RwLock<bool> = RwLock::new(false);

const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SM_CMONITORS: i32 = 80;

#[derive(Serialize)]
struct UiEvent {
    event_type: &'static str,
    metric: &'static str,
    spoofed: bool,
}

unsafe extern "system" fn det_get_system_metrics(index: i32) -> i32 {
    let original = ORIG_GET_SYSTEM_METRICS.read().unwrap().unwrap()(index);

    match index {
        SM_CXSCREEN => {
            let width = *SPOOF_WIDTH.read().unwrap();
            if let Some(w) = width {
                send_event(&UiEvent {
                    event_type: "ui_spoofed",
                    metric: "SM_CXSCREEN",
                    spoofed: true,
                });
                return w as i32;
            }
        }

        SM_CYSCREEN => {
            let height = *SPOOF_HEIGHT.read().unwrap();
            if let Some(h) = height {
                send_event(&UiEvent {
                    event_type: "ui_spoofed",
                    metric: "SM_CYSCREEN",
                    spoofed: true,
                });
                return h as i32;
            }
        }

        SM_CMONITORS => {
            let monitors = *SPOOF_MONITORS.read().unwrap();
            if let Some(m) = monitors {
                send_event(&UiEvent {
                    event_type: "ui_spoofed",
                    metric: "SM_CMONITORS",
                    spoofed: true,
                });
                return m as i32;
            }
        }

        _ => {}
    }

    original
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

fn is_vm_window(class: &str, title: &str) -> bool {
    for vm_class in VM_WINDOW_CLASSES {
        if class.contains(vm_class) || title.contains(vm_class) {
            return true;
        }
    }
    false
}

unsafe extern "system" fn det_find_window_a(class: *const u8, title: *const u8) -> HWND {
    if *HIDE_VM_WINDOWS.read().unwrap() {
        let class_str = ansi_to_string(class);

        let title_str = ansi_to_string(title);
        if is_vm_window(&class_str, &title_str) {
            send_event(&UiEvent {
                event_type: "vm_window_hidden",
                metric: "FindWindowA",
                spoofed: true,
            });
            return HWND::default();
        }
    }
    ORIG_FIND_WINDOW_A.read().unwrap().unwrap()(class, title)
}

unsafe extern "system" fn det_find_window_w(class: *const u16, title: *const u16) -> HWND {
    if *HIDE_VM_WINDOWS.read().unwrap() {
        let class_str = wide_to_string(class);

        let title_str = wide_to_string(title);
        if is_vm_window(&class_str, &title_str) {
            send_event(&UiEvent {
                event_type: "vm_window_hidden",
                metric: "FindWindowW",
                spoofed: true,
            });
            return HWND::default();
        }
    }
    ORIG_FIND_WINDOW_W.read().unwrap().unwrap()(class, title)
}

pub unsafe fn install(config: &UiConfig) -> anyhow::Result<()> {
    *HIDE_VM_WINDOWS.write().unwrap() = config.hide_vm_windows;

    if let Some((w, h)) = config.spoof_screen_resolution {
        *SPOOF_WIDTH.write().unwrap() = Some(w);
        *SPOOF_HEIGHT.write().unwrap() = Some(h);
    }
    *SPOOF_MONITORS.write().unwrap() = config.spoof_monitor_count;

    let spoof_w = *SPOOF_WIDTH.read().unwrap();
    let spoof_m = *SPOOF_MONITORS.read().unwrap();
    let needs_hooks = spoof_w.is_some() || spoof_m.is_some() || *HIDE_VM_WINDOWS.read().unwrap();

    if !needs_hooks {
        return Ok(());
    }

    let user32 = GetModuleHandleA(PCSTR::from_raw("user32.dll\0".as_ptr()))?;

    if spoof_w.is_some() || spoof_m.is_some() {
        if let Some(addr) = GetProcAddress(user32, PCSTR::from_raw("GetSystemMetrics\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_get_system_metrics as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_GET_SYSTEM_METRICS.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    if *HIDE_VM_WINDOWS.read().unwrap() {
        if let Some(addr) = GetProcAddress(user32, PCSTR::from_raw("FindWindowA\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_find_window_a as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_FIND_WINDOW_A.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(user32, PCSTR::from_raw("FindWindowW\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_find_window_w as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            *ORIG_FIND_WINDOW_W.write().unwrap() = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Ok(())
}
