use crate::config::CpuConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type GetSystemInfoFn = unsafe extern "system" fn(*mut SystemInfo);
type GetNativeSystemInfoFn = unsafe extern "system" fn(*mut SystemInfo);

#[repr(C)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: *mut c_void,
    maximum_application_address: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

static mut ORIG_GET_SYSTEM_INFO: Option<GetSystemInfoFn> = None;
static mut ORIG_GET_NATIVE_SYSTEM_INFO: Option<GetNativeSystemInfoFn> = None;
static mut SPOOF_CORE_COUNT: Option<u32> = None;

#[derive(Serialize)]
struct CpuEvent {
    event_type: &'static str,
    function: &'static str,
    original_cores: u32,
    spoofed_cores: u32,
}

unsafe extern "system" fn det_get_system_info(info: *mut SystemInfo) {
    ORIG_GET_SYSTEM_INFO.unwrap()(info);
    if let Some(cores) = SPOOF_CORE_COUNT {
        if !info.is_null() {
            let original = (*info).number_of_processors;
            if original < cores {
                send_event(&CpuEvent {
                    event_type: "cpu_spoofed",
                    function: "GetSystemInfo",
                    original_cores: original,
                    spoofed_cores: cores,
                });
                (*info).number_of_processors = cores;
            }
        }
    }
}

unsafe extern "system" fn det_get_native_system_info(info: *mut SystemInfo) {
    ORIG_GET_NATIVE_SYSTEM_INFO.unwrap()(info);
    if let Some(cores) = SPOOF_CORE_COUNT {
        if !info.is_null() {
            let original = (*info).number_of_processors;
            if original < cores {
                send_event(&CpuEvent {
                    event_type: "cpu_spoofed",
                    function: "GetNativeSystemInfo",
                    original_cores: original,
                    spoofed_cores: cores,
                });
                (*info).number_of_processors = cores;
            }
        }
    }
}

pub unsafe fn install(config: &CpuConfig) -> anyhow::Result<()> {
    SPOOF_CORE_COUNT = config.spoof_core_count;

    if config.spoof_core_count.is_none() {
        return Ok(());
    }

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GetSystemInfo\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_get_system_info as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_GET_SYSTEM_INFO = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GetNativeSystemInfo\0".as_ptr()))
    {
        let t = MinHook::create_hook(addr as _, det_get_native_system_info as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_GET_NATIVE_SYSTEM_INFO = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
