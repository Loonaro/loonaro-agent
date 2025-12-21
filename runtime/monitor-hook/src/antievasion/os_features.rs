use crate::config::OsFeaturesConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use std::sync::RwLock;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type GlobalMemoryStatusExFn = unsafe extern "system" fn(*mut MemoryStatusEx) -> i32;

#[repr(C)]
struct MemoryStatusEx {
    length: u32,
    memory_load: u32,
    total_phys: u64,
    avail_phys: u64,
    total_page_file: u64,
    avail_page_file: u64,
    total_virtual: u64,
    avail_virtual: u64,
    avail_extended_virtual: u64,
}

static ORIG_GLOBAL_MEMORY_STATUS: RwLock<Option<GlobalMemoryStatusExFn>> = RwLock::new(None);
static SPOOF_MEMORY: RwLock<Option<u64>> = RwLock::new(None);
static HIDE_HYPERVISOR: RwLock<bool> = RwLock::new(false);

#[derive(Serialize)]
struct OsFeaturesEvent {
    event_type: &'static str,
    feature: &'static str,
    original_bytes: u64,
    spoofed_bytes: u64,
}

unsafe extern "system" fn det_global_memory_status(info: *mut MemoryStatusEx) -> i32 {
    let result = ORIG_GLOBAL_MEMORY_STATUS.read().unwrap().unwrap()(info);

    if result != 0 && !info.is_null() {
        if let Some(spoof_mem) = *SPOOF_MEMORY.read().unwrap() {
            let original = (*info).total_phys;

            if original < spoof_mem {
                send_event(&OsFeaturesEvent {
                    event_type: "memory_spoofed",
                    feature: "GlobalMemoryStatusEx",
                    original_bytes: original,
                    spoofed_bytes: spoof_mem,
                });
                (*info).total_phys = spoof_mem;
            }
        }
    }

    result
}

pub unsafe fn install(config: &OsFeaturesConfig) -> anyhow::Result<()> {
    *SPOOF_MEMORY.write().unwrap() = config.spoof_memory_size;
    *HIDE_HYPERVISOR.write().unwrap() = config.hide_hypervisor;

    if SPOOF_MEMORY.read().unwrap().is_none() {
        return Ok(());
    }

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GlobalMemoryStatusEx\0".as_ptr()))
    {
        let t = MinHook::create_hook(addr as _, det_global_memory_status as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        *ORIG_GLOBAL_MEMORY_STATUS.write().unwrap() = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
