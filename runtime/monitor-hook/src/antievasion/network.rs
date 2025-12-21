use crate::config::NetworkConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use std::sync::RwLock;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

const VM_MAC_PREFIXES: &[[u8; 3]] = &[
    [0x00, 0x0C, 0x29], // VMware
    [0x00, 0x50, 0x56], // VMware
    [0x00, 0x05, 0x69], // VMware
    [0x08, 0x00, 0x27], // VirtualBox
    [0x00, 0x1C, 0x42], // Parallels
    [0x00, 0x1C, 0x14], // VMware
    [0x00, 0x03, 0xFF], // Microsoft Hyper-V
    [0x00, 0x15, 0x5D], // Microsoft Hyper-V
];

type GetAdaptersInfoFn = unsafe extern "system" fn(*mut u8, *mut u32) -> u32;

static ORIG_GET_ADAPTERS_INFO: RwLock<Option<GetAdaptersInfoFn>> = RwLock::new(None);
static SPOOF_MAC: RwLock<Option<[u8; 6]>> = RwLock::new(None);
static HIDE_VM_ADAPTERS: RwLock<bool> = RwLock::new(false);

#[derive(Serialize)]
struct NetworkEvent {
    event_type: &'static str,
    action: &'static str,
}

fn is_vm_mac(mac: &[u8]) -> bool {
    if mac.len() < 3 {
        return false;
    }
    VM_MAC_PREFIXES.iter().any(|prefix| mac[0..3] == *prefix)
}

unsafe extern "system" fn det_get_adapters_info(info: *mut u8, size: *mut u32) -> u32 {
    let result = ORIG_GET_ADAPTERS_INFO.read().unwrap().unwrap()(info, size);

    if result == 0 && !info.is_null() {
        let mut current = info;
        while !current.is_null() {
            let addr_len_offset = 400;
            let addr_offset = 404;
            let next_offset = 0;

            let addr_len = *(current.add(addr_len_offset) as *const u32);
            if addr_len == 6 {
                let mac = std::slice::from_raw_parts_mut(current.add(addr_offset), 6);

                if is_vm_mac(mac) {
                    if let Some(spoof) = *SPOOF_MAC.read().unwrap() {
                        mac.copy_from_slice(&spoof);
                        send_event(&NetworkEvent {
                            event_type: "network_mac_spoofed",
                            action: "replaced_vm_mac",
                        });
                    } else if *HIDE_VM_ADAPTERS.read().unwrap() {
                        mac[0] = 0x00;
                        mac[1] = 0x1A;
                        mac[2] = 0x2B;
                        send_event(&NetworkEvent {
                            event_type: "network_mac_spoofed",
                            action: "randomized_vm_mac",
                        });
                    }
                }
            }

            let next_ptr = *(current.add(next_offset) as *const *mut u8);
            current = next_ptr;
        }
    }

    result
}

pub unsafe fn install(config: &NetworkConfig) -> anyhow::Result<()> {
    *HIDE_VM_ADAPTERS.write().unwrap() = config.hide_vm_adapters;

    if let Some(ref mac_str) = config.spoof_mac_address {
        let parts: Vec<u8> = mac_str
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&parts);
            *SPOOF_MAC.write().unwrap() = Some(mac);
        }
    }

    if !*HIDE_VM_ADAPTERS.read().unwrap() && SPOOF_MAC.read().unwrap().is_none() {
        return Ok(());
    }

    let iphlpapi = GetModuleHandleA(PCSTR::from_raw("iphlpapi.dll\0".as_ptr()))
        .or_else(|_| LoadLibraryA(PCSTR::from_raw("iphlpapi.dll\0".as_ptr())).map(|h| h.into()))?;

    if let Some(addr) = GetProcAddress(iphlpapi, PCSTR::from_raw("GetAdaptersInfo\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_get_adapters_info as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        *ORIG_GET_ADAPTERS_INFO.write().unwrap() = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
