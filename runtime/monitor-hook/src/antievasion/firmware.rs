use crate::config::FirmwareConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const VM_FIRMWARE_STRINGS: &[&[u8]] = &[
    b"VBOX",
    b"VMWARE",
    b"VIRTUAL",
    b"QEMU",
    b"XEN",
    b"PARALLELS",
    b"VirtualBox",
    b"VMware",
    b"Hyper-V",
    b"Microsoft Corporation",
    b"innotek GmbH",
    b"Oracle",
    b"Bochs",
    b"SeaBIOS",
];

type GetSystemFirmwareTableFn = unsafe extern "system" fn(u32, u32, *mut c_void, u32) -> u32;
type NtQuerySystemInformationFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

static mut ORIG_GET_FIRMWARE_TABLE: Option<GetSystemFirmwareTableFn> = None;
static mut ORIG_NT_QUERY_SYSTEM_INFO: Option<NtQuerySystemInformationFn> = None;
static mut HIDE_SMBIOS: bool = false;
static mut HIDE_ACPI: bool = false;

const SYSTEM_FIRMWARE_TABLE_INFO: u32 = 76;

#[derive(Serialize)]
struct FirmwareEvent {
    event_type: &'static str,
    table_type: &'static str,
    scrubbed: bool,
}

fn scrub_vm_strings(buffer: &mut [u8]) -> bool {
    let mut modified = false;
    for vm_str in VM_FIRMWARE_STRINGS {
        let vm_str_len = vm_str.len();
        for i in 0..buffer.len().saturating_sub(vm_str_len) {
            if buffer[i..i + vm_str_len].eq_ignore_ascii_case(vm_str) {
                for j in 0..vm_str_len {
                    if buffer[i + j] != 0 {
                        buffer[i + j] = b'X';
                    }
                }
                modified = true;
            }
        }
    }
    modified
}

unsafe extern "system" fn det_get_firmware_table(
    table_provider: u32,
    table_id: u32,
    buffer: *mut c_void,
    size: u32,
) -> u32 {
    let result = ORIG_GET_FIRMWARE_TABLE.unwrap()(table_provider, table_id, buffer, size);

    if result > 0 && !buffer.is_null() {
        let is_smbios = table_provider == u32::from_le_bytes(*b"RSMB");
        let is_acpi = table_provider == u32::from_le_bytes(*b"ACPI");

        if (HIDE_SMBIOS && is_smbios) || (HIDE_ACPI && is_acpi) {
            let buf_slice = std::slice::from_raw_parts_mut(buffer as *mut u8, result as usize);
            if scrub_vm_strings(buf_slice) {
                send_event(&FirmwareEvent {
                    event_type: "firmware_scrubbed",
                    table_type: if is_smbios { "SMBIOS" } else { "ACPI" },
                    scrubbed: true,
                });
            }
        }
    }

    result
}

unsafe extern "system" fn det_nt_query_system_info(
    info_class: u32,
    buffer: *mut c_void,
    length: u32,
    return_length: *mut u32,
) -> i32 {
    let result = ORIG_NT_QUERY_SYSTEM_INFO.unwrap()(info_class, buffer, length, return_length);

    if result >= 0 && info_class == SYSTEM_FIRMWARE_TABLE_INFO && !buffer.is_null() {
        let buf_len = if !return_length.is_null() {
            *return_length
        } else {
            length
        };
        if buf_len > 16 {
            let buf_slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buf_len as usize);
            if scrub_vm_strings(&mut buf_slice[16..]) {
                send_event(&FirmwareEvent {
                    event_type: "firmware_scrubbed",
                    table_type: "SystemFirmwareTableInformation",
                    scrubbed: true,
                });
            }
        }
    }

    result
}

pub unsafe fn install(config: &FirmwareConfig) -> anyhow::Result<()> {
    HIDE_SMBIOS = config.hide_smbios_vm_strings;
    HIDE_ACPI = config.hide_acpi_vm_strings;

    if !HIDE_SMBIOS && !HIDE_ACPI {
        return Ok(());
    }

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;
    let ntdll = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(
        kernel32,
        PCSTR::from_raw("GetSystemFirmwareTable\0".as_ptr()),
    ) {
        let t = MinHook::create_hook(addr as _, det_get_firmware_table as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_GET_FIRMWARE_TABLE = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(
        ntdll,
        PCSTR::from_raw("NtQuerySystemInformation\0".as_ptr()),
    ) {
        let t = MinHook::create_hook(addr as _, det_nt_query_system_info as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_NT_QUERY_SYSTEM_INFO = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
