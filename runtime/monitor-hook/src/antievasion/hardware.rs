use crate::config::HardwareConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const VM_DISK_STRINGS: &[&str] = &["vbox", "vmware", "virtual", "qemu", "xen", "parallels"];

type DeviceIoControlFn = unsafe extern "system" fn(
    HANDLE,
    u32,
    *const c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
) -> i32;

static mut ORIG_DEVICE_IO_CONTROL: Option<DeviceIoControlFn> = None;
static mut ENABLED: bool = false;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

#[derive(Serialize)]
struct HardwareEvent {
    event_type: &'static str,
    ioctl: u32,
    modified: bool,
}

unsafe extern "system" fn det_device_io_control(
    device: HANDLE,
    control_code: u32,
    in_buffer: *const c_void,
    in_size: u32,
    out_buffer: *mut c_void,
    out_size: u32,
    bytes_returned: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let result = ORIG_DEVICE_IO_CONTROL.unwrap()(
        device,
        control_code,
        in_buffer,
        in_size,
        out_buffer,
        out_size,
        bytes_returned,
        overlapped,
    );

    if ENABLED
        && control_code == IOCTL_STORAGE_QUERY_PROPERTY
        && result != 0
        && !out_buffer.is_null()
    {
        let returned = if !bytes_returned.is_null() {
            *bytes_returned
        } else {
            out_size
        };
        if returned > 0 {
            let buffer = std::slice::from_raw_parts_mut(out_buffer as *mut u8, returned as usize);
            let buffer_str = String::from_utf8_lossy(buffer).to_lowercase();

            for vm_str in VM_DISK_STRINGS {
                if buffer_str.contains(vm_str) {
                    send_event(&HardwareEvent {
                        event_type: "hardware_query_modified",
                        ioctl: control_code,
                        modified: true,
                    });

                    for i in 0..buffer.len() {
                        if buffer[i] != 0 && (buffer[i] as char).is_alphabetic() {
                            buffer[i] = b'X';
                        }
                    }
                    break;
                }
            }
        }
    }

    result
}

pub unsafe fn install(config: &HardwareConfig) -> anyhow::Result<()> {
    ENABLED = config.spoof_disk_size.is_some() || config.spoof_bios_vendor.is_some();

    if !ENABLED {
        return Ok(());
    }

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

    if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("DeviceIoControl\0".as_ptr())) {
        let t = MinHook::create_hook(addr as _, det_device_io_control as *mut c_void)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        ORIG_DEVICE_IO_CONTROL = Some(mem::transmute(t));
        MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}
