use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

mod antievasion;
mod config;
mod hooks;
mod pipe;

fn debug_log(msg: &str) {
    unsafe {
        let formatted = format!("[loonaro-hook] {}\0", msg);
        OutputDebugStringA(PCSTR::from_raw(formatted.as_ptr()));
    }
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HMODULE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            std::thread::spawn(|| {
                if let Err(e) = initialize() {
                    debug_log(&format!("Initialization failed: {}", e));
                }
            });
        }
        DLL_PROCESS_DETACH => {
            debug_log("DLL detaching");
            pipe::send_status("detaching", None);
            let _ = hooks::cleanup();
        }
        _ => {}
    }
    BOOL::from(true)
}

fn initialize() -> anyhow::Result<()> {
    debug_log("Connecting to agent pipe...");

    let config = match pipe::connect_and_handshake() {
        Ok(cfg) => cfg,
        Err(e) => {
            debug_log(&format!("Pipe connection failed: {}", e));
            return Err(e);
        }
    };

    pipe::send_status("connected", None);
    debug_log(&format!(
        "Received config: {} categories",
        config.categories.len()
    ));

    if let Err(e) = hooks::install(config.clone()) {
        pipe::send_status("hook_error", Some(&e.to_string()));
        debug_log(&format!("Hook installation failed: {}", e));
        return Err(e);
    }

    if let Err(e) = antievasion::install(&config.anti_evasion) {
        pipe::send_status("antievasion_error", Some(&e.to_string()));
        debug_log(&format!("Anti-evasion installation failed: {}", e));
        return Err(e);
    }

    pipe::send_status("ready", None);
    debug_log("Initialization complete");

    Ok(())
}
