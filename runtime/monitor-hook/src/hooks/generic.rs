use crate::config::GenericHook;
use crate::pipe::send_event;
use minhook::MinHook;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;
use std::sync::Mutex;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

thread_local! {
    static CURRENT_HOOK_ID: Cell<usize> = const { Cell::new(0) };
}

struct GenericHookInfo {
    dll_name: String,
    function_name: String,
    original: *mut c_void,
}

unsafe impl Send for GenericHookInfo {}
unsafe impl Sync for GenericHookInfo {}

static GENERIC_HOOKS: Lazy<Mutex<HashMap<usize, GenericHookInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Serialize)]
struct GenericHookEvent {
    event_type: &'static str,
    dll: String,
    function: String,
    args: Vec<usize>,
}

macro_rules! define_trampoline {
    ($name:ident, $n:expr, $($arg:ident),*) => {
        unsafe extern "system" fn $name($($arg: usize),*) -> usize {
            let args = vec![$($arg),*];
            let hook_id = CURRENT_HOOK_ID.with(|id| id.get());

            let (dll, func, original) = {
                let hooks = GENERIC_HOOKS.lock().unwrap();
                if let Some(info) = hooks.get(&hook_id) {
                    (info.dll_name.clone(), info.function_name.clone(), info.original)
                } else {
                    return 0;
                }
            };

            let event = GenericHookEvent {
                event_type: "generic_hook",
                dll,
                function: func,
                args: args.clone(),
            };
            send_event(&event);

            call_original(original, &args)
        }
    };
}

define_trampoline!(trampoline_0, 0,);
define_trampoline!(trampoline_1, 1, a1);
define_trampoline!(trampoline_2, 2, a1, a2);
define_trampoline!(trampoline_3, 3, a1, a2, a3);
define_trampoline!(trampoline_4, 4, a1, a2, a3, a4);
define_trampoline!(trampoline_5, 5, a1, a2, a3, a4, a5);
define_trampoline!(trampoline_6, 6, a1, a2, a3, a4, a5, a6);

unsafe fn call_original(original: *mut c_void, args: &[usize]) -> usize {
    match args.len() {
        0 => {
            let f: unsafe extern "system" fn() -> usize = mem::transmute(original);
            f()
        }
        1 => {
            let f: unsafe extern "system" fn(usize) -> usize = mem::transmute(original);
            f(args[0])
        }
        2 => {
            let f: unsafe extern "system" fn(usize, usize) -> usize = mem::transmute(original);
            f(args[0], args[1])
        }
        3 => {
            let f: unsafe extern "system" fn(usize, usize, usize) -> usize =
                mem::transmute(original);
            f(args[0], args[1], args[2])
        }
        4 => {
            let f: unsafe extern "system" fn(usize, usize, usize, usize) -> usize =
                mem::transmute(original);
            f(args[0], args[1], args[2], args[3])
        }
        5 => {
            let f: unsafe extern "system" fn(usize, usize, usize, usize, usize) -> usize =
                mem::transmute(original);
            f(args[0], args[1], args[2], args[3], args[4])
        }
        6 => {
            let f: unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> usize =
                mem::transmute(original);
            f(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        _ => 0,
    }
}

fn get_trampoline(num_args: usize) -> Option<*mut c_void> {
    match num_args {
        0 => Some(trampoline_0 as *mut c_void),
        1 => Some(trampoline_1 as *mut c_void),
        2 => Some(trampoline_2 as *mut c_void),
        3 => Some(trampoline_3 as *mut c_void),
        4 => Some(trampoline_4 as *mut c_void),
        5 => Some(trampoline_5 as *mut c_void),
        6 => Some(trampoline_6 as *mut c_void),
        _ => None,
    }
}

pub unsafe fn install_hooks(hooks: &[GenericHook]) -> anyhow::Result<()> {
    for hook in hooks {
        if let Err(e) = install_single_hook(hook) {
            crate::pipe::send_status(
                "generic_hook_error",
                Some(&format!("{}!{}: {}", hook.dll, hook.function, e)),
            );
        }
    }
    Ok(())
}

unsafe fn install_single_hook(hook: &GenericHook) -> anyhow::Result<()> {
    let dll_cstr = format!("{}\0", hook.dll);
    let func_cstr = format!("{}\0", hook.function);

    let module = GetModuleHandleA(PCSTR::from_raw(dll_cstr.as_ptr()))
        .or_else(|_| LoadLibraryA(PCSTR::from_raw(dll_cstr.as_ptr())).map(|h| h.into()))
        .map_err(|e| anyhow::anyhow!("Failed to load {}: {}", hook.dll, e))?;

    let addr = GetProcAddress(module, PCSTR::from_raw(func_cstr.as_ptr()))
        .ok_or_else(|| anyhow::anyhow!("Function {} not found in {}", hook.function, hook.dll))?;

    let target_addr = addr as usize;

    let wrapper = create_wrapper_for_hook(target_addr, hook.num_args)?;

    let original = MinHook::create_hook(addr as _, wrapper)
        .map_err(|e| anyhow::anyhow!("create_hook failed: {:?}", e))?;

    MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("enable_hook failed: {:?}", e))?;

    let mut hooks_map = GENERIC_HOOKS.lock().unwrap();
    hooks_map.insert(
        target_addr,
        GenericHookInfo {
            dll_name: hook.dll.clone(),
            function_name: hook.function.clone(),
            original,
        },
    );

    crate::pipe::send_status(
        "generic_hook_installed",
        Some(&format!("{}!{}", hook.dll, hook.function)),
    );

    Ok(())
}

unsafe fn create_wrapper_for_hook(hook_id: usize, num_args: usize) -> anyhow::Result<*mut c_void> {
    let base_trampoline = get_trampoline(num_args)
        .ok_or_else(|| anyhow::anyhow!("Unsupported arg count: {}", num_args))?;

    CURRENT_HOOK_ID.with(|id| id.set(hook_id));

    Ok(base_trampoline)
}
