use crate::config::TimingConfig;
use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

static SLEEP_SKIP_ENABLED: AtomicBool = AtomicBool::new(false);
static SLEEP_THRESHOLD_MS: AtomicU64 = AtomicU64::new(100);
static TIME_ACCEL_FACTOR: AtomicU64 = AtomicU64::new(1);
static TICK_BASE_REAL: AtomicU64 = AtomicU64::new(0);
static TICK_BASE_FAKE: AtomicU64 = AtomicU64::new(0);

type SleepFn = unsafe extern "system" fn(u32);
type SleepExFn = unsafe extern "system" fn(u32, i32) -> u32;
type NtDelayExecutionFn = unsafe extern "system" fn(u8, *const i64) -> i32;
type WaitForSingleObjectFn = unsafe extern "system" fn(HANDLE, u32) -> u32;
type WaitForMultipleObjectsFn = unsafe extern "system" fn(u32, *const HANDLE, i32, u32) -> u32;
type GetTickCountFn = unsafe extern "system" fn() -> u32;
type GetTickCount64Fn = unsafe extern "system" fn() -> u64;
type QueryPerformanceCounterFn = unsafe extern "system" fn(*mut i64) -> i32;

static mut ORIG_SLEEP: Option<SleepFn> = None;
static mut ORIG_SLEEP_EX: Option<SleepExFn> = None;
static mut ORIG_NT_DELAY: Option<NtDelayExecutionFn> = None;
static mut ORIG_WAIT_SINGLE: Option<WaitForSingleObjectFn> = None;
static mut ORIG_WAIT_MULTI: Option<WaitForMultipleObjectsFn> = None;
static mut ORIG_TICK_COUNT: Option<GetTickCountFn> = None;
static mut ORIG_TICK_COUNT64: Option<GetTickCount64Fn> = None;
static mut ORIG_QPC: Option<QueryPerformanceCounterFn> = None;

#[derive(Serialize)]
struct TimingEvent {
    event_type: &'static str,
    function: &'static str,
    requested_ms: u64,
    actual_ms: u64,
    skipped: bool,
}

fn accelerate_delay(ms: u64) -> (u64, bool) {
    if !SLEEP_SKIP_ENABLED.load(Ordering::Relaxed) {
        return (ms, false);
    }
    let threshold = SLEEP_THRESHOLD_MS.load(Ordering::Relaxed);
    if ms > threshold {
        (threshold, true)
    } else {
        (ms, false)
    }
}

unsafe extern "system" fn det_sleep(ms: u32) {
    let (actual, skipped) = accelerate_delay(ms as u64);
    send_event(&TimingEvent {
        event_type: "timing",
        function: "Sleep",
        requested_ms: ms as u64,
        actual_ms: actual,
        skipped,
    });
    ORIG_SLEEP.unwrap()(actual as u32);
}

unsafe extern "system" fn det_sleep_ex(ms: u32, alertable: i32) -> u32 {
    let (actual, skipped) = accelerate_delay(ms as u64);
    send_event(&TimingEvent {
        event_type: "timing",
        function: "SleepEx",
        requested_ms: ms as u64,
        actual_ms: actual,
        skipped,
    });
    ORIG_SLEEP_EX.unwrap()(actual as u32, alertable)
}

unsafe extern "system" fn det_nt_delay(alertable: u8, interval: *const i64) -> i32 {
    let requested = if !interval.is_null() {
        ((-*interval) / 10000) as u64
    } else {
        0
    };
    let (actual, skipped) = accelerate_delay(requested);
    send_event(&TimingEvent {
        event_type: "timing",
        function: "NtDelayExecution",
        requested_ms: requested,
        actual_ms: actual,
        skipped,
    });
    let actual_100ns = -(actual as i64 * 10000);
    ORIG_NT_DELAY.unwrap()(alertable, &actual_100ns)
}

unsafe extern "system" fn det_wait_single(handle: HANDLE, ms: u32) -> u32 {
    if ms != 0xFFFFFFFF {
        let (actual, skipped) = accelerate_delay(ms as u64);
        if skipped {
            send_event(&TimingEvent {
                event_type: "timing",
                function: "WaitForSingleObject",
                requested_ms: ms as u64,
                actual_ms: actual,
                skipped,
            });
            return ORIG_WAIT_SINGLE.unwrap()(handle, actual as u32);
        }
    }
    ORIG_WAIT_SINGLE.unwrap()(handle, ms)
}

unsafe extern "system" fn det_wait_multi(
    count: u32,
    handles: *const HANDLE,
    wait_all: i32,
    ms: u32,
) -> u32 {
    if ms != 0xFFFFFFFF {
        let (actual, skipped) = accelerate_delay(ms as u64);
        if skipped {
            send_event(&TimingEvent {
                event_type: "timing",
                function: "WaitForMultipleObjects",
                requested_ms: ms as u64,
                actual_ms: actual,
                skipped,
            });
            return ORIG_WAIT_MULTI.unwrap()(count, handles, wait_all, actual as u32);
        }
    }
    ORIG_WAIT_MULTI.unwrap()(count, handles, wait_all, ms)
}

unsafe extern "system" fn det_tick_count() -> u32 {
    let real = ORIG_TICK_COUNT.unwrap()();
    let factor = TIME_ACCEL_FACTOR.load(Ordering::Relaxed);
    if factor <= 1 {
        return real;
    }
    let base_r = TICK_BASE_REAL.load(Ordering::Relaxed) as u32;
    let base_f = TICK_BASE_FAKE.load(Ordering::Relaxed) as u32;
    base_f.wrapping_add((real.wrapping_sub(base_r)) * factor as u32)
}

unsafe extern "system" fn det_tick_count64() -> u64 {
    let real = ORIG_TICK_COUNT64.unwrap()();
    let factor = TIME_ACCEL_FACTOR.load(Ordering::Relaxed);
    if factor <= 1 {
        return real;
    }
    let base_r = TICK_BASE_REAL.load(Ordering::Relaxed);
    let base_f = TICK_BASE_FAKE.load(Ordering::Relaxed);
    base_f.wrapping_add((real.wrapping_sub(base_r)) * factor)
}

unsafe extern "system" fn det_qpc(counter: *mut i64) -> i32 {
    let result = ORIG_QPC.unwrap()(counter);
    let factor = TIME_ACCEL_FACTOR.load(Ordering::Relaxed);
    if result != 0 && !counter.is_null() && factor > 1 {
        *counter *= factor as i64;
    }
    result
}

pub unsafe fn install(config: &TimingConfig) -> anyhow::Result<()> {
    SLEEP_SKIP_ENABLED.store(config.sleep_skip_enabled, Ordering::Relaxed);
    SLEEP_THRESHOLD_MS.store(config.sleep_skip_threshold_ms, Ordering::Relaxed);
    TIME_ACCEL_FACTOR.store(config.time_acceleration_factor, Ordering::Relaxed);

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;
    let ntdll = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr()))?;

    if let Some(f) = GetProcAddress(kernel32, PCSTR::from_raw("GetTickCount64\0".as_ptr())) {
        let func: GetTickCount64Fn = mem::transmute(f);
        let now = func();
        TICK_BASE_REAL.store(now, Ordering::Relaxed);
        TICK_BASE_FAKE.store(now, Ordering::Relaxed);
    }

    if config.sleep_skip_enabled {
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("Sleep\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_sleep as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_SLEEP = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("SleepEx\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_sleep_ex as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_SLEEP_EX = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(ntdll, PCSTR::from_raw("NtDelayExecution\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_nt_delay as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_NT_DELAY = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) =
            GetProcAddress(kernel32, PCSTR::from_raw("WaitForSingleObject\0".as_ptr()))
        {
            let t = MinHook::create_hook(addr as _, det_wait_single as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_WAIT_SINGLE = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(
            kernel32,
            PCSTR::from_raw("WaitForMultipleObjects\0".as_ptr()),
        ) {
            let t = MinHook::create_hook(addr as _, det_wait_multi as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_WAIT_MULTI = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    if config.time_acceleration_factor > 1 {
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GetTickCount\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_tick_count as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_TICK_COUNT = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(kernel32, PCSTR::from_raw("GetTickCount64\0".as_ptr())) {
            let t = MinHook::create_hook(addr as _, det_tick_count64 as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_TICK_COUNT64 = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        if let Some(addr) = GetProcAddress(
            kernel32,
            PCSTR::from_raw("QueryPerformanceCounter\0".as_ptr()),
        ) {
            let t = MinHook::create_hook(addr as _, det_qpc as *mut c_void)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            ORIG_QPC = Some(mem::transmute(t));
            MinHook::enable_hook(addr as _).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Ok(())
}
