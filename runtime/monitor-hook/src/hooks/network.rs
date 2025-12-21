use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

// ============================================================================
// WinSock Types (ws2_32.dll)
// ============================================================================

type ConnectFn = unsafe extern "system" fn(usize, *const u8, i32) -> i32;
type SendFn = unsafe extern "system" fn(usize, *const u8, i32, i32) -> i32;
type RecvFn = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;

// ============================================================================
// WinINet Types (wininet.dll)
// ============================================================================

type InternetOpenUrlAFn =
    unsafe extern "system" fn(*mut c_void, *const u8, *const u8, u32, u32, usize) -> *mut c_void;

// ============================================================================
// Original Function Pointers
// ============================================================================

static mut ORIGINAL_CONNECT: Option<ConnectFn> = None;
static mut ORIGINAL_SEND: Option<SendFn> = None;
static mut ORIGINAL_RECV: Option<RecvFn> = None;
static mut ORIGINAL_INTERNET_OPEN_URL: Option<InternetOpenUrlAFn> = None;

// ============================================================================
// Event Structures
// ============================================================================

#[derive(Serialize)]
struct NetworkConnectEvent {
    event_type: &'static str,
    socket: usize,
    address_family: u16,
    port: u16,
    ip_address: String,
}

#[derive(Serialize)]
struct NetworkSendEvent {
    event_type: &'static str,
    socket: usize,
    bytes_sent: i32,
}

#[derive(Serialize)]
struct NetworkRecvEvent {
    event_type: &'static str,
    socket: usize,
    bytes_received: i32,
}

#[derive(Serialize)]
struct HttpRequestEvent {
    event_type: &'static str,
    url: String,
}

// ============================================================================
// Detour Functions
// ============================================================================

unsafe extern "system" fn detour_connect(socket: usize, addr: *const u8, addrlen: i32) -> i32 {
    let original = ORIGINAL_CONNECT.expect("Original not set");
    let result = original(socket, addr, addrlen);

    if result == 0 && addrlen >= 8 {
        // Parse sockaddr_in structure
        let family = *(addr as *const u16);
        let port = u16::from_be(*(addr.add(2) as *const u16));
        let ip_bytes = std::slice::from_raw_parts(addr.add(4), 4);
        let ip_address = format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        );

        let event = NetworkConnectEvent {
            event_type: "connect",
            socket,
            address_family: family,
            port,
            ip_address,
        };
        send_event(&event);
    }
    result
}

unsafe extern "system" fn detour_send(socket: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    let original = ORIGINAL_SEND.expect("Original not set");
    let result = original(socket, buf, len, flags);

    if result > 0 {
        let event = NetworkSendEvent {
            event_type: "send",
            socket,
            bytes_sent: result,
        };
        send_event(&event);
    }
    result
}

unsafe extern "system" fn detour_recv(socket: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let original = ORIGINAL_RECV.expect("Original not set");
    let result = original(socket, buf, len, flags);

    if result > 0 {
        let event = NetworkRecvEvent {
            event_type: "recv",
            socket,
            bytes_received: result,
        };
        send_event(&event);
    }
    result
}

unsafe extern "system" fn detour_internet_open_url(
    h_internet: *mut c_void,
    url: *const u8,
    headers: *const u8,
    headers_len: u32,
    flags: u32,
    context: usize,
) -> *mut c_void {
    let original = ORIGINAL_INTERNET_OPEN_URL.expect("Original not set");

    // Capture URL before call
    let url_str = if !url.is_null() {
        let mut len = 0;
        while *url.add(len) != 0 {
            len += 1;
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(url, len)).to_string()
    } else {
        String::new()
    };

    let result = original(h_internet, url, headers, headers_len, flags, context);

    if !result.is_null() {
        let event = HttpRequestEvent {
            event_type: "InternetOpenUrlA",
            url: url_str,
        };
        send_event(&event);
    }
    result
}

// ============================================================================
// Installation
// ============================================================================

pub unsafe fn install_all() -> anyhow::Result<()> {
    // WinSock hooks (ws2_32.dll)
    if let Ok(ws2_32) = GetModuleHandleA(PCSTR::from_raw("ws2_32.dll\0".as_ptr())) {
        install_winsock_hooks(ws2_32)?;
    } else if let Ok(ws2_32) = LoadLibraryA(PCSTR::from_raw("ws2_32.dll\0".as_ptr())) {
        install_winsock_hooks(ws2_32.into())?;
    }

    // WinINet hooks (wininet.dll) - load if needed
    if let Ok(wininet) = GetModuleHandleA(PCSTR::from_raw("wininet.dll\0".as_ptr())) {
        install_wininet_hooks(wininet)?;
    }

    Ok(())
}

unsafe fn install_winsock_hooks(module: windows::Win32::Foundation::HMODULE) -> anyhow::Result<()> {
    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("connect\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_connect as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook connect: {:?}", e))?;
        ORIGINAL_CONNECT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook connect: {:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("send\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_send as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook send: {:?}", e))?;
        ORIGINAL_SEND = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook send: {:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("recv\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_recv as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook recv: {:?}", e))?;
        ORIGINAL_RECV = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook recv: {:?}", e))?;
    }

    Ok(())
}

unsafe fn install_wininet_hooks(module: windows::Win32::Foundation::HMODULE) -> anyhow::Result<()> {
    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("InternetOpenUrlA\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_internet_open_url as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook InternetOpenUrlA: {:?}", e))?;
        ORIGINAL_INTERNET_OPEN_URL = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook InternetOpenUrlA: {:?}", e))?;
    }

    Ok(())
}
