use crate::pipe::send_event;
use minhook::MinHook;
use serde::Serialize;
use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

// ============================================================================
// BCrypt Types (bcrypt.dll)
// ============================================================================

type BCryptEncryptFn = unsafe extern "system" fn(
    *mut c_void,
    *const u8,
    u32,
    *mut c_void,
    *mut u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    u32,
) -> NTSTATUS;

type BCryptDecryptFn = unsafe extern "system" fn(
    *mut c_void,
    *const u8,
    u32,
    *mut c_void,
    *mut u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    u32,
) -> NTSTATUS;

type BCryptHashDataFn = unsafe extern "system" fn(*mut c_void, *const u8, u32, u32) -> NTSTATUS;

// ============================================================================
// CryptAPI Types (advapi32.dll / crypt32.dll)
// ============================================================================

type CryptEncryptFn =
    unsafe extern "system" fn(usize, usize, i32, u32, *mut u8, *mut u32, u32) -> i32;

type CryptDecryptFn = unsafe extern "system" fn(usize, usize, i32, u32, *mut u8, *mut u32) -> i32;

// ============================================================================
// Original Function Pointers
// ============================================================================

static mut ORIGINAL_BCRYPT_ENCRYPT: Option<BCryptEncryptFn> = None;
static mut ORIGINAL_BCRYPT_DECRYPT: Option<BCryptDecryptFn> = None;
static mut ORIGINAL_BCRYPT_HASH_DATA: Option<BCryptHashDataFn> = None;
static mut ORIGINAL_CRYPT_ENCRYPT: Option<CryptEncryptFn> = None;
static mut ORIGINAL_CRYPT_DECRYPT: Option<CryptDecryptFn> = None;

// ============================================================================
// Event Structures
// ============================================================================

#[derive(Serialize)]
struct CryptoEvent {
    event_type: &'static str,
    operation: &'static str,
    input_size: u32,
    output_size: u32,
    success: bool,
}

// ============================================================================
// Detour Functions
// ============================================================================

unsafe extern "system" fn detour_bcrypt_encrypt(
    h_key: *mut c_void,
    input: *const u8,
    input_len: u32,
    padding_info: *mut c_void,
    iv: *mut u8,
    iv_len: u32,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    flags: u32,
) -> NTSTATUS {
    let original = ORIGINAL_BCRYPT_ENCRYPT.expect("Original not set");
    let status = original(
        h_key,
        input,
        input_len,
        padding_info,
        iv,
        iv_len,
        output,
        output_len,
        result_len,
        flags,
    );

    let event = CryptoEvent {
        event_type: "BCryptEncrypt",
        operation: "encrypt",
        input_size: input_len,
        output_size: if !result_len.is_null() {
            *result_len
        } else {
            0
        },
        success: status.0 >= 0,
    };
    send_event(&event);

    status
}

unsafe extern "system" fn detour_bcrypt_decrypt(
    h_key: *mut c_void,
    input: *const u8,
    input_len: u32,
    padding_info: *mut c_void,
    iv: *mut u8,
    iv_len: u32,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    flags: u32,
) -> NTSTATUS {
    let original = ORIGINAL_BCRYPT_DECRYPT.expect("Original not set");
    let status = original(
        h_key,
        input,
        input_len,
        padding_info,
        iv,
        iv_len,
        output,
        output_len,
        result_len,
        flags,
    );

    let event = CryptoEvent {
        event_type: "BCryptDecrypt",
        operation: "decrypt",
        input_size: input_len,
        output_size: if !result_len.is_null() {
            *result_len
        } else {
            0
        },
        success: status.0 >= 0,
    };
    send_event(&event);

    status
}

unsafe extern "system" fn detour_bcrypt_hash_data(
    h_hash: *mut c_void,
    input: *const u8,
    input_len: u32,
    flags: u32,
) -> NTSTATUS {
    let original = ORIGINAL_BCRYPT_HASH_DATA.expect("Original not set");
    let status = original(h_hash, input, input_len, flags);

    let event = CryptoEvent {
        event_type: "BCryptHashData",
        operation: "hash",
        input_size: input_len,
        output_size: 0,
        success: status.0 >= 0,
    };
    send_event(&event);

    status
}

unsafe extern "system" fn detour_crypt_encrypt(
    h_key: usize,
    h_hash: usize,
    is_final: i32,
    flags: u32,
    data: *mut u8,
    data_len: *mut u32,
    buf_len: u32,
) -> i32 {
    let original = ORIGINAL_CRYPT_ENCRYPT.expect("Original not set");
    let input_size = if !data_len.is_null() { *data_len } else { 0 };
    let result = original(h_key, h_hash, is_final, flags, data, data_len, buf_len);

    let event = CryptoEvent {
        event_type: "CryptEncrypt",
        operation: "encrypt",
        input_size,
        output_size: if !data_len.is_null() { *data_len } else { 0 },
        success: result != 0,
    };
    send_event(&event);

    result
}

unsafe extern "system" fn detour_crypt_decrypt(
    h_key: usize,
    h_hash: usize,
    is_final: i32,
    flags: u32,
    data: *mut u8,
    data_len: *mut u32,
) -> i32 {
    let original = ORIGINAL_CRYPT_DECRYPT.expect("Original not set");
    let input_size = if !data_len.is_null() { *data_len } else { 0 };
    let result = original(h_key, h_hash, is_final, flags, data, data_len);

    let event = CryptoEvent {
        event_type: "CryptDecrypt",
        operation: "decrypt",
        input_size,
        output_size: if !data_len.is_null() { *data_len } else { 0 },
        success: result != 0,
    };
    send_event(&event);

    result
}

// ============================================================================
// Installation
// ============================================================================

pub unsafe fn install_all() -> anyhow::Result<()> {
    // BCrypt hooks (bcrypt.dll)
    if let Ok(bcrypt) = GetModuleHandleA(PCSTR::from_raw("bcrypt.dll\0".as_ptr()))
        .or_else(|_| LoadLibraryA(PCSTR::from_raw("bcrypt.dll\0".as_ptr())).map(|h| h.into()))
    {
        install_bcrypt_hooks(bcrypt)?;
    }

    // CryptAPI hooks (advapi32.dll)
    if let Ok(advapi32) = GetModuleHandleA(PCSTR::from_raw("advapi32.dll\0".as_ptr())) {
        install_cryptapi_hooks(advapi32)?;
    }

    Ok(())
}

unsafe fn install_bcrypt_hooks(module: windows::Win32::Foundation::HMODULE) -> anyhow::Result<()> {
    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("BCryptEncrypt\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_bcrypt_encrypt as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook BCryptEncrypt: {:?}", e))?;
        ORIGINAL_BCRYPT_ENCRYPT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook BCryptEncrypt: {:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("BCryptDecrypt\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_bcrypt_decrypt as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook BCryptDecrypt: {:?}", e))?;
        ORIGINAL_BCRYPT_DECRYPT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook BCryptDecrypt: {:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("BCryptHashData\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_bcrypt_hash_data as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook BCryptHashData: {:?}", e))?;
        ORIGINAL_BCRYPT_HASH_DATA = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook BCryptHashData: {:?}", e))?;
    }

    Ok(())
}

unsafe fn install_cryptapi_hooks(
    module: windows::Win32::Foundation::HMODULE,
) -> anyhow::Result<()> {
    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("CryptEncrypt\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_crypt_encrypt as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook CryptEncrypt: {:?}", e))?;
        ORIGINAL_CRYPT_ENCRYPT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook CryptEncrypt: {:?}", e))?;
    }

    if let Some(addr) = GetProcAddress(module, PCSTR::from_raw("CryptDecrypt\0".as_ptr())) {
        let trampoline = MinHook::create_hook(addr as _, detour_crypt_decrypt as *mut c_void)
            .map_err(|e| anyhow::anyhow!("create_hook CryptDecrypt: {:?}", e))?;
        ORIGINAL_CRYPT_DECRYPT = Some(mem::transmute(trampoline));
        MinHook::enable_hook(addr as _)
            .map_err(|e| anyhow::anyhow!("enable_hook CryptDecrypt: {:?}", e))?;
    }

    Ok(())
}
