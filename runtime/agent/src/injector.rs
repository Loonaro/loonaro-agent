use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, FALSE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, INFINITE, LPTHREAD_START_ROUTINE,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, WaitForSingleObject,
};
use windows::core::PWSTR;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub unsafe fn spawn_and_inject(exe_path: &str, dll_path: &str) -> Result<()> {
    // Ensure absolute path for DLL
    let abs_dll_path = std::fs::canonicalize(dll_path)
        .context("Dll path not found")?
        .to_string_lossy()
        .to_string();

    let mut wide_exe = to_wide(exe_path);
    let wide_dll = to_wide(&abs_dll_path);

    // Wait, WriteProcessMemory takes *const c_void for buffer.

    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    // Create Suspended
    let created = unsafe {
        CreateProcessW(
            None,
            PWSTR(wide_exe.as_mut_ptr()),
            None,
            None,
            FALSE,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
    };

    if created.is_err() {
        return Err(anyhow::anyhow!(
            "CreateProcessW failed: {:?}",
            created.err()
        ));
    }

    println!("Spawned process PID: {}", pi.dwProcessId);

    // Prepare Injection
    let kernel32 = unsafe { GetModuleHandleW(windows::core::w!("kernel32.dll")) }?;
    let load_library = unsafe { GetProcAddress(kernel32, windows::core::s!("LoadLibraryW")) }
        .ok_or(anyhow::anyhow!("LoadLibraryW not found"))?;

    // Alloc for DLL Path
    let size = wide_dll.len() * 2;
    let mem = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if mem.is_null() {
        return Err(anyhow::anyhow!("VirtualAllocEx failed"));
    }

    // Write DLL Path
    let mut written = 0;
    let write_res = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            mem,
            wide_dll.as_ptr() as *const c_void,
            size,
            Some(&mut written),
        )
    };

    if write_res.is_err() || written != size {
        return Err(anyhow::anyhow!("WriteProcessMemory failed"));
    }

    // Create Remote Thread -> LoadLibraryW(path)
    let thread_start: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(load_library) };

    let remote_thread =
        unsafe { CreateRemoteThread(pi.hProcess, None, 0, thread_start, Some(mem), 0, None) }?;

    println!("Injection thread created.");
    unsafe {
        WaitForSingleObject(remote_thread, INFINITE);
        let _ = CloseHandle(remote_thread);
    }

    // Resume
    unsafe {
        let _ = ResumeThread(pi.hThread);
    };

    println!("Resumed main thread.");

    unsafe {
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }

    Ok(())
}
