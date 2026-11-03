//! Platform-specific primitives. Linux kernel tools are never reported as
//! active on other operating systems.
#[cfg(not(target_os = "linux"))]
pub mod firewall;

pub fn control_process(pid: u32, terminate: bool) -> Result<serde_json::Value, String> {
    #[cfg(unix)]
    {
        let name = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .map_err(|e| e.to_string())?;
        let state = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "stat="])
            .output()
            .map_err(|e| e.to_string())?;
        if !state.status.success() || state.stdout.is_empty() {
            return Err("Process exited or access denied".into());
        }
        let suspended = !state.stdout.contains(&b'T') && !terminate;
        let signal = if terminate {
            libc::SIGKILL
        } else if suspended {
            libc::SIGSTOP
        } else {
            libc::SIGCONT
        };
        if unsafe { libc::kill(pid as i32, signal) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(
            serde_json::json!({"ok":true,"pid":pid,"name":String::from_utf8_lossy(&name.stdout).trim(),"suspended":suspended}),
        )
    }
    #[cfg(windows)]
    {
        use std::sync::{Mutex, OnceLock};
        use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::*};
        static SUSPENDED: OnceLock<Mutex<std::collections::HashMap<u32, u64>>> = OnceLock::new();
        let mut suspended = SUSPENDED.get_or_init(Default::default).lock().unwrap();
        unsafe {
            let handle = OpenProcess(
                PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            #[link(name = "ntdll")]
            unsafe extern "system" {
                fn NtSuspendProcess(handle: *mut std::ffi::c_void) -> i32;
                fn NtResumeProcess(handle: *mut std::ffi::c_void) -> i32;
            }
            let mut created = std::mem::zeroed();
            let mut exited = std::mem::zeroed();
            let mut kernel = std::mem::zeroed();
            let mut user = std::mem::zeroed();
            if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
                let error = std::io::Error::last_os_error().to_string();
                CloseHandle(handle);
                return Err(error);
            }
            let identity = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
            let resume = suspended.get(&pid) == Some(&identity);
            let result = if terminate {
                if TerminateProcess(handle, 1) != 0 {
                    0
                } else {
                    -1
                }
            } else if resume {
                NtResumeProcess(handle)
            } else {
                NtSuspendProcess(handle)
            };
            CloseHandle(handle);
            if result < 0 {
                return Err(format!("Process control failed: {result:#x}"));
            }
            if terminate || resume {
                suspended.remove(&pid);
            } else {
                suspended.insert(pid, identity);
            }
            Ok(serde_json::json!({"ok":true,"pid":pid,"suspended":!terminate&&!resume}))
        }
    }
}
