//! Bounded native mapped-module enumeration, with explicit access errors.
#[cfg(windows)]
pub fn paths(pid: u32) -> Result<Vec<String>, String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE},
        System::Diagnostics::ToolHelp::*,
    };
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        let mut ok = Module32FirstW(snapshot, &mut entry);
        let mut paths = vec![];
        while ok != 0 && paths.len() < 1024 {
            let length = entry
                .szExePath
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExePath.len());
            paths.push(String::from_utf16_lossy(&entry.szExePath[..length]));
            ok = Module32NextW(snapshot, &mut entry);
        }
        let error = GetLastError();
        CloseHandle(snapshot);
        if ok != 0 {
            return Err("Mapped module limit reached; refusing a partial baseline".into());
        }
        if error != ERROR_NO_MORE_FILES {
            return Err(std::io::Error::from_raw_os_error(error as i32).to_string());
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}
#[cfg(target_os = "macos")]
mod apple {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        dead_code
    )]
    include!(concat!(env!("OUT_DIR"), "/mac_proc.rs"));
}
#[cfg(target_os = "macos")]
pub fn paths(pid: u32) -> Result<Vec<String>, String> {
    let started = std::time::Instant::now();
    let mut address = 0u64;
    let mut paths = std::collections::BTreeSet::new();
    for _ in 0..16384 {
        if started.elapsed() > std::time::Duration::from_millis(500) {
            return Err("Mapped region scan timed out; refusing a partial baseline".into());
        }
        let mut region: apple::proc_regionwithpathinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&region) as i32;
        let read = unsafe {
            apple::proc_pidinfo(
                pid as i32,
                apple::PROC_PIDREGIONPATHINFO as i32,
                address,
                (&mut region as *mut apple::proc_regionwithpathinfo).cast(),
                size,
            )
        };
        if read != size {
            let error = std::io::Error::last_os_error();
            if !paths.is_empty()
                && matches!(error.raw_os_error(), Some(libc::EINVAL) | Some(libc::ESRCH))
            {
                return Ok(paths.into_iter().collect());
            }
            return Err(error.to_string());
        }
        let raw = &region.prp_vip.vip_path;
        let bytes: Vec<u8> = raw
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        if let Ok(path) = String::from_utf8(bytes) {
            if path.starts_with('/') {
                paths.insert(path);
            }
        }
        address = region
            .prp_prinfo
            .pri_address
            .checked_add(region.prp_prinfo.pri_size)
            .filter(|next| *next > address)
            .ok_or("Invalid mapped region boundary")?;
    }
    Err("Mapped region limit reached; refusing a partial baseline".into())
}
#[cfg(test)]
mod tests {
    #[test]
    fn own_process_has_mapped_executable() {
        let paths = super::paths(std::process::id()).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert!(paths
            .iter()
            .any(|p| std::path::Path::new(p).canonicalize().ok() == exe.canonicalize().ok()));
    }
}
