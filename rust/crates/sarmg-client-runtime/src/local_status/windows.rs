//! Native local-only named pipe, administrator/service ACL, authenticated server image.
use super::*;
use std::{
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};
fn wide(text: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain(Some(0)).collect()
}
fn pipe_name(path: &Path) -> Vec<u16> {
    use sha2::{Digest, Sha256};
    wide(format!(
        r"\\.\pipe\sarmg-client-status-{:x}",
        Sha256::digest(path.to_string_lossy().to_lowercase().as_bytes())
    ))
}
fn trusted(pid: u32, verify_image: bool) -> bool {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return false;
        }
        let process = File::from_raw_handle(process);
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = File::from_raw_handle(token);
        let mut required = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
        if required == 0 || required > 16384 {
            return false;
        }
        let mut user = vec![0u64; (required as usize).div_ceil(8)];
        if GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            required,
            &mut required,
        ) == 0
        {
            return false;
        }
        let sid = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let elevated = GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut required,
        ) != 0
            && elevation.TokenIsElevated != 0;
        if IsWellKnownSid(sid, WinLocalSystemSid) == 0
            && IsWellKnownSid(sid, WinLocalServiceSid) == 0
            && !elevated
        {
            return false;
        }
        if verify_image {
            let mut image = vec![0u16; 32768];
            let mut len = image.len() as u32;
            if QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut len)
                == 0
            {
                return false;
            }
            let actual = String::from_utf16_lossy(&image[..len as usize]);
            let Ok(expected) = std::env::current_exe() else {
                return false;
            };
            if !actual.eq_ignore_ascii_case(&expected.to_string_lossy()) {
                return false;
            }
        }
        true
    }
}
fn write_bounded(file: &File, bytes: &[u8]) -> bool {
    unsafe {
        let mut offset = 0;
        let deadline = Instant::now() + Duration::from_millis(500);
        while offset < bytes.len() && Instant::now() < deadline {
            let mut written = 0;
            let ok = WriteFile(
                file.as_raw_handle(),
                bytes[offset..].as_ptr(),
                (bytes.len() - offset) as u32,
                &mut written,
                std::ptr::null_mut(),
            );
            if ok == 0 && GetLastError() != ERROR_NO_DATA {
                return false;
            }
            offset += written as usize;
            if written == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        offset == bytes.len()
    }
}
pub(super) fn publish(
    path: &Path,
    binding: String,
    revision: String,
) -> std::io::Result<Publisher> {
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)");
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let raw = CreateNamedPipeW(
            pipe_name(path).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            32768,
            64,
            500,
            &attributes,
        );
        LocalFree(descriptor);
        if raw == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let pipe = File::from_raw_handle(raw);
        *SNAPSHOT
            .get_or_init(|| Mutex::new(Value::Null))
            .lock()
            .map_err(|_| std::io::Error::other("status lock poisoned"))? = json!({"ipc_version":1,"service_epoch":uuid::Uuid::new_v4(),"sequence":1,"binding_generation":binding,"effective_revision":revision,"observed_at":now(),"runtime":"running","business_health":"unknown"});
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let connected = ConnectNamedPipe(pipe.as_raw_handle(), std::ptr::null_mut()) != 0
                    || GetLastError() == ERROR_PIPE_CONNECTED;
                if !connected {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                let mut pid = 0;
                // The protected pipe DACL authorizes only SYSTEM, elevated
                // administrators and LocalService. Windows already checked it
                // when the client connected. LocalService cannot query an
                // administrator's process token; that redundant check rejects
                // authorized clients. The reader still authenticates our image,
                // service identity and binding before accepting a response.
                if GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) != 0 {
                    let mut bytes = [0u8; 14];
                    let mut count = 0;
                    let deadline = Instant::now() + Duration::from_millis(500);
                    while count < bytes.len() && Instant::now() < deadline {
                        let mut read = 0;
                        let ok = ReadFile(
                            pipe.as_raw_handle(),
                            bytes[count..].as_mut_ptr(),
                            (bytes.len() - count) as u32,
                            &mut read,
                            std::ptr::null_mut(),
                        );
                        if ok == 0 && GetLastError() != ERROR_NO_DATA {
                            break;
                        }
                        count += read as usize;
                        if read == 0 {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                    if count == 14
                        && &bytes == b"GetStatus/1\n\0\0"
                        && let Ok(snapshot) = SNAPSHOT.get().unwrap().lock()
                        && let Ok(bytes) = serde_json::to_vec(&*snapshot)
                        && bytes.len() <= 32768
                        && write_bounded(&pipe, &bytes)
                    {
                        let deadline = Instant::now() + Duration::from_millis(500);
                        let mut ack = [0u8; 4];
                        let mut count = 0;
                        while count < 4 && Instant::now() < deadline {
                            let mut got = 0;
                            let ok = ReadFile(
                                pipe.as_raw_handle(),
                                ack[count..].as_mut_ptr(),
                                (4 - count) as u32,
                                &mut got,
                                std::ptr::null_mut(),
                            );
                            if ok == 0 && GetLastError() != ERROR_NO_DATA {
                                break;
                            }
                            count += got as usize;
                            if got == 0 {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                    }
                }
                DisconnectNamedPipe(pipe.as_raw_handle());
            }
        });
        Ok(Publisher {
            stop,
            thread: Some(thread),
        })
    }
}
pub(super) fn read(path: &Path, binding: Option<&str>) -> Option<Value> {
    unsafe {
        let handle = CreateFileW(
            pipe_name(path).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let pipe = File::from_raw_handle(handle);
        let mut pid = 0;
        if GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) == 0 || !trusted(pid, true) {
            return None;
        }
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        if SetNamedPipeHandleState(
            pipe.as_raw_handle(),
            &mode,
            std::ptr::null(),
            std::ptr::null(),
        ) == 0
        {
            return None;
        }
        if !write_bounded(&pipe, b"GetStatus/1\n\0\0") {
            return None;
        }
        let mut bytes = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            let mut part = [0u8; 4096];
            let mut read = 0;
            let ok = ReadFile(
                pipe.as_raw_handle(),
                part.as_mut_ptr(),
                part.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            );
            if read > 0 {
                bytes.extend_from_slice(&part[..read as usize]);
                if bytes.len() > 32768 {
                    return None;
                }
                if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
                    if value["ipc_version"] != 1
                        || binding.is_some_and(|b| value["binding_generation"] != b)
                    {
                        return None;
                    }
                    value["available"] = json!(true);
                    value["stale"] = json!(false);
                    write_bounded(&pipe, b"ACK\n");
                    return Some(value);
                }
            }
            if ok == 0 && !matches!(GetLastError(), ERROR_NO_DATA | ERROR_PIPE_LISTENING) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }
}
