//! Native local-only named pipe, administrator/service ACL, authenticated server image.
use super::*;
use std::{
    fs::File,
    io::{Read, Write},
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
    let digest = Sha256::digest(path.to_string_lossy().to_lowercase().as_bytes());
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    wide(format!(r"\\.\pipe\xcsc-status-{hash}"))
}
fn trusted(pid: u32, verify_image: bool) -> bool {
    // SAFETY: only successful SDK calls create uniquely owned File handles.
    // Token storage is initialized, bounded and u64-aligned; fixed structures
    // and native image lengths are checked before Rust references/slices.
    // SDK SID pointers remain backed by the token allocation during use.
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
        if required < std::mem::size_of::<TOKEN_USER>() as u32 || required > 16384 {
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
        if required as usize > user.len() * 8 || required < std::mem::size_of::<TOKEN_USER>() as u32
        {
            return false;
        }
        let sid = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut elevation = TOKEN_ELEVATION::default();
        let elevated = GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut required,
        ) != 0
            && required == std::mem::size_of::<TOKEN_ELEVATION>() as u32
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
            if len as usize > image.len() {
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
    let mut writer = file;
    let mut offset = 0;
    let deadline = Instant::now() + Duration::from_millis(500);
    while offset < bytes.len() && Instant::now() < deadline {
        let written = match writer.write(&bytes[offset..]) {
            Ok(written) => written,
            Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => 0,
            Err(_) => return false,
        };
        offset += written;
        if written == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    offset == bytes.len()
}
fn read_available(file: &File, bytes: &mut [u8]) -> std::io::Result<usize> {
    let mut reader = file;
    match reader.read(bytes) {
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_NO_DATA as i32 || code == ERROR_PIPE_LISTENING as i32) => {
            Ok(0)
        }
        result => result,
    }
}
pub(super) fn publish(
    path: &Path,
    binding: String,
    revision: String,
) -> std::io::Result<Publisher> {
    // SAFETY: this fixed local-only pipe name and DACL are NUL terminated and
    // live through the SDK calls. LocalFree owns the descriptor; File owns the
    // successful pipe handle, moved once into the worker. Initialized SDK
    // output pointers never escape; no handle is concurrently closed.
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
        let creation_error = std::io::Error::last_os_error();
        LocalFree(descriptor);
        if raw == INVALID_HANDLE_VALUE {
            return Err(creation_error);
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
                // when the client connected. Client authorization uses that
                // DACL and requires no process-token query by LocalService.
                // The reader authenticates our image, service identity and
                // binding before accepting a response.
                if GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) != 0 {
                    let mut bytes = [0u8; 14];
                    let mut count = 0;
                    let deadline = Instant::now() + Duration::from_millis(500);
                    while count < bytes.len() && Instant::now() < deadline {
                        let Ok(read) = read_available(&pipe, &mut bytes[count..]) else {
                            break;
                        };
                        count += read;
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
                            let Ok(got) = read_available(&pipe, &mut ack[count..]) else {
                                break;
                            };
                            count += got;
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
    // SAFETY: the bounded NUL-terminated pipe name is held during open. File
    // owns the successful non-inheritable handle; fixed initialized output
    // slots stay live. The authenticated server PID is checked before any
    // bytes are accepted. Ordinary reads/writes use safe std::io slices.
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
            let Ok(read) = read_available(&pipe, &mut part) else {
                break;
            };
            if read > 0 {
                bytes.extend_from_slice(&part[..read]);
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
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }
}
