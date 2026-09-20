//! Read-only local status protocol. No configuration, secrets or control verbs.
//!
//! The operating-system bindings need narrowly scoped FFI for peer identity and
//! named-pipe access. All unsafe code stays inside this Foundation-owned module.
#![allow(unsafe_code)]
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
static SNAPSHOT: OnceLock<Mutex<Value>> = OnceLock::new();
/// Update one public observation in the active local-status snapshot.
///
/// Calls made before a publisher starts are intentionally ignored. Secrets and
/// configuration contents must never be passed through this diagnostic channel.
pub fn observe(field: &str, value: Value) {
    if let Some(snapshot) = SNAPSHOT.get()
        && let Ok(mut s) = snapshot.lock()
    {
        s[field] = value;
        s["sequence"] = json!(s["sequence"].as_u64().unwrap_or(0) + 1);
        s["observed_at"] = json!(now());
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// Owns the local-status endpoint thread and stops it on drop.
pub struct Publisher {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Publisher {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
#[cfg(unix)]
fn trusted(stream: &std::os::unix::net::UnixStream, owner: u32) -> bool {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    unsafe {
        let mut credential: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut len,
        ) == 0
            && (credential.uid == owner || credential.uid == 0)
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let mut uid = 0;
        let mut gid = 0;
        libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && (uid == owner || uid == 0)
    }
}
#[cfg(unix)]
/// Publish a read-only status endpoint inside an existing protected state directory.
pub fn publish(path: &Path, binding: String, revision: String) -> std::io::Result<Publisher> {
    use std::{
        io::{Read, Write},
        os::unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixListener,
        },
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    let directory = sarmg_client_fs_safety::PrivateDirectory::open_for_administration(path)
        .map_err(std::io::Error::other)?;
    let owner = std::fs::symlink_metadata(path)?.uid();
    let socket = path.join("runtime-status.sock");
    // Caller owns the maintenance gate; only a stale socket can remain here.
    if let Ok(m) = std::fs::symlink_metadata(&socket) {
        if !m.file_type().is_socket() || m.uid() != owner {
            return Err(std::io::Error::other("unsafe status endpoint"));
        }
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let snapshot = SNAPSHOT.get_or_init(|| Mutex::new(Value::Null));
    *snapshot
        .lock()
        .map_err(|_| std::io::Error::other("status lock poisoned"))? = json!({"ipc_version":1,"service_epoch":uuid::Uuid::new_v4(),"sequence":1,"binding_generation":binding,"effective_revision":revision,"observed_at":now(),"runtime":"running","business_health":"unknown"});
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let thread = std::thread::spawn(move || {
        let _directory = directory;
        while !stopping.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !trusted(&stream, owner) {
                        continue;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                    let mut request = [0u8; 14];
                    if stream.read_exact(&mut request).is_ok()
                        && &request == b"GetStatus/1\n\0\0"
                        && let Ok(s) = SNAPSHOT.get().unwrap().lock()
                        && let Ok(bytes) = serde_json::to_vec(&*s)
                        && bytes.len() <= 32768
                    {
                        let _ = stream.write_all(&bytes);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(_) => break,
            }
        }
        let _ = std::fs::remove_file(socket);
    });
    Ok(Publisher {
        stop,
        thread: Some(thread),
    })
}
#[cfg(unix)]
/// Read a bounded status snapshot and optionally require an exact binding generation.
pub fn read(path: &Path, binding: Option<&str>) -> Option<Value> {
    use std::{
        io::{Read, Write},
        os::unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
        time::Duration,
    };
    let _directory =
        sarmg_client_fs_safety::PrivateDirectory::open_for_administration(path).ok()?;
    let owner = std::fs::symlink_metadata(path).ok()?.uid();
    let socket = path.join("runtime-status.sock");
    let m = std::fs::symlink_metadata(&socket).ok()?;
    if !m.file_type().is_socket() || m.uid() != owner || m.mode() & 0o777 != 0o600 {
        return None;
    }
    let mut stream = UnixStream::connect(socket).ok()?;
    if !trusted(&stream, owner) {
        return None;
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream.write_all(b"GetStatus/1\n\0\0").ok()?;
    let mut bytes = Vec::new();
    stream.take(32769).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 32768 {
        return None;
    }
    let mut value: Value = serde_json::from_slice(&bytes).ok()?;
    if value["ipc_version"] != 1 || binding.is_some_and(|b| value["binding_generation"] != b) {
        return None;
    }
    value["available"] = json!(true);
    value["stale"] = json!(false);
    Some(value)
}
#[cfg(windows)]
mod windows;
#[cfg(windows)]
/// Publish the protected Windows named-pipe status endpoint.
pub fn publish(path: &Path, binding: String, revision: String) -> std::io::Result<Publisher> {
    windows::publish(path, binding, revision)
}
#[cfg(windows)]
/// Read the Windows named-pipe status snapshot from the authenticated service image.
pub fn read(path: &Path, binding: Option<&str>) -> Option<Value> {
    windows::read(path, binding)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn socket_is_readonly_bounded_and_bound_to_this_runtime() {
        // Darwin per-user TMPDIR can exceed the Unix socket path limit.
        let root = std::path::Path::new("/tmp")
            .canonicalize()
            .unwrap()
            .join(format!("client-status-{}", uuid::Uuid::new_v4()));
        let directory = sarmg_client_fs_safety::PrivateDirectory::create(&root).unwrap();
        let publisher = publish(&root, "binding-a".into(), "revision-a".into()).unwrap();
        let first = read(&root, Some("binding-a")).unwrap();
        assert_eq!(first["ipc_version"], 1);
        assert_eq!(first["effective_revision"], "revision-a");
        assert!(read(&root, Some("binding-b")).is_none());
        observe("last_ack_at", json!(42));
        let second = read(&root, Some("binding-a")).unwrap();
        assert_eq!(second["service_epoch"], first["service_epoch"]);
        assert!(second["sequence"].as_u64() > first["sequence"].as_u64());
        drop(publisher);
        assert!(read(&root, None).is_none());
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }
}
