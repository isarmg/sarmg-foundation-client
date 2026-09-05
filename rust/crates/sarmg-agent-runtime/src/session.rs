//! Exclusive delivery lifetime, separate from short credential transactions.

use crate::{Error, SingleInstanceLock};
use sarmg_agent_fs_safety::PrivateDirectory;
use std::path::Path;

/// Owns the private state directory and its single delivery-instance lock.
/// Acquire before bootstrap/collection, retain through delivery shutdown, and
/// use the anchored directory for child resources. Pairing and read-only
/// diagnostics must not acquire this delivery lock.
pub struct AgentSession {
    directory: PrivateDirectory,
    _lock: SingleInstanceLock,
}

impl AgentSession {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let directory = PrivateDirectory::create(path)?;
        let lock = SingleInstanceLock::acquire(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    pub fn directory(&self) -> &PrivateDirectory {
        &self.directory
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    #[test]
    fn session_rejects_unsafe_lock_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        let directory = PrivateDirectory::create(&path).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, "untouched").unwrap();
        let lock = path.join("agent.instance.lock");
        symlink(&target, &lock).unwrap();
        assert!(AgentSession::open(&path).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        fs::remove_file(&lock).unwrap();
        fs::write(&lock, "unsafe lock").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AgentSession::open(&path).is_err());
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o644
        );
        drop(directory);
    }

    #[test]
    fn session_excludes_another_process_until_its_owner_drops() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        let session = AgentSession::open(&path).unwrap();
        let check_contender = |expected| {
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "session::tests::contender_process_helper",
                ])
                .env("SARMG_AGENT_SESSION_TEST_PATH", &path)
                .env("SARMG_AGENT_SESSION_TEST_EXPECT", expected)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        check_contender("busy");
        drop(session);
        check_contender("free");
        assert!(path.join("agent.instance.lock").is_file());
    }

    #[test]
    #[ignore = "subprocess helper invoked by session_excludes_another_process_until_its_owner_drops"]
    fn contender_process_helper() {
        let path = std::env::var_os("SARMG_AGENT_SESSION_TEST_PATH").unwrap();
        let result = AgentSession::open(Path::new(&path));
        if std::env::var("SARMG_AGENT_SESSION_TEST_EXPECT").unwrap() == "busy" {
            assert!(matches!(result, Err(Error::AlreadyRunning)));
        } else {
            assert!(result.is_ok());
        }
    }
}
