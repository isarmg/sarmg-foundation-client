//! Interpret editor preferences without invoking a shell.

use super::{Result, fail};
use std::{
    ffi::{OsStr, OsString},
    io,
    path::Path,
    process::{Command, ExitStatus, Stdio},
};

pub(super) fn run(value: &OsStr, file: &Path) -> Result<ExitStatus> {
    // Try the original literal executable first. This also preserves OS lookup
    // behavior such as PATH names with spaces and Windows' implicit .exe suffix.
    let launch = |command: &mut Command| {
        command
            .arg(file)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
    };
    match launch(&mut Command::new(value)) {
        Ok(status) => Ok(status),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::InvalidFilename
            ) && !Path::new(value).is_file() =>
        {
            launch(&mut command(value)?)
                .map_err(|error| fail(8, "editor_failed").with_detail(error))
        }
        Err(error) => Err(fail(8, "editor_failed").with_detail(error)),
    }
}

fn command(value: &OsStr) -> Result<Command> {
    // Historically the entire value was an executable path. Preserve existing
    // files first, including unquoted paths with spaces or quote characters.
    if Path::new(value).is_file() {
        return Ok(Command::new(value));
    }
    let words = split(value)?;
    let (program, arguments) = words
        .split_first()
        .filter(|(program, _)| !program.is_empty())
        .ok_or_else(|| fail(2, "editor_not_configured"))?;
    let mut command = Command::new(program);
    command.args(arguments);
    Ok(command)
}

#[cfg(unix)]
fn split(value: &OsStr) -> Result<Vec<OsString>> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    shlex::bytes::split(value.as_bytes())
        .map(|words| words.into_iter().map(OsString::from_vec).collect())
        .ok_or_else(|| fail(2, "editor_failed").with_detail("Invalid editor command quoting."))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn split(value: &OsStr) -> Result<Vec<OsString>> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};

    let value: Vec<u16> = value.encode_wide().collect();
    // The native API treats an empty command line as the current executable.
    // Do not let an empty editor preference relaunch the product itself.
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.contains(&0) {
        return Err(fail(2, "editor_failed"));
    }
    let value: Vec<u16> = value.into_iter().chain(Some(0)).collect();
    let mut count = 0;
    // SAFETY: value is NUL-terminated and count is writable. On success the
    // native API owns one allocation containing count NUL-terminated strings.
    let argv = unsafe { CommandLineToArgvW(value.as_ptr(), &mut count) };
    if argv.is_null() {
        return Err(fail(8, "editor_failed").with_detail(std::io::Error::last_os_error()));
    }
    struct Arguments(*mut *mut u16);
    impl Drop for Arguments {
        fn drop(&mut self) {
            // SAFETY: the sole allocation from CommandLineToArgvW is freed once,
            // after all borrowed strings have been copied into owned OsStrings.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    let allocation = Arguments(argv);
    // SAFETY: the API guarantees count valid string pointers in this allocation.
    let pointers = unsafe { std::slice::from_raw_parts(allocation.0, count as usize) };
    Ok(pointers
        .iter()
        .map(|&pointer| {
            let mut len = 0;
            // SAFETY: each returned string is NUL-terminated and the allocation
            // remains live throughout the scan and the owned copy below.
            unsafe {
                while *pointer.add(len) != 0 {
                    len += 1;
                }
                OsString::from_wide(std::slice::from_raw_parts(pointer, len))
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_supports_wait_flags_and_quoted_arguments() {
        let command = command(OsStr::new("code --wait \"two words\" \"\"")).unwrap();
        assert_eq!(command.get_program(), "code");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--wait", "two words", ""]
        );
    }

    #[test]
    fn editor_preserves_existing_literal_path_with_spaces() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("editor helper");
        std::fs::write(&path, b"").unwrap();
        let command = command(path.as_os_str()).unwrap();
        assert_eq!(command.get_program(), path.as_os_str());
        assert_eq!(command.get_args().count(), 0);
    }

    #[test]
    fn editor_empty_preferences_do_not_launch_a_program() {
        for value in ["", "\"\""] {
            assert_eq!(
                command(OsStr::new(value)).unwrap_err().code,
                "editor_not_configured"
            );
        }
    }

    #[test]
    fn editor_does_not_expand_shell_expressions() {
        let command = command(OsStr::new("editor \"$HOME\" \"*.json\" \"$(echo text)\"")).unwrap();
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["$HOME", "*.json", "$(echo text)"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn editor_unix_quotes_and_non_unicode_bytes_are_preserved() {
        use std::os::unix::ffi::OsStrExt;
        let command = command(OsStr::from_bytes(
            b"'/some editor' -f 'a\xff b' escaped\\ space",
        ))
        .unwrap();
        assert_eq!(command.get_program(), "/some editor");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-f"),
                OsStr::from_bytes(b"a\xff b"),
                OsStr::new("escaped space")
            ]
        );
        assert_eq!(
            super::command(OsStr::new("editor 'unfinished"))
                .unwrap_err()
                .code,
            "editor_failed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn editor_windows_paths_and_backslashes_are_preserved() {
        let command = command(OsStr::new(
            r#""C:\Program Files\Editor\editor.exe" --wait "C:\work files\document.json""#,
        ))
        .unwrap();
        assert_eq!(command.get_program(), r"C:\Program Files\Editor\editor.exe");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--wait", r"C:\work files\document.json"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn editor_windows_keeps_unpaired_utf16_and_quoted_backslashes() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let value = OsString::from_wide(&[101, 100, 105, 116, 111, 114, 32, 0xd800]);
        let parsed = command(&value).unwrap();
        assert_eq!(
            parsed
                .get_args()
                .next()
                .unwrap()
                .encode_wide()
                .collect::<Vec<_>>(),
            [0xd800]
        );
        let arguments = [r"C:\trailing slash\", "embedded \"quote", ""];
        let value = format!(
            "editor {}",
            arguments
                .iter()
                .map(|value| super::super::elevation::windows_quote_argument(value))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let parsed = command(OsStr::new(&value)).unwrap();
        assert_eq!(parsed.get_args().collect::<Vec<_>>(), arguments);
    }

    #[cfg(windows)]
    #[test]
    fn editor_windows_literal_path_retains_implicit_exe_extension() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("editor helper.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        // The test harness receives a nonmatching test filter and exits without
        // recursively running tests. No real editor or shell is launched.
        let status = run(
            path.with_extension("").as_os_str(),
            Path::new("xcsc-no-such-test-filter"),
        )
        .unwrap();
        assert!(status.success());
    }
}
