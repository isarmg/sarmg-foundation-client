//! Windows setup elevation and native handle ownership.

use crate::cli::{Result, duration, fail};
use std::{
    io::{self, IsTerminal},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
pub enum WindowsSetupElevation {
    Continue,
    ChildExited(u8),
}

#[cfg(windows)]
pub fn prepare_windows_setup_elevation(
    raw: &[String],
    interactive: bool,
    installer_session: bool,
    elevated_child: bool,
) -> Result<WindowsSetupElevation> {
    let elevated = windows_is_elevated()?;
    if !interactive {
        return if elevated {
            Ok(WindowsSetupElevation::Continue)
        } else {
            Err(fail(7, "administrator_privileges_required").at_step("configuration"))
        };
    }
    if elevated_child {
        return if elevated {
            if interactive {
                eprintln!(
                    "Administrator Setup process started. Secret input is hidden; paste or type it, then press Enter."
                );
            }
            Ok(WindowsSetupElevation::Continue)
        } else {
            Err(fail(7, "elevation_failed").at_step("configuration"))
        };
    }
    if installer_session || !elevated {
        eprintln!(
            "Setup requires administrator privileges. Continue in the elevated console window after approving UAC."
        );
        let timeout = windows_setup_timeout(raw)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| fail(2, "invalid_timeout").at_step("configuration"))?;
        return windows_relaunch_elevated(raw, deadline).map(WindowsSetupElevation::ChildExited);
    }
    Ok(WindowsSetupElevation::Continue)
}

#[cfg(windows)]
pub fn pause_installer_setup() {
    if io::stdin().is_terminal() {
        eprintln!("Press Enter to close Setup.");
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }
}

#[cfg(windows)]
fn windows_is_elevated() -> Result<bool> {
    use std::{ffi::c_void, mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = null_mut();
    // SAFETY: the current-process pseudo handle is valid and token is a live
    // initialized output slot. Only a successful call creates an owned guard.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(fail(6, "elevation_failed").with_detail(std::io::Error::last_os_error()));
    }
    // SAFETY: OpenProcessToken succeeded and transferred this unique handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: this initialized fixed SDK structure and length output remain
    // live for the call; TOKEN_QUERY authorizes this information class.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(fail(6, "elevation_failed").with_detail(std::io::Error::last_os_error()));
    }
    if returned != size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(fail(6, "elevation_failed"));
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
fn windows_setup_timeout(raw: &[String]) -> Result<Duration> {
    let mut arguments = raw.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--timeout" {
            let value = arguments
                .next()
                .ok_or_else(|| fail(2, "missing_option_value"))?;
            return duration(value);
        }
    }
    duration("60s")
}

#[cfg(windows)]
fn windows_relaunch_elevated(raw: &[String], deadline: Instant) -> Result<u8> {
    use std::{ffi::OsStr, mem::size_of, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{GetExitCodeProcess, WaitForSingleObject},
        UI::{
            Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    let executable =
        std::env::current_exe().map_err(|error| fail(6, "elevation_failed").with_detail(error))?;
    let mut child_args = raw.to_vec();
    child_args.push("--elevated-setup-child".into());
    let parameters = child_args
        .iter()
        .map(|argument| windows_quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let verb = wide(OsStr::new("runas"));
    let executable = wide(executable.as_os_str());
    let parameters = wide(OsStr::new(&parameters));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..SHELLEXECUTEINFOW::default()
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        let failure = if code == ERROR_CANCELLED {
            fail(7, "elevation_cancelled")
        } else {
            fail(6, "elevation_failed").with_detail(std::io::Error::from_raw_os_error(code as i32))
        };
        return Err(failure.at_step("configuration"));
    }
    if info.hProcess.is_null() {
        return Err(fail(6, "elevation_failed").at_step("configuration"));
    }
    // SAFETY: ShellExecuteExW succeeded with SEE_MASK_NOCLOSEPROCESS and
    // transferred the non-null process handle to this sole owner.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| fail(9, "elevated_setup_timeout").at_step("configuration"))?;
    let wait_millis = remaining
        .as_millis()
        .saturating_add(1)
        .min(u32::MAX as u128) as u32;
    match unsafe { WaitForSingleObject(process.as_raw_handle(), wait_millis) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            return Err(fail(9, "elevated_setup_timeout").at_step("configuration"));
        }
        _ => {
            return Err(fail(6, "elevation_failed")
                .with_detail(std::io::Error::last_os_error())
                .at_step("configuration"));
        }
    }
    let mut exit_code = 1;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit_code) } == 0 {
        return Err(fail(6, "elevation_failed")
            .with_detail(std::io::Error::last_os_error())
            .at_step("configuration"));
    }
    Ok(u8::try_from(exit_code).unwrap_or(1))
}

#[cfg(windows)]
pub(super) fn windows_quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.into();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            if character == '"' {
                quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}
