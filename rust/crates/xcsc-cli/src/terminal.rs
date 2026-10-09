//! Bounded controlling-terminal input with mode and signal restoration.

use crate::{Result, fail};
#[cfg(unix)]
use std::io::{IsTerminal, Write};
use std::{sync::Mutex, time::Instant};
#[cfg(unix)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

static INTERACTIVE_PROMPT: Mutex<()> = Mutex::new(());

/// Read visible text directly from the process' controlling terminal.
///
/// `deadline` is absolute so time spent in earlier command phases is not
/// silently granted again. The read stops as soon as `max_bytes` is exceeded.
pub fn prompt_text(label: &str, max_bytes: usize, deadline: Instant) -> Result<String> {
    read_terminal(label, false, max_bytes, deadline).map(|value| value.to_string())
}

/// Read a secret directly from the controlling terminal without echoing it.
/// The allocation is erased when the returned value is dropped.
pub fn prompt_secret(
    label: &str,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    read_terminal(label, true, max_bytes, deadline)
}

fn read_terminal(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    if max_bytes == 0 {
        return Err(fail(2, "input_too_large"));
    }
    let _prompt = INTERACTIVE_PROMPT
        .lock()
        .map_err(|_| fail(8, "interactive_terminal_unavailable"))?;
    #[cfg(unix)]
    return unix_terminal_input(label, secret, max_bytes, deadline);
    #[cfg(windows)]
    return windows_terminal_input(label, secret, max_bytes, deadline);
}

#[cfg(unix)]
static TERMINAL_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn terminal_signal_handler(signal: libc::c_int) {
    TERMINAL_SIGNAL.store(signal, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
struct TerminalSignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
impl TerminalSignalGuard {
    fn install() -> Result<Self> {
        TERMINAL_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut guard = Self { previous: vec![] };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: the libc C structs permit all-zero initial values. The
            // handler only updates a lock-free atomic; libc's sigaction ABI is
            // needed on both Linux and Darwin (kernel_sigaction is not a
            // portable replacement). Live output storage captures restoration
            // state before the next installation; Drop restores in reverse.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = terminal_signal_handler as *const () as usize;
            action.sa_flags = 0;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(fail(2, "terminal_mode_unavailable")
                    .with_detail(std::io::Error::last_os_error()));
            }
            guard.previous.push((signal, previous));
        }
        Ok(guard)
    }
}

#[cfg(unix)]
impl Drop for TerminalSignalGuard {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().rev() {
            // SAFETY: previous is the exact initialized action returned by a
            // successful installation. The caller serializes interactive
            // prompts; this guard still owns each installed disposition.
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
        TERMINAL_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(unix)]
struct UnixTerminalMode<'fd> {
    fd: std::os::fd::BorrowedFd<'fd>,
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl Drop for UnixTerminalMode<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.fd,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

#[cfg(unix)]
fn unix_terminal_input(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    use std::{
        fs::OpenOptions,
        os::{fd::AsFd, unix::fs::OpenOptionsExt},
    };

    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/tty")
        .map_err(|error| fail(2, "interactive_terminal_required").with_detail(error))?;
    if !terminal.is_terminal() {
        return Err(fail(2, "interactive_terminal_required"));
    }
    let fd = terminal.as_fd();
    let original = rustix::termios::tcgetattr(fd)
        .map_err(|error| fail(2, "terminal_mode_unavailable").with_detail(error))?;
    let mut protected = original.clone();
    protected.local_modes.remove(
        rustix::termios::LocalModes::ECHO
            | rustix::termios::LocalModes::ICANON
            | rustix::termios::LocalModes::ISIG,
    );
    // Readiness owns the absolute deadline. One byte avoids Darwin VMIN=0
    // readiness semantics while retaining the same input and restoration rules.
    protected.special_codes[rustix::termios::SpecialCodeIndex::VMIN] = 1;
    protected.special_codes[rustix::termios::SpecialCodeIndex::VTIME] = 0;
    let _signals = TerminalSignalGuard::install()?;
    rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Flush, &protected)
        .map_err(|error| fail(2, "terminal_mode_unavailable").with_detail(error))?;
    let mode = UnixTerminalMode { fd, original };
    let mut writer = &terminal;
    let suffix = if secret {
        " (input hidden; type or paste, then press Enter): "
    } else {
        ": "
    };
    writer
        .write_all(format!("{label}{suffix}").as_bytes())
        .and_then(|_| writer.flush())
        .map_err(|error| fail(2, "interactive_terminal_unavailable").with_detail(error))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(max_bytes.min(4096)));
    let result = 'input: loop {
        if TERMINAL_SIGNAL.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            break Err(fail(130, "interactive_input_cancelled"));
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break Err(fail(9, "interactive_input_timeout"));
        };
        if remaining.is_zero() {
            break Err(fail(9, "interactive_input_timeout"));
        }
        let mut readable = [rustix::event::PollFd::new(
            &terminal,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        match rustix::event::poll(&mut readable, Some(&timeout)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => break Err(fail(2, "interactive_terminal_unavailable").with_detail(error)),
        }
        let mut chunk = Zeroizing::new([0_u8; 256]);
        let count = match rustix::io::read(&terminal, &mut chunk[..]) {
            Ok(0) => break Err(fail(2, "interactive_input_cancelled")),
            Ok(count) => count,
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {
                continue;
            }
            Err(error) => break Err(fail(2, "interactive_terminal_unavailable").with_detail(error)),
        };
        for byte in &chunk[..count] {
            match *byte {
                b'\r' | b'\n' => {
                    let value = std::mem::take(&mut *bytes);
                    match String::from_utf8(value) {
                        Ok(value) => break 'input Ok(Zeroizing::new(value)),
                        Err(error) => {
                            let mut invalid = error.into_bytes();
                            invalid.zeroize();
                            break 'input Err(fail(2, "invalid_input"));
                        }
                    }
                }
                3 => break 'input Err(fail(130, "interactive_input_cancelled")),
                8 | 127 => {
                    if let Some(removed) = bytes.pop() {
                        if removed & 0b1100_0000 == 0b1000_0000 {
                            while bytes
                                .last()
                                .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
                            {
                                bytes.pop();
                            }
                            bytes.pop();
                        }
                        if !secret {
                            let _ = writer.write_all(b"\x08 \x08");
                            let _ = writer.flush();
                        }
                    }
                }
                byte if byte < 0x20 => {}
                byte => {
                    bytes.push(byte);
                    if bytes.len() > max_bytes {
                        let _ =
                            rustix::termios::tcflush(fd, rustix::termios::QueueSelector::IFlush);
                        break 'input Err(fail(2, "input_too_large"));
                    }
                    if !secret {
                        let _ = writer.write_all(&[byte]);
                        let _ = writer.flush();
                    }
                }
            }
        }
    };
    drop(mode);
    let _ = writer.write_all(b"\r\n");
    let _ = writer.flush();
    result
}

#[cfg(windows)]
fn windows_terminal_input(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    use std::{
        ffi::OsStr,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };
    use windows_sys::Win32::{
        Foundation::{
            GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::{
            Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                FlushConsoleInputBuffer, GetConsoleMode, INPUT_RECORD, KEY_EVENT,
                ReadConsoleInputW, SetConsoleMode, WriteConsoleW,
            },
            Threading::WaitForSingleObject,
        },
    };

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().collect()
    }
    fn open_console(name: &str, access: u32) -> Result<OwnedHandle> {
        let name: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(fail(2, "interactive_terminal_required")
                .with_detail(std::io::Error::last_os_error()))
        } else {
            // SAFETY: successful CreateFileW transferred this unique handle.
            // OwnedHandle closes it once after the console mode guard is dropped.
            Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
        }
    }
    fn write_console(handle: windows_sys::Win32::Foundation::HANDLE, units: &[u16]) -> Result<()> {
        let mut written = 0;
        if unsafe {
            WriteConsoleW(
                handle,
                units.as_ptr().cast(),
                units.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || written != units.len() as u32
        {
            return Err(fail(2, "interactive_terminal_unavailable")
                .with_detail(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    struct WindowsConsoleMode {
        handle: windows_sys::Win32::Foundation::HANDLE,
        original: u32,
    }
    impl Drop for WindowsConsoleMode {
        fn drop(&mut self) {
            unsafe { SetConsoleMode(self.handle, self.original) };
        }
    }

    let input = open_console("CONIN$", GENERIC_READ | GENERIC_WRITE)?;
    let output = open_console("CONOUT$", GENERIC_READ | GENERIC_WRITE)?;
    let mut original = 0;
    if unsafe { GetConsoleMode(input.as_raw_handle(), &mut original) } == 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let protected = original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    if unsafe { SetConsoleMode(input.as_raw_handle(), protected) } == 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let mode = WindowsConsoleMode {
        handle: input.as_raw_handle(),
        original,
    };
    let suffix = if secret {
        " (input hidden; type or paste, then press Enter): "
    } else {
        ": "
    };
    write_console(output.as_raw_handle(), &wide(&format!("{label}{suffix}")))?;
    let mut units = Zeroizing::new(Vec::<u16>::with_capacity(max_bytes.min(4096)));
    let mut utf8_bytes = 0_usize;
    let result = 'input: loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break Err(fail(9, "interactive_input_timeout"));
        };
        if remaining.is_zero() {
            break Err(fail(9, "interactive_input_timeout"));
        }
        let millis = remaining.as_millis().clamp(1, u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(input.as_raw_handle(), millis) } {
            WAIT_TIMEOUT => break Err(fail(9, "interactive_input_timeout")),
            WAIT_OBJECT_0 => {}
            _ => {
                break Err(fail(2, "interactive_terminal_unavailable")
                    .with_detail(std::io::Error::last_os_error()));
            }
        }
        let mut record = INPUT_RECORD::default();
        let mut read = 0;
        if unsafe { ReadConsoleInputW(input.as_raw_handle(), &mut record, 1, &mut read) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(995) {
                break Err(fail(130, "interactive_input_cancelled"));
            }
            break Err(fail(2, "interactive_terminal_unavailable").with_detail(error));
        }
        if read == 0 {
            break Err(fail(2, "interactive_input_cancelled"));
        }
        if record.EventType != KEY_EVENT as u16 {
            continue;
        }
        let key = unsafe { record.Event.KeyEvent };
        if key.bKeyDown == 0 {
            continue;
        }
        let unit = unsafe { key.uChar.UnicodeChar };
        if unit == 0 {
            continue;
        }
        for _ in 0..key.wRepeatCount.max(1) {
            match unit {
                10 => {}
                13 => match String::from_utf16(&units) {
                    Ok(value) => break 'input Ok(Zeroizing::new(value)),
                    Err(_) => break 'input Err(fail(2, "invalid_input")),
                },
                3 => break 'input Err(fail(130, "interactive_input_cancelled")),
                8 | 127 => {
                    if let Some(removed) = units.pop() {
                        if (0xDC00..=0xDFFF).contains(&removed)
                            && units
                                .last()
                                .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit))
                        {
                            units.pop();
                            utf8_bytes = utf8_bytes.saturating_sub(4);
                        } else if !(0xD800..=0xDBFF).contains(&removed) {
                            utf8_bytes = utf8_bytes.saturating_sub(
                                char::from_u32(removed as u32)
                                    .map(char::len_utf8)
                                    .unwrap_or(0),
                            );
                        }
                        if !secret {
                            let _ = write_console(output.as_raw_handle(), &[8, 32, 8]);
                        }
                    }
                }
                unit if unit < 0x20 => {}
                unit => {
                    let previous_high_surrogate = units
                        .last()
                        .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit));
                    let encoded_bytes = if (0xD800..=0xDBFF).contains(&unit) {
                        if previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        0
                    } else if (0xDC00..=0xDFFF).contains(&unit) {
                        if !previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        4
                    } else {
                        if previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        char::from_u32(unit as u32)
                            .map(char::len_utf8)
                            .ok_or_else(|| fail(2, "invalid_input"))?
                    };
                    units.push(unit);
                    utf8_bytes = utf8_bytes.saturating_add(encoded_bytes);
                    if utf8_bytes > max_bytes {
                        unsafe { FlushConsoleInputBuffer(input.as_raw_handle()) };
                        break 'input Err(fail(2, "input_too_large"));
                    }
                    if !secret && encoded_bytes != 0 {
                        let start = if (0xDC00..=0xDFFF).contains(&unit) {
                            units.len() - 2
                        } else {
                            units.len() - 1
                        };
                        let _ = write_console(output.as_raw_handle(), &units[start..]);
                    }
                }
            }
        }
    };
    drop(mode);
    let _ = write_console(output.as_raw_handle(), &[13, 10]);
    result
}
