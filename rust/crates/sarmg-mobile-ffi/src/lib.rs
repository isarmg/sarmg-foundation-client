#![allow(unsafe_code)]
//! One current length-delimited ABI. No thread-local errors or NUL-string reader.

#[cfg(panic = "abort")]
compile_error!("sarmg-mobile-ffi requires panic=unwind so panics cannot terminate the host");

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Mutex, Once},
};

#[cfg(feature = "jni")]
pub mod jni;

pub const ABI_REVISION: u32 = 2;
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HANDLES: usize = 4096;
pub const SARMG_FFI_OK: i32 = 0;
pub const SARMG_FFI_INVALID_ARGUMENT: i32 = 1;
pub const SARMG_FFI_INVALID_HANDLE: i32 = 2;
pub const SARMG_FFI_INTERNAL_ERROR: i32 = 3;
pub const SARMG_FFI_RESOURCE_EXHAUSTED: i32 = 4;
pub const SARMG_FFI_INTERNAL_PANIC: i32 = 255;

/// A serializer sink that refuses growth beyond the shared result budget.
#[derive(Default)]
pub struct OutputBuffer(Vec<u8>);
impl OutputBuffer {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
impl std::io::Write for OutputBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_OUTPUT_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("FFI output budget exceeded"));
        }
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| std::io::Error::other("FFI allocation refused"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Owned result bytes: success data, or a redacted UTF-8 error when status != 0.
/// The host must not change this pair; release the whole result exactly once.
#[repr(C)]
pub struct SarmgFfiBytesV2 {
    pub data: *mut u8,
    pub length: usize,
}
impl Default for SarmgFfiBytesV2 {
    fn default() -> Self {
        Self {
            data: std::ptr::null_mut(),
            length: 0,
        }
    }
}

#[repr(C)]
pub struct SarmgFfiResultV2 {
    pub abi_revision: u32,
    pub status: i32,
    pub value: u64,
    pub bytes: SarmgFfiBytesV2,
}
impl Default for SarmgFfiResultV2 {
    fn default() -> Self {
        Self {
            abi_revision: ABI_REVISION,
            status: SARMG_FFI_OK,
            value: 0,
            bytes: SarmgFfiBytesV2::default(),
        }
    }
}

#[derive(Default)]
pub struct Payload {
    pub value: u64,
    pub bytes: Vec<u8>,
}
impl Payload {
    pub fn value(value: u64) -> Self {
        Self {
            value,
            bytes: Vec::new(),
        }
    }
    pub fn bytes(bytes: Vec<u8>) -> Result<Self, FfiError> {
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err(FfiError::resource_exhausted());
        }
        Ok(Self { value: 0, bytes })
    }
}

#[derive(Debug)]
pub struct FfiError {
    status: i32,
    public_message: &'static str,
}
impl FfiError {
    pub const fn status(&self) -> i32 {
        self.status
    }
    pub const fn public_message(&self) -> &'static str {
        self.public_message
    }
    pub const fn invalid_argument() -> Self {
        Self {
            status: SARMG_FFI_INVALID_ARGUMENT,
            public_message: "invalid argument",
        }
    }
    pub const fn invalid_handle() -> Self {
        Self {
            status: SARMG_FFI_INVALID_HANDLE,
            public_message: "invalid handle",
        }
    }
    pub const fn internal() -> Self {
        Self {
            status: SARMG_FFI_INTERNAL_ERROR,
            public_message: "operation failed",
        }
    }
    pub const fn resource_exhausted() -> Self {
        Self {
            status: SARMG_FFI_RESOURCE_EXHAUSTED,
            public_message: "resource limit reached",
        }
    }
}

thread_local! { static FFI_DEPTH: Cell<usize> = const { Cell::new(0) }; }
static PANIC_HOOK: Once = Once::new();

struct PanicScope;
impl Drop for PanicScope {
    fn drop(&mut self) {
        FFI_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Catches operation panics and suppresses their payload in the process hook.
/// The previously installed hook still handles panics outside FFI boundaries.
/// Hosts must not replace this hook after initializing the native library.
pub fn boundary<T>(operation: impl FnOnce() -> Result<T, FfiError>) -> Result<T, FfiError> {
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if FFI_DEPTH
                .try_with(|depth| depth.get() == 0)
                .unwrap_or(false)
            {
                previous(info);
            }
        }));
    });
    FFI_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
    let _scope = PanicScope;
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(FfiError {
            status: SARMG_FFI_INTERNAL_PANIC,
            public_message: "internal panic",
        }),
    }
}

fn owned_bytes(bytes: Vec<u8>) -> SarmgFfiBytesV2 {
    if bytes.is_empty() {
        return SarmgFfiBytesV2::default();
    }
    let bytes = bytes.into_boxed_slice();
    let length = bytes.len();
    SarmgFfiBytesV2 {
        data: Box::into_raw(bytes).cast(),
        length,
    }
}

/// # Safety
/// Output must point to aligned writable storage for one result, not alias any
/// input, and contain no unreleased result. Null/misaligned pointers are rejected.
/// Other invalid pointers cannot be made safe by an FFI boundary.
pub unsafe fn guard(
    output: *mut SarmgFfiResultV2,
    operation: impl FnOnce() -> Result<Payload, FfiError>,
) -> i32 {
    if output.is_null() || !output.is_aligned() {
        return SARMG_FFI_INVALID_ARGUMENT;
    }
    let result = boundary(|| {
        let payload = operation()?;
        if payload.bytes.len() > MAX_OUTPUT_BYTES {
            return Err(FfiError::resource_exhausted());
        }
        Ok(payload)
    });
    let (status, payload) = match result {
        Ok(payload) => (SARMG_FFI_OK, payload),
        Err(error) => (
            error.status,
            Payload {
                value: 0,
                bytes: error.public_message.as_bytes().to_vec(),
            },
        ),
    };
    unsafe {
        output.write(SarmgFfiResultV2 {
            abi_revision: ABI_REVISION,
            status,
            value: payload.value,
            bytes: owned_bytes(payload.bytes),
        });
    }
    status
}

/// Frees and resets a result; freeing the same reset storage is idempotent.
/// # Safety
/// Output must be null or aligned writable storage containing an unmodified
/// result from guard, or a default empty result. Copies must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sarmg_ffi_result_free_v2(output: *mut SarmgFfiResultV2) -> i32 {
    match boundary(|| {
        if output.is_null() || !output.is_aligned() {
            return Err(FfiError::invalid_argument());
        }
        let result = unsafe { &mut *output };
        if result.abi_revision != ABI_REVISION
            || result.bytes.length > MAX_OUTPUT_BYTES
            || result.bytes.data.is_null() && result.bytes.length != 0
        {
            return Err(FfiError::invalid_argument());
        }
        let previous = std::mem::take(result);
        if !previous.bytes.data.is_null() {
            let slice =
                std::ptr::slice_from_raw_parts_mut(previous.bytes.data, previous.bytes.length);
            drop(unsafe { Box::from_raw(slice) });
        }
        Ok(())
    }) {
        Ok(()) => SARMG_FFI_OK,
        Err(error) => error.status,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    pub slot: u32,
    pub generation: u32,
}
impl Handle {
    pub const fn to_u64(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }

    pub const fn from_u64(value: u64) -> Self {
        Self {
            slot: value as u32,
            generation: (value >> 32) as u32,
        }
    }
}
struct Slot<T> {
    generation: u32,
    value: Option<T>,
}
pub struct HandleRegistry<T> {
    slots: Mutex<Vec<Slot<T>>>,
}
impl<T> Default for HandleRegistry<T> {
    fn default() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
        }
    }
}
impl<T> HandleRegistry<T> {
    pub fn insert(&self, value: T) -> Result<Handle, FfiError> {
        let mut slots = self.slots.lock().map_err(|_| FfiError::internal())?;
        if let Some((index, slot)) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.value.is_none() && s.generation < u32::MAX)
        {
            slot.generation += 1;
            slot.value = Some(value);
            return Ok(Handle {
                slot: index as u32,
                generation: slot.generation,
            });
        }
        if slots.len() >= MAX_HANDLES {
            return Err(FfiError::resource_exhausted());
        }
        let index = u32::try_from(slots.len()).map_err(|_| FfiError::resource_exhausted())?;
        slots
            .try_reserve(1)
            .map_err(|_| FfiError::resource_exhausted())?;
        slots.push(Slot {
            generation: 1,
            value: Some(value),
        });
        Ok(Handle {
            slot: index,
            generation: 1,
        })
    }
    pub fn with<R>(&self, handle: Handle, operation: impl FnOnce(&T) -> R) -> Result<R, FfiError> {
        let slots = self.slots.lock().map_err(|_| FfiError::internal())?;
        let slot = slots
            .get(handle.slot as usize)
            .filter(|s| s.generation == handle.generation)
            .and_then(|s| s.value.as_ref())
            .ok_or_else(FfiError::invalid_handle)?;
        Ok(operation(slot))
    }
    pub fn remove(&self, handle: Handle) -> Result<T, FfiError> {
        let mut slots = self.slots.lock().map_err(|_| FfiError::internal())?;
        let slot = slots
            .get_mut(handle.slot as usize)
            .filter(|s| s.generation == handle.generation)
            .ok_or_else(FfiError::invalid_handle)?;
        slot.value.take().ok_or_else(FfiError::invalid_handle)
    }
}

impl<T: Clone> HandleRegistry<T> {
    /// Clones a registered value so callers do not hold the registry lock while
    /// performing product work.
    pub fn get(&self, handle: Handle) -> Result<T, FfiError> {
        self.with(handle, Clone::clone)
    }
}

/// # Safety
/// Nonempty input must address length initialized readable bytes in one allocation,
/// alive and unchanged throughout the borrow. Null with zero length is empty.
pub unsafe fn checked_input<'a>(
    pointer: *const u8,
    length: usize,
    max_length: usize,
) -> Result<&'a [u8], FfiError> {
    if length > max_length.min(MAX_INPUT_BYTES)
        || length > isize::MAX as usize
        || pointer.is_null() && length != 0
    {
        return Err(FfiError::invalid_argument());
    }
    if length == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}
/// # Safety
/// The same memory requirements as checked_input apply.
pub unsafe fn checked_utf8<'a>(
    pointer: *const u8,
    length: usize,
    max_length: usize,
) -> Result<&'a str, FfiError> {
    std::str::from_utf8(unsafe { checked_input(pointer, length, max_length) }?)
        .map_err(|_| FfiError::invalid_argument())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_ffi_contract_matches_mobile_profile() {
        let source = include_str!("../../../../profiles/mobile-agent.toml");
        let mut in_ffi = false;
        let mut values = std::collections::BTreeMap::new();
        for line in source.lines().map(str::trim) {
            if line.starts_with('[') {
                in_ffi = line == "[policy.ffi]";
            } else if in_ffi && let Some((name, value)) = line.split_once('=') {
                values.insert(name.trim(), value.trim().parse::<usize>().unwrap());
            }
        }
        assert_eq!(
            values,
            std::collections::BTreeMap::from([
                ("abi_revision", ABI_REVISION as usize),
                ("max_input_bytes", MAX_INPUT_BYTES),
                ("max_output_bytes", MAX_OUTPUT_BYTES),
                ("max_handles", MAX_HANDLES),
            ])
        );
    }

    #[test]
    fn output_budget_is_enforced_before_growth() {
        use std::io::Write;
        let mut output = OutputBuffer::default();
        output.write_all(&vec![7; MAX_OUTPUT_BYTES]).unwrap();
        assert!(output.write_all(&[1]).is_err());
        assert_eq!(output.into_bytes().len(), MAX_OUTPUT_BYTES);
    }

    #[test]
    #[ignore = "invoked by panic_payload_is_not_logged_by_the_host_process"]
    fn panic_process_child() {
        let error = boundary(|| -> Result<(), FfiError> { panic!("ffi-secret-must-not-escape") })
            .unwrap_err();
        assert_eq!(error.status, SARMG_FFI_INTERNAL_PANIC);
        assert_eq!(error.public_message, "internal panic");
    }

    #[test]
    fn panic_payload_is_not_logged_by_the_host_process() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::panic_process_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("ffi-secret-must-not-escape"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("ffi-secret-must-not-escape"));
    }

    #[test]
    fn guards_have_explicit_status_and_owned_length_delimited_results() {
        let mut out = SarmgFfiResultV2::default();
        assert_eq!(
            unsafe { guard(&mut out, || Payload::bytes(vec![0, 255, 0])) },
            SARMG_FFI_OK
        );
        assert_eq!(
            unsafe { checked_input(out.bytes.data, out.bytes.length, 3) }.unwrap(),
            &[0, 255, 0]
        );
        assert_eq!(unsafe { sarmg_ffi_result_free_v2(&mut out) }, SARMG_FFI_OK);
        assert!(out.bytes.data.is_null());
        assert_eq!(unsafe { sarmg_ffi_result_free_v2(&mut out) }, SARMG_FFI_OK);
        assert_eq!(
            unsafe { guard(&mut out, || panic!("private credential")) },
            SARMG_FFI_INTERNAL_PANIC
        );
        assert_eq!(
            unsafe { checked_utf8(out.bytes.data, out.bytes.length, 100) }.unwrap(),
            "internal panic"
        );
        unsafe {
            sarmg_ffi_result_free_v2(&mut out);
        }
    }
    #[test]
    fn rejected_output_never_runs_product_work_and_input_is_bounded() {
        assert_eq!(
            unsafe { guard(std::ptr::null_mut(), || panic!("must not execute")) },
            SARMG_FFI_INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe {
                guard(std::ptr::dangling_mut::<u8>().cast(), || {
                    panic!("must not execute")
                })
            },
            SARMG_FFI_INVALID_ARGUMENT
        );
        unsafe {
            assert!(checked_input(std::ptr::null(), 1, 10).is_err());
            assert_eq!(checked_input(std::ptr::null(), 0, 10).unwrap(), &[]);
            assert!(checked_input(std::ptr::null(), usize::MAX, usize::MAX).is_err());
            assert!(checked_input(std::ptr::dangling(), MAX_INPUT_BYTES + 1, usize::MAX).is_err());
            assert!(checked_utf8([255].as_ptr(), 1, 1).is_err());
            assert_eq!(checked_utf8(b"abc".as_ptr(), 3, 3).unwrap(), "abc");
        }
    }
    #[test]
    fn stale_handles_and_exhausted_generations_never_alias() {
        let registry = HandleRegistry::default();
        let first = registry.insert("old").unwrap();
        registry.remove(first).unwrap();
        let second = registry.insert("new").unwrap();
        assert_ne!(first, second);
        assert!(registry.get(first).is_err());
        registry.slots.lock().unwrap()[second.slot as usize].generation = u32::MAX;
        registry
            .remove(Handle {
                slot: second.slot,
                generation: u32::MAX,
            })
            .unwrap();
        assert_ne!(registry.insert("fresh").unwrap().slot, second.slot);
        assert!(registry.remove(first).is_err());
    }
    #[test]
    fn registry_is_bounded_and_poison_fails_closed() {
        let registry = HandleRegistry::default();
        for _ in 0..MAX_HANDLES {
            registry.insert(()).unwrap();
        }
        assert_eq!(
            registry.insert(()).unwrap_err().status,
            SARMG_FFI_RESOURCE_EXHAUSTED
        );
        let registry = HandleRegistry::default();
        let handle = registry.insert(1).unwrap();
        assert!(
            boundary(|| {
                registry.with(handle, |_| panic!("private value"))?;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(
            registry.get(handle).unwrap_err().status,
            SARMG_FFI_INTERNAL_ERROR
        );
    }
}
