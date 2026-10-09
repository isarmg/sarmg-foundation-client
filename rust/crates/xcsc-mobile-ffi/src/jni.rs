//! JNI exception and bounded Unicode handling; no product wire knowledge.
use crate::{FfiError, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, boundary};
use ::jni::{
    Env, EnvUnowned,
    errors::{ErrorPolicy, JniError},
    jni_sig, jni_str,
    objects::{JCharArray, JString},
    strings::JNIString,
    sys::jstring,
};

/// Borrow JNI APIs only inside the caller's valid native stack frame. Public
/// errors and panics use stable messages; an existing Java exception wins.
/// The FFI-safe native method argument is EnvUnowned, never an owned Env.
pub fn guard<'local, T: Default>(
    env: &mut EnvUnowned<'local>,
    error_return: T,
    operation: impl FnOnce(&mut Env<'local>) -> Result<T, FfiError>,
) -> T {
    let mut fallback = Some(error_return);
    let result = boundary(|| {
        let outcome = env.with_env(|env| {
            boundary(|| {
                if env.exception_check() {
                    return Err(FfiError::internal());
                }
                operation(env)
            })
        });
        Ok(outcome.resolve_with::<PublicErrorPolicy, _>(|| fallback.take()))
    });
    result.unwrap_or_else(|_| fallback.take().unwrap_or_default())
}

struct PublicErrorPolicy;
impl<T: Default> ErrorPolicy<T, FfiError> for PublicErrorPolicy {
    type Captures<'local: 'native_method, 'native_method> = Option<T>;

    fn on_error<'local: 'native_method, 'native_method>(
        env: &mut Env<'local>,
        fallback: &mut Option<T>,
        error: FfiError,
    ) -> ::jni::errors::Result<T> {
        if !env.exception_check() {
            // throw_new returning JavaException means the intended exception
            // is now pending. Never inspect or display an arbitrary JNI error.
            let _ = env.throw_new(
                JNIString::new(exception_class(error.status)),
                JNIString::new(format!(
                    "native status {}: {}",
                    error.status, error.public_message
                )),
            );
        }
        Ok(fallback.take().unwrap_or_default())
    }

    fn on_panic<'local: 'native_method, 'native_method>(
        env: &mut Env<'local>,
        fallback: &mut Option<T>,
        payload: Box<dyn std::any::Any + Send>,
    ) -> ::jni::errors::Result<T> {
        // This fallback also contains a payload whose Drop itself could panic.
        // It is never formatted or passed to the host.
        std::mem::forget(payload);
        Self::on_error(
            env,
            fallback,
            FfiError {
                status: crate::XCSC_FFI_INTERNAL_PANIC,
                public_message: "internal panic",
            },
        )
    }

    fn on_internal_jni_error<'local: 'native_method, 'native_method>(
        fallback: &mut Option<T>,
        _error: ::jni::errors::Error,
    ) -> T {
        fallback.take().unwrap_or_default()
    }

    fn on_internal_panic<'local: 'native_method, 'native_method>(
        fallback: &mut Option<T>,
        payload: Box<dyn std::any::Any + Send>,
    ) -> T {
        std::mem::forget(payload);
        fallback.take().unwrap_or_default()
    }
}

impl From<::jni::errors::Error> for FfiError {
    fn from(error: ::jni::errors::Error) -> Self {
        match error {
            ::jni::errors::Error::JniCall(JniError::NoMemory) => Self::resource_exhausted(),
            _ => Self::internal(),
        }
    }
}

pub fn exception_class(status: i32) -> &'static str {
    match status {
        crate::XCSC_FFI_INVALID_ARGUMENT => "java/lang/IllegalArgumentException",
        crate::XCSC_FFI_INVALID_HANDLE => "java/lang/IllegalStateException",
        crate::XCSC_FFI_RESOURCE_EXHAUSTED => "java/lang/OutOfMemoryError",
        _ => "java/lang/RuntimeException",
    }
}

pub fn read_string(
    env: &mut Env<'_>,
    value: JString<'_>,
    max_bytes: usize,
) -> Result<String, FfiError> {
    if value.is_null() {
        return Err(FfiError::invalid_argument());
    }
    let units = env
        .call_method(&value, jni_str!("length"), jni_sig!("()I"), &[])
        .and_then(|v| v.into_int())
        .map_err(|_| FfiError::invalid_argument())?;
    let units = usize::try_from(units).map_err(|_| FfiError::invalid_argument())?;
    let limit = max_bytes.min(MAX_INPUT_BYTES);
    if units > limit {
        return Err(FfiError::invalid_argument());
    }
    let array = env
        .call_method(&value, jni_str!("toCharArray"), jni_sig!("()[C"), &[])
        .and_then(|v| v.into_object())
        .map_err(FfiError::from)?;
    let array = JCharArray::cast_local(env, array).map_err(FfiError::from)?;
    let mut utf16 = vec![0; units];
    array
        .get_region(env, 0, &mut utf16)
        .map_err(FfiError::from)?;
    // Reject unpaired surrogates; do not silently replace malformed host text.
    let text = String::from_utf16(&utf16).map_err(|_| FfiError::invalid_argument())?;
    if text.len() > limit {
        return Err(FfiError::invalid_argument());
    }
    Ok(text)
}

pub fn new_string(env: &mut Env<'_>, text: String) -> Result<jstring, FfiError> {
    if text.len() > MAX_OUTPUT_BYTES {
        return Err(FfiError::resource_exhausted());
    }
    JString::from_str(env, text)
        .map(|value| value.into_raw())
        .map_err(FfiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_classes_are_explicit_and_panic_is_not_a_success_value() {
        assert_eq!(
            exception_class(crate::XCSC_FFI_INVALID_ARGUMENT),
            "java/lang/IllegalArgumentException"
        );
        assert_eq!(
            exception_class(crate::XCSC_FFI_INVALID_HANDLE),
            "java/lang/IllegalStateException"
        );
        assert_eq!(
            exception_class(crate::XCSC_FFI_INTERNAL_PANIC),
            "java/lang/RuntimeException"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_tests {
    use super::*;
    use ::jni::{
        JNIVersion, JValue,
        vm::{InitArgsBuilder, JavaVM},
    };

    #[test]
    #[ignore = "explicitly executed with the pinned real JVM by the native-jni CI job"]
    fn native_jvm_keeps_unicode_budgets_pending_exceptions_and_public_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let args = InitArgsBuilder::new()
            .version(JNIVersion::V1_8)
            .option("-Xcheck:jni")
            .build()?;
        let vm = JavaVM::new(args)?;
        vm.attach_current_thread(|env| -> ::jni::errors::Result<()> {
            // SAFETY: the VM attached this current thread and the assigned
            // lifetime is scoped to its live frame. All native calls complete
            // before that frame ends; this test never detaches or escapes it.
            let mut native = unsafe { EnvUnowned::from_raw(env.get_raw()) };
            let value = guard(&mut native, -1i32, |env| {
                let text = "camera-摄像头-😀\0";
                let string = JString::from_str(env, text).map_err(FfiError::from)?;
                assert_eq!(read_string(env, string, text.len())?, text);
                Ok(7)
            });
            assert_eq!(value, 7);
            assert!(!env.exception_check());

            assert_eq!(
                guard(&mut native, -1i32, |env| {
                    let string = JString::from_str(env, "éé").map_err(FfiError::from)?;
                    read_string(env, string, 3)?;
                    Ok(7)
                }),
                -1
            );
            let thrown = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            env.exception_clear();
            assert!(env.is_instance_of(&thrown, jni_str!("java/lang/IllegalArgumentException"))?);

            assert_eq!(
                guard(&mut native, -1i32, |env| {
                    let characters = JCharArray::new(env, 1).map_err(FfiError::from)?;
                    characters
                        .set_region(env, 0, &[0xd800])
                        .map_err(FfiError::from)?;
                    let string = env
                        .new_object(
                            jni_str!("java/lang/String"),
                            jni_sig!("([C)V"),
                            &[JValue::Object(&characters)],
                        )
                        .map_err(FfiError::from)?;
                    let string = JString::cast_local(env, string).map_err(FfiError::from)?;
                    read_string(env, string, 4)?;
                    Ok(7)
                }),
                -1
            );
            let thrown = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            env.exception_clear();
            assert!(env.is_instance_of(&thrown, jni_str!("java/lang/IllegalArgumentException"))?);

            let _ = env.throw_new(
                jni_str!("java/lang/IllegalStateException"),
                jni_str!("original Java failure"),
            );
            let before = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            assert_eq!(
                guard(&mut native, -9i32, |_| panic!(
                    "must not run with a pending exception"
                )),
                -9
            );
            let after = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            env.exception_clear();
            assert!(env.is_same_object(&before, &after)?);
            env.exception_clear();

            assert_eq!(
                guard(&mut native, -5i32, |_| Err(FfiError::invalid_handle())),
                -5
            );
            let thrown = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            env.exception_clear();
            assert!(env.is_instance_of(&thrown, jni_str!("java/lang/IllegalStateException"))?);
            assert_eq!(
                guard(&mut native, -6i32, |_| panic!(
                    "jni-private-value-must-not-escape"
                )),
                -6
            );
            let thrown = env
                .exception_occurred()
                .expect("a Java exception must be pending");
            env.exception_clear();
            assert!(env.is_instance_of(&thrown, jni_str!("java/lang/RuntimeException"))?);
            let message = env
                .call_method(
                    &thrown,
                    jni_str!("getMessage"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .into_object()?;
            let message = JString::cast_local(env, message)?;
            let text = read_string(env, message, 512).unwrap();
            assert_eq!(text, "native status 255: internal panic");
            assert!(!text.contains("jni-private-value"));
            assert_eq!(guard(&mut native, -1i32, |_| Ok(11)), 11);
            Ok(())
        })?;
        Ok(())
    }
}
