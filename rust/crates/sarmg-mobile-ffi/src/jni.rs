//! JNI exception and bounded Unicode handling; no product wire knowledge.
use crate::{FfiError, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, boundary};
use ::jni::{
    JNIEnv,
    objects::{JCharArray, JString},
    sys::jstring,
};

pub fn guard<'local, T>(
    env: &mut JNIEnv<'local>,
    error_return: T,
    operation: impl FnOnce(&mut JNIEnv<'local>) -> Result<T, FfiError>,
) -> T {
    match boundary(|| {
        if env.exception_check().map_err(|_| FfiError::internal())? {
            return Err(FfiError::internal());
        }
        operation(env)
    }) {
        Ok(value) => value,
        Err(error) => {
            // Preserve any pending JVM exception, including allocation failures.
            let _ = boundary(|| {
                if !env.exception_check().map_err(|_| FfiError::internal())? {
                    env.throw_new(
                        exception_class(error.status),
                        format!("native status {}: {}", error.status, error.public_message),
                    )
                    .map_err(|_| FfiError::internal())?;
                }
                Ok(())
            });
            error_return
        }
    }
}

pub fn exception_class(status: i32) -> &'static str {
    match status {
        crate::SARMG_FFI_INVALID_ARGUMENT => "java/lang/IllegalArgumentException",
        crate::SARMG_FFI_INVALID_HANDLE => "java/lang/IllegalStateException",
        crate::SARMG_FFI_RESOURCE_EXHAUSTED => "java/lang/OutOfMemoryError",
        _ => "java/lang/RuntimeException",
    }
}

pub fn read_string(
    env: &mut JNIEnv<'_>,
    value: JString<'_>,
    max_bytes: usize,
) -> Result<String, FfiError> {
    if value.is_null() {
        return Err(FfiError::invalid_argument());
    }
    let units = env
        .call_method(&value, "length", "()I", &[])
        .and_then(|v| v.i())
        .map_err(|_| FfiError::invalid_argument())?;
    let units = usize::try_from(units).map_err(|_| FfiError::invalid_argument())?;
    let limit = max_bytes.min(MAX_INPUT_BYTES);
    if units > limit {
        return Err(FfiError::invalid_argument());
    }
    let array = env
        .call_method(&value, "toCharArray", "()[C", &[])
        .and_then(|v| v.l())
        .map_err(|_| FfiError::internal())?;
    let array = JCharArray::from(array);
    let mut utf16 = vec![0; units];
    env.get_char_array_region(&array, 0, &mut utf16)
        .map_err(|_| FfiError::internal())?;
    // Reject unpaired surrogates; do not silently replace malformed host text.
    let text = String::from_utf16(&utf16).map_err(|_| FfiError::invalid_argument())?;
    if text.len() > limit {
        return Err(FfiError::invalid_argument());
    }
    Ok(text)
}

pub fn new_string(env: &mut JNIEnv<'_>, text: String) -> Result<jstring, FfiError> {
    if text.len() > MAX_OUTPUT_BYTES {
        return Err(FfiError::resource_exhausted());
    }
    env.new_string(text)
        .map(|value| value.into_raw())
        .map_err(|_| FfiError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_classes_are_explicit_and_panic_is_not_a_success_value() {
        assert_eq!(
            exception_class(crate::SARMG_FFI_INVALID_ARGUMENT),
            "java/lang/IllegalArgumentException"
        );
        assert_eq!(
            exception_class(crate::SARMG_FFI_INVALID_HANDLE),
            "java/lang/IllegalStateException"
        );
        assert_eq!(
            exception_class(crate::SARMG_FFI_INTERNAL_PANIC),
            "java/lang/RuntimeException"
        );
    }
}
