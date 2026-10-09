//! Secret values are redacted by default, are not serializable, and zeroize on drop.

use std::{fmt, io, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

pub struct SecretString(Zeroizing<String>);
impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Bounded serialization sink. The full budget is reserved before accepting
/// secrets, so growth never reallocates a populated secret buffer. Partial
/// output is zeroized on failure or drop; formatting never exposes it.
pub struct SecretWriter {
    bytes: SecretBytes,
    limit: usize,
}
impl SecretWriter {
    pub fn new(limit: usize) -> io::Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(limit).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "secret buffer allocation failed",
            )
        })?;
        Ok(Self {
            bytes: SecretBytes::new(bytes),
            limit,
        })
    }
    pub fn into_bytes(self) -> SecretBytes {
        self.bytes
    }
}
impl io::Write for SecretWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret output exceeds its byte budget",
            ));
        }
        self.bytes.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl fmt::Debug for SecretWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub struct SecretKey<const N: usize>([u8; N]);
impl<const N: usize> SecretKey<N> {
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}
impl<const N: usize> Drop for SecretKey<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub struct Redacted<T>(pub T);
impl<T> Redacted<T> {
    pub fn expose(&self) -> &T {
        &self.0
    }
    pub fn into_inner(self) -> T {
        self.0
    }
}
impl<T> Deref for Redacted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn serialization_sink_is_bounded_redacted_and_never_reallocates() {
        let mut writer = SecretWriter::new(6).unwrap();
        let pointer = writer.bytes.0.as_ptr();
        writer.write_all(b"nee").unwrap();
        writer.write_all(b"dle").unwrap();
        assert_eq!(writer.bytes.0.as_ptr(), pointer);
        assert_eq!(format!("{writer:?}"), "[REDACTED]");
        let error = writer.write_all(b"private overflow").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!error.to_string().contains("private overflow"));
        assert_eq!(writer.into_bytes().expose(), b"needle");
        let mut empty = SecretWriter::new(0).unwrap();
        empty.write_all(b"").unwrap();
        assert!(empty.write_all(b"x").is_err());
        assert!(SecretWriter::new(usize::MAX).is_err());
    }
    #[test]
    fn formatting_never_discloses_values() {
        let secret = SecretString::new("needle".into());
        assert_eq!(format!("{secret:?}/{secret}"), "[REDACTED]/[REDACTED]");
        assert!(!format!("{:?}", SecretBytes::new(b"needle".to_vec())).contains("needle"));
        assert_eq!(format!("{:?}", SecretKey::new([7_u8; 32])), "[REDACTED]");
    }
}
