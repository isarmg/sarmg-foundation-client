//! Bounded physical line selection. Typed parsing remains with the caller.
use std::{
    fmt,
    io::{self, Read, Seek, SeekFrom},
};

const MAX_TAIL_BYTES: usize = 64 * 1024 * 1024;

pub enum TailReadError {
    InvalidLimits,
    LineTooLarge,
    TruncatedLine,
    SourceChanged,
    Io(io::Error),
}
impl fmt::Debug for TailReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TailReadError({self})")
    }
}
impl fmt::Display for TailReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "Tail read limits are invalid.",
            Self::LineTooLarge => "A retained line exceeds the declared byte limit.",
            Self::TruncatedLine => {
                "The suffix cannot contain a complete line within its byte limit."
            }
            Self::SourceChanged => "The source was truncated during the bounded read.",
            Self::Io(_) => "The bounded source could not be read.",
        })
    }
}
impl std::error::Error for TailReadError {}
impl From<io::Error> for TailReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Read at most `max_bytes` of the existing suffix from an already-authorized
/// seekable source. Limits are capped at 64 MiB; the reader position changes.
/// Only an initial line cut by the suffix boundary is skipped. An incomplete
/// final line stays in the result, so the typed parser can reject it. A source
/// append does not invalidate captured bytes; truncation fails explicitly.
pub fn read_tail_lines<R: Read + Seek>(
    reader: &mut R,
    max_bytes: usize,
    max_line_bytes: usize,
) -> Result<Vec<u8>, TailReadError> {
    if max_bytes == 0
        || max_bytes > MAX_TAIL_BYTES
        || max_line_bytes == 0
        || max_line_bytes > max_bytes
    {
        return Err(TailReadError::InvalidLimits);
    }
    let length = reader.seek(SeekFrom::End(0))?;
    let start = length.saturating_sub(max_bytes as u64);
    let read_start = start.saturating_sub(1);
    reader.seek(SeekFrom::Start(read_start))?;
    // One extra byte establishes whether the suffix starts at a line boundary.
    let expected =
        usize::try_from(length - read_start).map_err(|_| TailReadError::InvalidLimits)?;
    let mut bytes = Vec::with_capacity(expected);
    (&mut *reader)
        .take(expected as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected || reader.seek(SeekFrom::End(0))? < length {
        return Err(TailReadError::SourceChanged);
    }
    if start > 0 {
        let at_boundary = bytes[0] == b'\n';
        bytes.remove(0);
        if !at_boundary {
            let newline = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or(TailReadError::TruncatedLine)?;
            if newline + 1 > max_line_bytes {
                return Err(TailReadError::LineTooLarge);
            }
            bytes.drain(..=newline);
        }
    }
    if bytes
        .split_inclusive(|byte| *byte == b'\n')
        .any(|line| line.len() > max_line_bytes)
    {
        return Err(TailReadError::LineTooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn suffix_boundaries_skip_only_a_cut_first_line_and_preserve_partial_last_line() {
        let bytes = b"first\nsecond\nlast";
        assert_eq!(
            read_tail_lines(&mut Cursor::new(bytes), 11, 11).unwrap(),
            b"second\nlast"
        );
        assert_eq!(
            read_tail_lines(&mut Cursor::new(bytes), 10, 10).unwrap(),
            b"last"
        );
        assert_eq!(
            read_tail_lines(&mut Cursor::new(bytes), 30, 30).unwrap(),
            bytes
        );
        assert!(
            read_tail_lines(&mut Cursor::new(b""), 10, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            read_tail_lines(&mut Cursor::new(b"a\nb\n"), 2, 2).unwrap(),
            b"b\n"
        );
    }

    #[test]
    fn impossible_tail_and_oversized_retained_lines_fail_without_partial_output() {
        assert!(matches!(
            read_tail_lines(&mut Cursor::new(b"sensitive-value"), 4, 4),
            Err(TailReadError::TruncatedLine)
        ));
        assert!(matches!(
            read_tail_lines(&mut Cursor::new(b"long-line\n"), 20, 4),
            Err(TailReadError::LineTooLarge)
        ));
        assert!(matches!(
            read_tail_lines(&mut Cursor::new(b"x\nlong-line\n"), 10, 4),
            Err(TailReadError::LineTooLarge)
        ));
        for (bytes, line) in [(0, 1), (1, 0), (10, 11), (MAX_TAIL_BYTES + 1, 1)] {
            assert!(matches!(
                read_tail_lines(&mut Cursor::new(b""), bytes, line),
                Err(TailReadError::InvalidLimits)
            ));
        }
    }

    #[test]
    fn real_file_tail_reads_a_bounded_suffix_and_does_not_change_bytes() {
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Write;
        file.write_all(b"first\nsecond\nlast\n").unwrap();
        assert_eq!(read_tail_lines(&mut file, 5, 5).unwrap(), b"last\n");
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first\nsecond\nlast\n");
    }

    struct Changing {
        inner: Cursor<Vec<u8>>,
        truncate: bool,
        append: bool,
    }
    impl Seek for Changing {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }
    impl Read for Changing {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let result = self.inner.read(buffer)?;
            if self.truncate {
                self.inner.get_mut().clear();
            }
            if self.append {
                self.inner.get_mut().extend_from_slice(b"later\n");
            }
            self.truncate = false;
            self.append = false;
            Ok(result)
        }
    }
    #[test]
    fn captured_prefix_allows_append_but_rejects_truncation_and_masks_io_text() {
        let mut truncated = Changing {
            inner: Cursor::new(b"one\n".to_vec()),
            truncate: true,
            append: false,
        };
        assert!(matches!(
            read_tail_lines(&mut truncated, 20, 20),
            Err(TailReadError::SourceChanged)
        ));
        let mut appended = Changing {
            inner: Cursor::new(b"one\n".to_vec()),
            truncate: false,
            append: true,
        };
        assert_eq!(read_tail_lines(&mut appended, 20, 20).unwrap(), b"one\n");
        let error = TailReadError::Io(io::Error::other("sensitive-value"));
        assert!(!error.to_string().contains("sensitive-value"));
        assert!(!format!("{error:?}").contains("sensitive-value"));
    }
}
