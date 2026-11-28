use std::{
    fs::{self, File, Metadata},
    io::{self, Read},
    path::Path,
};

/// Reads a regular file containing at most `max_bytes` bytes.
///
/// Symlinks to regular files are accepted. Directories, pipes, and devices are rejected before
/// opening them. On Unix, nonblocking opening also prevents a replacement FIFO from blocking.
/// The opened file is checked again, and reads are bounded even if it grows after the metadata
/// check. No allocation is based on the file's reported length.
///
/// # Errors
/// Returns an I/O error if the path cannot be read, is not a regular file, or exceeds the limit.
pub fn read_file_bounded(path: impl AsRef<Path>, max_bytes: usize) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    check_metadata(&fs::metadata(path)?, max_bytes)?;
    read_file_after_metadata(path, max_bytes)
}

fn read_file_after_metadata(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};

        File::from(open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?)
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    check_metadata(&file.metadata()?, max_bytes)?;
    read_bounded(file, max_bytes)
}

fn check_metadata(metadata: &Metadata, max_bytes: usize) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a regular file"));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(size_error(max_bytes));
    }
    Ok(())
}

fn read_bounded(mut reader: impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.by_ref().take(max_bytes as u64).read_to_end(&mut bytes)?;
    match reader.read_exact(&mut [0]) {
        Ok(()) => Err(size_error(max_bytes)),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(bytes),
        Err(err) => Err(err),
    }
}

fn size_error(max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("file exceeds size limit of {max_bytes} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_accepts_the_limit_and_rejects_an_extra_byte() {
        assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), b"abc");
        assert_eq!(read_bounded(&b"ab"[..], 3).unwrap(), b"ab");
        let err = read_bounded(&b"abcd"[..], 3).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "file exceeds size limit of 3 bytes");
        assert!(read_bounded(&b""[..], 0).unwrap().is_empty());
        let err = read_bounded(&b"a"[..], 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "file exceeds size limit of 0 bytes");
    }

    #[test]
    fn bounded_read_stops_after_the_limit_and_one_probe_byte() {
        let mut source = io::Cursor::new(b"abcdef");
        assert!(read_bounded(&mut source, 3).is_err());
        assert_eq!(source.position(), 4);
    }

    #[test]
    fn bounded_read_retries_an_interrupted_overflow_probe() {
        struct InterruptedProbe<'a> {
            remaining: &'a [u8],
            interrupted: bool,
        }

        impl Read for InterruptedProbe<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.remaining.read(buf)
            }
        }

        for remaining in [b"".as_slice(), b"d".as_slice()] {
            let mut source =
                io::Cursor::new(b"abc").chain(InterruptedProbe { remaining, interrupted: false });
            let result = read_bounded(&mut source, 3);
            if remaining.is_empty() {
                assert_eq!(result.unwrap(), b"abc");
            } else {
                let err = result.unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert_eq!(err.to_string(), "file exceeds size limit of 3 bytes");
            }
        }
    }

    #[test]
    fn bounded_file_rejects_directories() {
        assert_eq!(
            read_file_bounded(std::env::temp_dir(), 3).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_rejects_devices() {
        assert_eq!(
            read_file_bounded("/dev/zero", 3).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_rejects_fifo_replacing_a_regular_file_without_blocking() {
        use std::{
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        const CHILD_PATH: &str = "MIDEN_TEST_REPLACED_FIFO_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            // Resume at the open after the parent checked the original regular file's metadata.
            let err = read_file_after_metadata(Path::new(&path), 3).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), "expected a regular file");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replaced");
        fs::write(&path, b"abc").unwrap();
        check_metadata(&fs::metadata(&path).unwrap(), 3).unwrap();
        fs::remove_file(&path).unwrap();
        // Darwin does not provide mkfifoat; the POSIX utility also works on that platform.
        assert!(
            Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );

        // Isolate the open in a child so a regression cannot hang this test indefinitely.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "file::tests::bounded_file_rejects_fifo_replacing_a_regular_file_without_blocking",
            ])
            .env(CHILD_PATH, &path)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "replacement FIFO child failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("opening a replacement FIFO blocked");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
