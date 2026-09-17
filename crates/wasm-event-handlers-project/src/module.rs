//! Reading a handler module file under the size cap of the `event_handlers` section.

use std::{fs::File, io::Read, path::Path};

use miden_assembly::diagnostics::Report;
use miden_mast_package::MAX_MODULE_BYTES;

/// Reads the Wasm module file at `path`, refusing before the allocation anything that cannot be a
/// handler module: a file that is not a regular file (reading a device or a FIFO would never
/// return), or a file over [`MAX_MODULE_BYTES`].
///
/// `io_error` builds the message of a plain I/O failure, so every call site keeps its own wording;
/// the file-kind and size failures are reported here.
///
/// The metadata lookup follows symlinks, so a symlink to a regular module file is read.
pub(crate) fn read(
    path: &Path,
    io_error: impl Fn(&std::io::Error) -> String,
) -> Result<Vec<u8>, Report> {
    let metadata = std::fs::metadata(path).map_err(|error| Report::msg(io_error(&error)))?;
    if !metadata.is_file() {
        return Err(Report::msg(format!(
            "the handler module '{}' is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_MODULE_BYTES as u64 {
        return Err(too_large(path, metadata.len()));
    }

    let file = File::open(path).map_err(|error| Report::msg(io_error(&error)))?;
    // The file can grow between the lookup above and the read, so the size the metadata reported
    // only sizes the buffer: the capped reader, and the check of what it produced, are what bound
    // the read.
    let mut wasm = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MODULE_BYTES as u64 + 1)
        .read_to_end(&mut wasm)
        .map_err(|error| Report::msg(io_error(&error)))?;
    if wasm.len() > MAX_MODULE_BYTES {
        return Err(too_large(path, wasm.len() as u64));
    }

    Ok(wasm)
}

/// Reports a module over the cap; `size` is what is known of its length.
fn too_large(path: &Path, size: u64) -> Report {
    Report::msg(format!(
        "the handler module '{}' is {size} bytes, over the {MAX_MODULE_BYTES}-byte limit",
        path.display()
    ))
}
