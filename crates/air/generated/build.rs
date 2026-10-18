//! Materialize packaged Rust; ordinary builds never capture or compile AIR definitions.

use std::{env, fs, io, path::PathBuf};

const ARTIFACT: &str = "artifacts/vm-evaluator.rs.zlib";
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={ARTIFACT}");
    let artifact = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(ARTIFACT);
    let compressed = fs::read(&artifact)?;
    let source =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&compressed, MAX_SOURCE_BYTES)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: invalid packaged evaluator: {:?}",
                        artifact.display(),
                        error.status
                    ),
                )
            })?;
    let source = std::str::from_utf8(&source)?;
    // Keep the exact generated text, including its inner documentation and lint attributes,
    // inside a module item that include! can consume.
    let module = format!("mod generated {{\n{source}\n}}\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("vm_evaluator.rs");
    fs::write(output, module)?;
    Ok(())
}
