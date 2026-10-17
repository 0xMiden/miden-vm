//! Stages a complete core-library assembly tree, verifier modules included.
//!
//! Usage: `miden-verifier-codegen --stage <core-library asm directory> <destination>`. The release
//! MASM compatibility gate and manual inspection use this; the `miden-core-lib` build stages the
//! same tree into `OUT_DIR`.

use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--stage", source, destination] => {
            miden_verifier_codegen::stage_core_library(Path::new(source), Path::new(destination))
        },
        _ => Err("usage: miden-verifier-codegen --stage <asm directory> <destination>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        },
    }
}
