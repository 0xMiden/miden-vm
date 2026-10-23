//! Check, regenerate, or stage the complete tracked verifier assembly.
//!
//! Regeneration is explicit; ordinary core-library builds assemble the tracked source.

use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--check", source] => {
            miden_verifier_codegen::sync_verifier_masm(Path::new(source), false)
        },
        ["--write", source] => {
            miden_verifier_codegen::sync_verifier_masm(Path::new(source), true)
        },
        ["--stage", source, destination] => {
            miden_verifier_codegen::stage_core_library(Path::new(source), Path::new(destination))
        },
        _ => Err("usage: miden-verifier-codegen --check|--write <asm directory>, or --stage <asm directory> <destination>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        },
    }
}
