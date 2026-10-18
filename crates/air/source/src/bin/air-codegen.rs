//! Generate or check production Rust and VM/PVM MASM projections from authored source.

use std::{env, path::PathBuf, process::ExitCode};

use miden_air_source::codegen::{self, Mode, constraints, precompile};

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let workspace = PathBuf::from(args.next().ok_or_else(|| {
        "usage: air-codegen <workspace-root> [--check|--write] [--derive-setup]".to_string()
    })?);
    let mut mode = Mode::Check;
    let mut derive_setup = false;
    for arg in args {
        match arg.as_str() {
            "--check" => mode = Mode::Check,
            "--write" => mode = Mode::Write,
            "--derive-setup" => derive_setup = true,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if derive_setup {
        constraints::check_setup(&workspace)?;
        precompile::check_setup(&workspace)?;
    }
    codegen::run(&workspace, mode)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        },
    }
}
