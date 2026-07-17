use std::{path::PathBuf, process::ExitCode};

use miden_core_lib_codegen::masm;

const DEFAULT_OUT_DIR: &str = "target/miden-core-lib-generated-asm";

fn usage() {
    println!("Usage:");
    println!("  miden-core-lib-codegen [--out <dir>]");
    println!();
    println!("Options:");
    println!("  --out <dir>  Write generated MASM preview to this directory");
    println!("               [default: {DEFAULT_OUT_DIR}]");
    println!("  -h, --help   Show this message");
}

fn parse_out_dir() -> Result<Option<PathBuf>, ExitCode> {
    let mut out_dir = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let Some(path) = args.next() else {
                    eprintln!("--out requires a directory");
                    usage();
                    return Err(ExitCode::FAILURE);
                };
                out_dir = Some(PathBuf::from(path));
            },
            "-h" | "--help" => {
                usage();
                return Err(ExitCode::SUCCESS);
            },
            other => {
                eprintln!("Unknown argument: {other}");
                usage();
                return Err(ExitCode::FAILURE);
            },
        }
    }

    Ok(out_dir)
}

fn main() -> ExitCode {
    let out_dir = match parse_out_dir() {
        Ok(out_dir) => out_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)),
        Err(code) => return code,
    };

    if let Err(error) = masm::write_to_dir(&out_dir) {
        eprintln!("failed: {error}");
        return ExitCode::FAILURE;
    }

    println!("wrote generated core-lib MASM to {}", out_dir.display());
    ExitCode::SUCCESS
}
