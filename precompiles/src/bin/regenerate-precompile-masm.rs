use std::process::ExitCode;

use miden_precompiles::codegen::masm::{self, Mode};

fn usage() {
    println!("Usage:");
    println!("  regenerate-precompile-masm [--check|--write]");
    println!();
    println!("Options:");
    println!("  --check   Verify checked-in precompile MASM artifacts (default)");
    println!("  --write   Rebuild and write precompile MASM artifacts");
    println!("  -h, --help  Show this message");
}

fn parse_mode() -> Result<Mode, ExitCode> {
    let mut mode = Mode::Check;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--check" => mode = Mode::Check,
            "--write" => mode = Mode::Write,
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

    Ok(mode)
}

fn main() -> ExitCode {
    let mode = match parse_mode() {
        Ok(mode) => mode,
        Err(code) => return code,
    };

    if let Err(error) = masm::run(mode) {
        eprintln!("failed: {error}");
        if mode == Mode::Check {
            eprintln!(
                "hint: run `cargo run -p miden-precompiles --features codegen-tools --bin regenerate-precompile-masm -- --write` or rerun with `--write` to refresh checked-in artifacts"
            );
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
