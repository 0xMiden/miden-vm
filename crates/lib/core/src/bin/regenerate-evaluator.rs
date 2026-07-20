use std::process::ExitCode;

use miden_core_lib::evaluator_regen::{self, Mode};

fn usage() {
    println!("Usage:");
    println!("  regenerate-evaluator [--check|--write]");
    println!();
    println!("Options:");
    println!("  --check   Verify the checked-in generated evaluators (default)");
    println!("  --write   Rebuild and write the generated evaluators");
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

    if let Err(error) = evaluator_regen::run(mode) {
        eprintln!("failed: {error}");
        if mode == Mode::Check {
            eprintln!("hint: rerun with `--write` to refresh the checked-in artifact");
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
