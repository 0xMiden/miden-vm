//! Regenerates the PVM ACE registry constants (`src/ace_registry/data.rs`).
//!
//! Usage: `cargo run -p miden-precompiles-prover --features registry-tools --release \
//!         --bin pvm-registry-regen -- [--check | --write]`

use miden_precompiles_prover::ace_registry_regen::{Mode, run};

fn parse_mode(args: Vec<String>) -> Result<Mode, Vec<String>> {
    match args.as_slice() {
        [arg] if arg == "--check" => Ok(Mode::Check),
        [arg] if arg == "--write" => Ok(Mode::Write),
        _ => Err(args),
    }
}

fn main() {
    let mode = match parse_mode(std::env::args().skip(1).collect()) {
        Ok(mode) => mode,
        Err(args) => {
            eprintln!("usage: pvm-registry-regen [--check | --write] (got {args:?})");
            std::process::exit(2);
        },
    };
    if let Err(err) = run(mode) {
        eprintln!("failed: {err}");
        if mode == Mode::Check {
            eprintln!(
                "if this protocol change is intentional, run `make regenerate-pvm-registry` \
                 and record the break; otherwise inspect the unexpected drift before updating \
                 constants"
            );
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_requires_exactly_one_known_argument() {
        assert_eq!(parse_mode(vec!["--check".into()]), Ok(Mode::Check));
        assert_eq!(parse_mode(vec!["--write".into()]), Ok(Mode::Write));
        assert!(parse_mode(Vec::new()).is_err());
        assert!(parse_mode(vec!["--write".into(), "extra".into()]).is_err());
        assert!(parse_mode(vec!["unknown".into()]).is_err());
    }
}
