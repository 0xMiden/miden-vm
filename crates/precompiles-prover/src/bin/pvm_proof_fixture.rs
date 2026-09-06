//! Checks or regenerates the pinned Eidos PVM proof fixture.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_core::{
    deferred::{DeferredState, Node, PrecompileRegistry},
    proof::HashFunction,
};
use miden_crypto::hash::keccak::Keccak256;
use miden_precompiles::Keccak256Precompile;
use miden_precompiles_prover::prove_deferred_state;
use miden_precompiles_verifier::verify_deferred;

const PROOF_PATH: &str = "../precompiles-verifier/tests/fixtures/pvm_eidos_v0_31.bin";
const ROOT_PATH: &str = "../precompiles-verifier/tests/fixtures/pvm_eidos_v0_31.root";
const INPUT: &[u8] = b"abc";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Check,
    Write,
}

fn main() {
    let mode = match parse_mode(std::env::args().skip(1).collect()) {
        Ok(mode) => mode,
        Err(args) => {
            eprintln!("usage: pvm-proof-fixture [--check | --write] (got {args:?})");
            std::process::exit(2);
        },
    };

    if let Err(error) = run(mode) {
        eprintln!("failed: {error}");
        std::process::exit(1);
    }
}

fn parse_mode(args: Vec<String>) -> Result<Mode, Vec<String>> {
    match args.as_slice() {
        [arg] if arg == "--check" => Ok(Mode::Check),
        [arg] if arg == "--write" => Ok(Mode::Write),
        _ => Err(args),
    }
}

fn run(mode: Mode) -> Result<(), String> {
    ensure_sequential_prover()?;

    let state = fixture_state()?;
    let proof = prove_deferred_state(&state, HashFunction::Eidos)
        .map_err(|error| format!("generate proof: {error}"))?;
    verify_deferred(&proof, state.root())
        .map_err(|error| format!("verify generated proof: {error}"))?;

    let proof_path = fixture_path(PROOF_PATH);
    let root_path = fixture_path(ROOT_PATH);
    let root = render_root(state.root());

    match mode {
        Mode::Check => {
            check_file(&proof_path, proof.bytes())?;
            check_file(&root_path, root.as_bytes())?;
            println!("PVM proof fixture is current ({} bytes)", proof.bytes().len());
        },
        Mode::Write => {
            write_if_changed(&proof_path, proof.bytes())?;
            write_if_changed(&root_path, root.as_bytes())?;
            println!("wrote PVM proof fixture ({} bytes)", proof.bytes().len());
        },
    }

    Ok(())
}

fn ensure_sequential_prover() -> Result<(), String> {
    if cfg!(feature = "concurrent") {
        return Err(
            "pinned proof generation requires the sequential prover; disable `concurrent`".into()
        );
    }
    Ok(())
}

fn fixture_state() -> Result<DeferredState, String> {
    let registry =
        Arc::new(PrecompileRegistry::new().with_precompile(Keccak256Precompile::default()));
    let mut state = DeferredState::new(registry).map_err(|error| error.to_string())?;

    let input = state
        .register(Node::chunks_from_bytes(INPUT))
        .map_err(|error| format!("register input: {error}"))?;
    let digest: [u8; 32] = Keccak256::hash(INPUT).into();
    let expected = state
        .register(Node::chunks_from_bytes(&digest))
        .map_err(|error| format!("register digest: {error}"))?;
    let input_len = u32::try_from(INPUT.len()).expect("fixture input length fits in u32");
    let assertion = state
        .register(Keccak256Precompile::assert_node(input_len, input, expected))
        .map_err(|error| format!("register Keccak assertion: {error}"))?;
    state
        .log_statement(assertion)
        .map_err(|error| format!("log assertion: {error}"))?;

    Ok(state)
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn render_root(root: miden_core::Word) -> String {
    let values = root
        .as_elements()
        .iter()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{values}\n")
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), String> {
    let actual = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "{} is stale; run `make regenerate-pvm-proof-fixture`",
            path.display()
        ));
    }
    Ok(())
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<(), String> {
    if fs::read(path).is_ok_and(|current| current == contents) {
        return Ok(());
    }
    fs::write(path, contents).map_err(|error| format!("write {}: {error}", path.display()))
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

    #[cfg(feature = "concurrent")]
    #[test]
    fn concurrent_prover_is_rejected() {
        assert!(ensure_sequential_prover().is_err());
    }

    #[cfg(not(feature = "concurrent"))]
    #[test]
    fn sequential_prover_is_accepted() {
        assert!(ensure_sequential_prover().is_ok());
    }
}
