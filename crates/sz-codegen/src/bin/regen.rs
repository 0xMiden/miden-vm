//! Regenerate checked-in MASM artifacts from spec.
//!
//! Usage:
//!   cargo run -p miden-sz-codegen --bin regen          # write artifacts in place
//!   cargo run -p miden-sz-codegen --bin regen -- --check # diff-only; nonzero exit on drift

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use miden_sz_codegen::{emit_module, specs};

/// Each entry: (spec, output path relative to the repo root).
fn artifacts() -> Vec<(&'static miden_sz_codegen::spec::LinearRelation, &'static str)> {
    vec![
        (&specs::MODMUL_K1_BASE, "crates/lib/core/asm/math/u256_sz_modmul_k1_base.masm"),
        (
            &specs::MODMUL_K1_SCALAR,
            "crates/lib/core/asm/math/u256_sz_modmul_k1_scalar.masm",
        ),
    ]
}

/// The u256 type alias the emitter bakes into every generated module. Must match the canonical
/// declaration at the top of `u256.masm`; [`check_u256_alias`] enforces this at regen time so the
/// generated modules cannot silently drift.
const EXPECTED_U256_ALIAS: &str = "pub type u256 = struct { lo: u128, hi: u128 }";

fn main() -> ExitCode {
    let check_mode = env::args().any(|a| a == "--check");
    let repo_root = repo_root();

    if let Err(e) = check_u256_alias(&repo_root) {
        eprintln!("FAILED: {e}");
        return ExitCode::from(2);
    }

    let mut drift = false;
    for (rel, rel_path) in artifacts() {
        let path = repo_root.join(rel_path);
        let new_content = emit_module(rel);
        let existing = fs::read_to_string(&path).unwrap_or_default();

        if existing == new_content {
            eprintln!("OK    {rel_path}");
            continue;
        }

        if check_mode {
            eprintln!("DRIFT {rel_path}");
            drift = true;
        } else if let Err(e) = fs::write(&path, &new_content) {
            eprintln!("FAILED to write {}: {e}", path.display());
            return ExitCode::from(2);
        } else {
            eprintln!("WROTE {rel_path}");
        }
    }

    if check_mode && drift {
        eprintln!(
            "\nregen --check: artifacts are out of date. Run `cargo run -p miden-sz-codegen --bin regen` to regenerate."
        );
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Asserts that `u256.masm`'s first line declares the canonical u256 type with the same shape
/// the emitter inlines into generated modules. Prevents the two from drifting silently.
fn check_u256_alias(repo_root: &Path) -> Result<(), String> {
    let path = repo_root.join("crates/lib/core/asm/math/u256.masm");
    let contents =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let first_line = contents.lines().next().unwrap_or("").trim_end();
    if first_line != EXPECTED_U256_ALIAS {
        return Err(format!(
            "u256.masm declares `{first_line}` but the codegen bakes in `{EXPECTED_U256_ALIAS}`. \
             Update EXPECTED_U256_ALIAS and emit_module's emitted alias to match."
        ));
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/sz-codegen at build time; the repo root is two levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| panic!("cannot locate repo root from {manifest_dir}"))
        .to_path_buf()
}
