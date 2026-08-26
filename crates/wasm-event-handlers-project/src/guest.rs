//! Building a Rust guest crate into a core-Wasm handler module.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

use miden_assembly::diagnostics::Report;
use miden_wasm_event_handlers::GUEST_RUSTFLAGS;

/// The target the guest crate is built for.
const TARGET: &str = "wasm32-unknown-unknown";

/// The advice a message carries when the toolchain may lack the Wasm target.
const TARGET_HINT: &str =
    "if the target is missing, run `rustup target add wasm32-unknown-unknown`";

/// The cargo target kind of the handler module.
const CDYLIB_TARGET_KIND: &str = "cdylib";

/// Builds the Rust guest crate at `crate_dir` and returns the bytes of the Wasm module it
/// produces.
///
/// The crate must produce exactly one `.wasm` artifact from a `cdylib` target, which a `[lib]`
/// with `crate-type = ["cdylib"]` gives. Other targets of the crate, such as a binary, are
/// ignored. The build is a release build for `wasm32-unknown-unknown` and writes into a dedicated
/// directory under the guest crate, so it never shares a target directory, and therefore never
/// shares a build lock, with the build that runs the project assembler.
///
/// # Errors
/// Returns an error when `cargo` is not available, when the build fails (the message carries the
/// captured build output), or when the build does not produce exactly one Wasm artifact.
pub(crate) fn build(crate_dir: &Path) -> Result<Vec<u8>, Report> {
    if !crate_dir.is_dir() {
        return Err(Report::msg(format!(
            "Wasm handler guest crate '{}' is not a directory",
            crate_dir.display()
        )));
    }

    let target_dir = crate_dir.join("target").join("wasm-event-handlers");
    let output = Command::new(cargo())
        .current_dir(crate_dir)
        // An inherited `RUSTFLAGS` replaces the rustflags a `.cargo/config.toml` sets, and
        // `CARGO_ENCODED_RUSTFLAGS` in turn replaces `RUSTFLAGS`. The first is pinned and the
        // second removed, so the guest builds the same way whatever the caller's environment
        // holds.
        .env("RUSTFLAGS", GUEST_RUSTFLAGS)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(["build", "--release", "--target", TARGET, "--message-format"])
        .arg("json-render-diagnostics")
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .map_err(|error| {
            Report::msg(format!(
                "failed to run cargo to build the Wasm handler guest crate '{}': {error}; \
                 cargo and the {TARGET} target must be installed",
                crate_dir.display()
            ))
        })?;

    if !output.status.success() {
        return Err(Report::msg(format!(
            "failed to build the Wasm handler guest crate '{}' for {TARGET} ({TARGET_HINT})\n{}",
            crate_dir.display(),
            String::from_utf8_lossy(&output.stderr),
        )));
    }

    let mut artifacts = wasm_artifacts(&output.stdout);
    match artifacts.len() {
        1 => std::fs::read(&artifacts[0]).map_err(|error| {
            Report::msg(format!(
                "failed to read the Wasm handler module '{}': {error}",
                artifacts[0].display()
            ))
        }),
        0 => Err(Report::msg(format!(
            "the Wasm handler guest crate '{}' produced no {TARGET} module; its manifest must \
             declare a library target with crate-type = [\"cdylib\"]",
            crate_dir.display()
        ))),
        _ => {
            artifacts.sort_unstable();
            let names: Vec<String> =
                artifacts.iter().map(|path| path.display().to_string()).collect();
            Err(Report::msg(format!(
                "the Wasm handler guest crate '{}' produced {} modules ({}); a package declares \
                 one handler module only",
                crate_dir.display(),
                names.len(),
                names.join(", "),
            )))
        },
    }
}

/// Returns the cargo executable the guest build runs.
///
/// A caller that is itself run by cargo names the matching executable in `CARGO`; other callers
/// get the one on `PATH`.
fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Collects the Wasm artifacts of the `cdylib` targets a cargo JSON message stream reports.
///
/// The artifact paths come from cargo's `compiler-artifact` messages rather than from the crate
/// name, because the crate name is not the file name: cargo replaces `-` with `_`, and a manifest
/// can rename the library target.
///
/// Only the `cdylib` targets count. A guest crate can hold a second Wasm-producing target, such
/// as a `src/main.rs` binary, and that target is not the handler module.
fn wasm_artifacts(stdout: &[u8]) -> Vec<PathBuf> {
    let mut artifacts = Vec::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let is_cdylib = message
            .get("target")
            .and_then(|target| target.get("kind"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|kinds| {
                kinds.iter().any(|kind| kind.as_str() == Some(CDYLIB_TARGET_KIND))
            });
        if !is_cdylib {
            continue;
        }
        let Some(filenames) = message.get("filenames").and_then(serde_json::Value::as_array) else {
            continue;
        };
        artifacts.extend(
            filenames
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|name| name.ends_with(".wasm"))
                .map(PathBuf::from),
        );
    }
    artifacts
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifacts_come_from_the_compiler_artifact_messages() {
        let stdout = br#"{"reason":"compiler-artifact","target":{"kind":["lib"]},"filenames":["/out/libdep.rlib"]}
{"reason":"build-script-executed","target":{"kind":["custom-build"]},"filenames":["/out/ignored.wasm"]}
{"reason":"compiler-artifact","target":{"kind":["cdylib"]},"filenames":["/out/guest.wasm","/out/guest.d"]}
not json
"#;
        assert_eq!(wasm_artifacts(stdout), vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn only_the_cdylib_artifacts_count() {
        // A guest crate with a `src/main.rs` also produces a `.wasm` binary; only the cdylib is
        // the handler module.
        let stdout = br#"{"reason":"compiler-artifact","target":{"kind":["bin"]},"filenames":["/out/guest-bin.wasm"]}
{"reason":"compiler-artifact","target":{"kind":["cdylib"]},"filenames":["/out/guest.wasm"]}
"#;
        assert_eq!(wasm_artifacts(stdout), vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn a_missing_guest_crate_directory_is_reported() {
        let error = build(Path::new("/definitely/not/a/guest/crate")).unwrap_err();
        assert!(error.to_string().contains("is not a directory"), "unexpected error: {error}");
    }
}
