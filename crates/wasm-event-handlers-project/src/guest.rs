//! Building a Rust guest crate into a core-Wasm handler module.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

use cargo_metadata::{Message, TargetKind};
use miden_assembly::diagnostics::Report;
use miden_wasm_event_handlers::GUEST_RUSTFLAGS;

/// The target the guest crate is built for.
const TARGET: &str = "wasm32-unknown-unknown";

/// The advice a message carries when the toolchain may lack the Wasm target.
const TARGET_HINT: &str =
    "if the target is missing, run `rustup target add wasm32-unknown-unknown`";

/// Builds the Rust guest crate at `crate_dir` and returns the bytes of the Wasm module it
/// produces.
///
/// The crate must produce exactly one `.wasm` artifact from a `cdylib` target, which a `[lib]`
/// with `crate-type = ["cdylib"]` gives. The build passes `--lib`, so the other targets of the
/// crate, such as a binary or an example, are not built at all: they cannot fail the handler
/// build and they cost no build time. The build is a release build for `wasm32-unknown-unknown`
/// and writes into a dedicated directory under the guest crate, so it never shares a target
/// directory, and therefore never shares a build lock, with the build that runs the project
/// assembler.
///
/// # Errors
/// Returns an error when `cargo` is not available, when the build fails (the message carries the
/// captured build output), or when the build does not produce exactly one Wasm artifact. A crate
/// with no library target fails in the build, with cargo's own message.
pub(crate) fn build(crate_dir: &Path) -> Result<Vec<u8>, Report> {
    if !crate_dir.is_dir() {
        return Err(Report::msg(format!(
            "Wasm handler guest crate '{}' is not a directory",
            crate_dir.display()
        )));
    }

    // The dedicated target directory carries the name of the metadata table that requested the
    // build.
    let target_dir = crate_dir.join("target").join(crate::config::TABLE);
    let output = Command::new(cargo())
        .current_dir(crate_dir)
        // An inherited `RUSTFLAGS` replaces the rustflags a `.cargo/config.toml` sets, and
        // `CARGO_ENCODED_RUSTFLAGS` in turn replaces `RUSTFLAGS`. The first is pinned and the
        // second removed, so the guest builds the same way whatever the caller's environment
        // holds.
        .env("RUSTFLAGS", GUEST_RUSTFLAGS)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // `--lib` builds the library target only. A binary or an example of the guest crate is
        // not the handler module, and a build failure in one of them must not fail the handler
        // build.
        .args(["build", "--lib", "--release", "--target", TARGET, "--message-format"])
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

    // The plugin canonicalizes `crate_dir`, and cargo reports an absolute canonical manifest
    // path, so the two spellings match.
    let mut artifacts = wasm_artifacts(&output.stdout, &crate_dir.join("Cargo.toml"));
    match artifacts.len() {
        1 => std::fs::read(&artifacts[0]).map_err(|error| {
            Report::msg(format!(
                "failed to read the Wasm handler module '{}': {error}",
                artifacts[0].display()
            ))
        }),
        // A crate with no library target at all does not reach this arm: `--lib` makes cargo
        // itself fail the build with its own "no library targets" message.
        0 => Err(Report::msg(format!(
            "the Wasm handler guest crate '{}' produced no {TARGET} module; its library target \
             must have crate-type = [\"cdylib\"]",
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

/// Collects the Wasm artifacts the guest crate's own `cdylib` targets contribute to a cargo JSON
/// message stream.
///
/// The artifact paths come from cargo's `compiler-artifact` messages rather than from the crate
/// name, because the crate name is not the file name: cargo replaces `-` with `_`, and a manifest
/// can rename the library target.
///
/// Only the artifacts of the guest crate itself count, matched by `manifest_path`, so the artifact
/// of a dependency is never taken. Of those, only the `cdylib` targets count: a library target
/// built without the `cdylib` crate type contributes nothing, which keeps the crate-type error
/// of the caller accurate.
fn wasm_artifacts(stdout: &[u8], manifest_path: &Path) -> Vec<PathBuf> {
    let mut artifacts = Vec::new();
    // `parse_stream` reports a line that is not a cargo message as `Message::TextLine` and fails
    // only on an I/O error, so a build output interleaved with plain text costs no artifact.
    for message in Message::parse_stream(stdout).flatten() {
        let Message::CompilerArtifact(artifact) = message else {
            continue;
        };
        if artifact.manifest_path.as_std_path() != manifest_path {
            continue;
        }
        if !artifact.target.kind.contains(&TargetKind::CDyLib) {
            continue;
        }
        artifacts.extend(
            artifact
                .filenames
                .iter()
                .filter(|name| name.extension() == Some("wasm"))
                .map(|name| name.clone().into_std_path_buf()),
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
        let stdout = br#"{"reason":"build-script-executed","package_id":"path+file:///guest#guest@0.1.0","linked_libs":[],"linked_paths":[],"cfgs":[],"env":[],"out_dir":"/out/build/guest-1/out"}
{"reason":"compiler-artifact","package_id":"path+file:///guest#guest@0.1.0","manifest_path":"/guest/Cargo.toml","target":{"kind":["cdylib"],"crate_types":["cdylib"],"name":"guest","src_path":"/guest/src/lib.rs","edition":"2021","doc":false,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/guest.wasm","/out/guest.d"],"executable":null,"fresh":false}
not json
{"reason":"build-finished","success":true}
"#;
        let artifacts = wasm_artifacts(stdout, Path::new("/guest/Cargo.toml"));
        assert_eq!(artifacts, vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn only_the_cdylib_artifacts_count() {
        // `--lib` keeps a `src/main.rs` binary out of the build; the filter is defense in depth.
        let stdout = br#"{"reason":"compiler-artifact","package_id":"path+file:///guest#guest@0.1.0","manifest_path":"/guest/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":"guest","src_path":"/guest/src/main.rs","edition":"2021","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/guest-bin.wasm"],"executable":"/out/guest-bin.wasm","fresh":false}
{"reason":"compiler-artifact","package_id":"path+file:///guest#guest@0.1.0","manifest_path":"/guest/Cargo.toml","target":{"kind":["cdylib"],"crate_types":["cdylib"],"name":"guest","src_path":"/guest/src/lib.rs","edition":"2021","doc":false,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/guest.wasm"],"executable":null,"fresh":false}
"#;
        let artifacts = wasm_artifacts(stdout, Path::new("/guest/Cargo.toml"));
        assert_eq!(artifacts, vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn a_multi_kind_library_target_gives_its_wasm_artifact_only() {
        // A `[lib]` with crate-type = ["cdylib", "rlib"] reports one message with both kinds and
        // both files; only the `.wasm` is the handler module.
        let stdout = br#"{"reason":"compiler-artifact","package_id":"path+file:///guest#guest@0.1.0","manifest_path":"/guest/Cargo.toml","target":{"kind":["cdylib","rlib"],"crate_types":["cdylib","rlib"],"name":"guest","src_path":"/guest/src/lib.rs","edition":"2021","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/guest.wasm","/out/libguest.rlib"],"executable":null,"fresh":false}
"#;
        let artifacts = wasm_artifacts(stdout, Path::new("/guest/Cargo.toml"));
        assert_eq!(artifacts, vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn a_dependency_artifact_is_excluded() {
        // A dependency that is a `cdylib` of its own reports a `.wasm` too; the manifest path is
        // what tells the two apart.
        let stdout = br#"{"reason":"compiler-artifact","package_id":"path+file:///deps/other#other@0.1.0","manifest_path":"/deps/other/Cargo.toml","target":{"kind":["cdylib"],"crate_types":["cdylib"],"name":"other","src_path":"/deps/other/src/lib.rs","edition":"2021","doc":false,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/other.wasm"],"executable":null,"fresh":false}
{"reason":"compiler-artifact","package_id":"path+file:///guest#guest@0.1.0","manifest_path":"/guest/Cargo.toml","target":{"kind":["cdylib"],"crate_types":["cdylib"],"name":"guest","src_path":"/guest/src/lib.rs","edition":"2021","doc":false,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/out/guest.wasm"],"executable":null,"fresh":false}
"#;
        let artifacts = wasm_artifacts(stdout, Path::new("/guest/Cargo.toml"));
        assert_eq!(artifacts, vec![PathBuf::from("/out/guest.wasm")]);
    }

    #[test]
    fn a_missing_guest_crate_directory_is_reported() {
        let error = build(Path::new("/definitely/not/a/guest/crate")).unwrap_err();
        assert!(error.to_string().contains("is not a directory"), "unexpected error: {error}");
    }
}
