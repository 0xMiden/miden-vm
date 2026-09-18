//! The package post-processors that attach the `event_handlers` section.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Mutex, PoisonError},
};

use miden_assembly::{PackagePostProcessor, PostProcessContext, diagnostics::Report};
use miden_mast_package::{EventHandlerSection, Package as MastPackage};
use miden_wasm_event_handlers::{WasmHandlerLimits, section_from_module};

use crate::{
    config::{self, CRATE_KEY, HandlerSource, MODULE_KEY},
    guest, module,
};

// PROCESSORS
// ================================================================================================

/// Attaches the prebuilt Wasm handler module a project manifest declares to every package of the
/// project under assembly (its root target and its required libraries, whatever the target type).
/// Source dependencies are never post-processed.
///
/// The processor reads `[package.metadata.midenc.event-handlers]` and serves the `module` key
/// only: it reads the module file, derives the `event_handlers` section from the module's own
/// manifest records, and attaches the section to the package. A package that declares no such
/// table passes through unchanged. See the [crate] documentation for the schema, the validation,
/// the memoization, and the one-package-per-host rule.
///
/// # Security
///
/// A manifest that declares `crate` fails the build here, because building a guest crate means
/// running `cargo build` on that source. [`WasmEventHandlerCargoBuildProcessor`] is the processor
/// that does it, and the refusal names it. Registering this processor therefore never executes
/// code from the assembled project.
///
/// The module it reads is untrusted but sandboxed input: it is validated against the default
/// [`WasmHandlerLimits`] at build time and runs under wasmi at execution time.
#[derive(Debug, Default)]
pub struct WasmEventHandlerProcessor {
    /// The sections this processor derived, and the flow that attaches them.
    sections: SectionProvider,
}

impl WasmEventHandlerProcessor {
    /// Creates a processor with an empty memoization cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PackagePostProcessor for WasmEventHandlerProcessor {
    fn post_process(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
    ) -> Result<(), Report> {
        self.sections.attach(package, context, GuestCrates::Refused)
    }
}

/// Attaches the Wasm handler module a project manifest declares to every package of the project
/// under assembly (its root target and its required libraries, whatever the target type). Source
/// dependencies are never post-processed.
///
/// The processor reads `[package.metadata.midenc.event-handlers]` and serves both keys: it builds
/// the guest crate of a `crate` key, or reads the module file of a `module` key, derives the
/// `event_handlers` section from the module's own manifest records, and attaches the section to
/// the package. A package that declares no such table passes through unchanged. See the [crate]
/// documentation for the schema, the toolchain the `crate` key needs, the validation, the
/// memoization, and the one-package-per-host rule.
///
/// # Security
///
/// Registering this processor is equivalent to running `cargo build` on the source the project
/// manifest references, with the permissions of the assembler process: build scripts and
/// procedural macros run native code. Register it only when the assembled source is trusted — a
/// local compiler building the developer's own project. A host that assembles source supplied by
/// other users must register [`WasmEventHandlerProcessor`] instead, which refuses guest-crate
/// builds.
#[derive(Debug, Default)]
pub struct WasmEventHandlerCargoBuildProcessor {
    /// The sections this processor derived, and the flow that attaches them.
    sections: SectionProvider,
}

impl WasmEventHandlerCargoBuildProcessor {
    /// Creates a processor with an empty memoization cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PackagePostProcessor for WasmEventHandlerCargoBuildProcessor {
    fn post_process(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
    ) -> Result<(), Report> {
        self.sections.attach(package, context, GuestCrates::Built)
    }
}

// SHARED SECTION PROVIDER
// ================================================================================================

/// What a processor does with the guest crate a `crate` key names: the one difference between the
/// two processors.
#[derive(Debug, Clone, Copy)]
enum GuestCrates {
    /// The crate is built, which runs `cargo build` on the source it names.
    Built,
    /// The crate fails the build, so the processor serves a prebuilt module only.
    Refused,
}

/// The post-process flow the two processors share: it produces the module bytes of the handler
/// source a manifest declares, derives the `event_handlers` section from them, and attaches the
/// section to the package under assembly.
#[derive(Debug, Default)]
struct SectionProvider {
    /// The derived section per handler source, together with the hash of the module bytes it was
    /// derived from.
    ///
    /// The key is the whole source (the variant and the resolved path together, so a `crate` and
    /// a `module` entry that name one path do not share an outcome), and the hash keys the
    /// content: an entry serves a later call only when the source produces exactly the bytes the
    /// entry came from, which keeps a stale section out of a build that follows an edit.
    ///
    /// Only a success is kept. A failure is re-attempted on the next call, so a source the
    /// developer fixes builds without a new processor.
    ///
    /// The lock is held across the whole call, so `cargo` runs one guest build at a time.
    derived: Mutex<BTreeMap<HandlerSource, (blake3::Hash, EventHandlerSection)>>,
}

impl SectionProvider {
    /// Attaches to `package` the section the manifest of the package under assembly declares.
    ///
    /// `guest_crates` decides what a `crate` key gives. A refusal is reported as soon as the
    /// source is known, before any build and before any memoization, so a processor that does not
    /// build guest crates never runs `cargo`.
    fn attach(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
        guest_crates: GuestCrates,
    ) -> Result<(), Report> {
        let assembly = context.assembly;
        let manifest_path = assembly.manifest_path;
        let Some(source) =
            config::read(assembly.package.as_ref(), manifest_path, assembly.project_root.as_ref())?
        else {
            return Ok(());
        };

        if matches!(guest_crates, GuestCrates::Refused)
            && let HandlerSource::GuestCrate(crate_dir) = &source
        {
            return Err(config::error(
                manifest_path,
                format!(
                    "key '{CRATE_KEY}' names the guest crate '{}', and building it means running \
                     `cargo build` on that source, which this processor refuses; register \
                     `WasmEventHandlerCargoBuildProcessor` to build guest crates, or set \
                     '{MODULE_KEY}' to a module another build produced",
                    crate_dir.display(),
                ),
            ));
        }

        let section =
            self.section(&source).map_err(|message| config::error(manifest_path, message))?;
        // The attachment refuses a package that already has the section, which keeps a second
        // producer of the section visible instead of silently replacing the first.
        package.attach_event_handlers(&section).map_err(|error| {
            Report::msg(format!(
                "{}: cannot attach the Wasm handlers of '{}' to package '{}': {error}",
                config::label(manifest_path),
                source.path().display(),
                package.name,
            ))
        })
    }

    /// Returns the section `source` gives.
    ///
    /// The module bytes are produced on every call — a file read, or an incremental `cargo` build
    /// that does no work for an unchanged guest crate — and only the derivation, the dry-load
    /// included, is skipped when they are the bytes the memoized section came from.
    ///
    /// The error is the bare failure message, without a manifest label: the caller prefixes the
    /// manifest of the package it is processing, so a source two projects share reports against
    /// the right one.
    fn section(&self, source: &HandlerSource) -> Result<EventHandlerSection, String> {
        let mut derived = self.derived.lock().unwrap_or_else(PoisonError::into_inner);

        let wasm = module_bytes(source).map_err(|error| format!("{error:#}"))?;
        let hash = blake3::hash(&wasm);
        if let Some((derived_from, section)) = derived.get(source)
            && *derived_from == hash
        {
            return Ok(section.clone());
        }

        let section = derive(source.path(), wasm).map_err(|error| format!("{error:#}"))?;
        derived.insert(source.clone(), (hash, section.clone()));
        Ok(section)
    }
}

/// Produces the bytes of the module `source` names: a guest crate is built, a prebuilt module is
/// read. Either way the bytes come through [`module::read`], so nothing over the handler module
/// size cap is loaded.
///
/// Errors name the source path but not the manifest: the caller adds the manifest label of the
/// package it is processing.
fn module_bytes(source: &HandlerSource) -> Result<Vec<u8>, Report> {
    match source {
        HandlerSource::GuestCrate(crate_dir) => guest::build(crate_dir),
        HandlerSource::Module(path) => module::read(path, |error| {
            format!("cannot read the handler module '{}': {error}", path.display())
        }),
    }
}

/// Derives the `event_handlers` section of the module `wasm` holds, which the source at `path`
/// produced.
///
/// Errors name the source path but not the manifest: the caller adds the manifest label of the
/// package it is processing.
fn derive(path: &Path, wasm: Vec<u8>) -> Result<EventHandlerSection, Report> {
    let section = section_from_module(wasm, WasmHandlerLimits::default()).map_err(|error| {
        Report::msg(format!("the handler module of '{}' is not valid: {error}", path.display()))
    })?;

    // A module with no manifest records derives an empty, and therefore useless, section. The
    // records come from the guest SDK macro, so an empty manifest almost always means the macro
    // is missing.
    if section.handlers.is_empty() {
        return Err(Report::msg(format!(
            "the handler module of '{}' declares no event handlers; mark every handler \
             function with `#[miden_event_handler(\"<event name>\")]` from the \
             `miden-event-handler-sdk` crate",
            path.display()
        )));
    }

    Ok(section)
}
