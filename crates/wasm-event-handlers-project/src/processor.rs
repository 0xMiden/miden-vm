//! The package post-processor that attaches the `event_handlers` section.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Mutex, PoisonError},
};

use miden_assembly::{PackagePostProcessor, PostProcessContext, diagnostics::Report};
use miden_mast_package::{EventHandlerSection, Package as MastPackage};
use miden_wasm_event_handlers::{WasmHandlerLimits, section_from_module};

use crate::{
    config::{self, HandlerSource},
    guest,
};

/// Attaches the Wasm handler module a project manifest declares to every package of the project
/// under assembly (its root target and its required libraries, whatever the target type).
/// Source dependencies are never post-processed.
///
/// The processor reads `[package.metadata.midenc.event-handlers]` (see the [crate] documentation
/// for the schema). It builds the guest crate, or reads the prebuilt module, derives the
/// `event_handlers` section from the module's own manifest records, and attaches the section to
/// the package. A package that declares no such table passes through unchanged.
///
/// The derived section is checked against [`WasmHandlerLimits::default`] at build time, so a
/// forbidden import, a SIMD instruction, a start section, a bad export, or an over-budget
/// instantiation fails the build instead of every host that later loads the package. Limits are
/// host policy, so a host may still run stricter ones.
///
/// One project assembles several targets, and the processor runs once per assembled package. The
/// module bytes are produced on every run — a file read, or a `cargo` build that is a fast no-op
/// when the guest crate did not change — and only the derivation is memoized, keyed by those
/// bytes. An edited source therefore publishes its new section instead of the previous one, and a
/// failure is never memoized, so a fixed source builds on the next run.
///
/// # One package per host
///
/// Every package of a project carries the same, full handler set, so a host registers the
/// handlers of ONE package of a project. A host that loads the handlers of a second package of
/// the same project fails with a duplicate-handler error, because the two packages declare the
/// same events. The failure is deliberate: a silent second registration would hide which package
/// answers an event.
#[derive(Debug, Default)]
pub struct WasmEventHandlerProcessor {
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

impl WasmEventHandlerProcessor {
    /// Creates a processor with an empty memoization cache.
    pub fn new() -> Self {
        Self::default()
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

impl PackagePostProcessor for WasmEventHandlerProcessor {
    fn post_process(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
    ) -> Result<(), Report> {
        let assembly = context.assembly;
        let manifest_path = assembly.manifest_path;
        let Some(source) =
            config::read(assembly.package.as_ref(), manifest_path, assembly.project_root.as_ref())?
        else {
            return Ok(());
        };

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
}

/// Produces the bytes of the module `source` names: a guest crate is built, a prebuilt module is
/// read.
///
/// Errors name the source path but not the manifest: the caller adds the manifest label of the
/// package it is processing.
fn module_bytes(source: &HandlerSource) -> Result<Vec<u8>, Report> {
    match source {
        HandlerSource::GuestCrate(crate_dir) => guest::build(crate_dir),
        HandlerSource::Module(module) => std::fs::read(module).map_err(|error| {
            Report::msg(format!("cannot read the handler module '{}': {error}", module.display()))
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
