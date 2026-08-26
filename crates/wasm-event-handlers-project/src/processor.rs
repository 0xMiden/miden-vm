//! The package post-processor that attaches the `event_handlers` section.

use std::{
    collections::{BTreeMap, btree_map::Entry},
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
/// The processor reads `[package.metadata.wasm-event-handlers]` (see the [crate] documentation
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
/// module is built, read, and derived once per source path: the outcome, success or failure, is
/// memoized for the life of the processor.
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
    /// The derived section per handler source (the variant and the resolved path together, so
    /// a `crate` and a `module` entry that name one path do not share an outcome).
    ///
    /// A failure is memoized as its message, because a build error is not clonable. The message
    /// carries no manifest path — the caller prefixes the manifest of the package it is
    /// processing, so a shared source reports against the right project. The lock is held
    /// across the derivation, so `cargo` runs at most once per source.
    derived: Mutex<BTreeMap<HandlerSource, Result<EventHandlerSection, String>>>,
}

impl WasmEventHandlerProcessor {
    /// Creates a processor with an empty memoization cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the section `source` gives, deriving it on the first call for that source.
    ///
    /// The error is the bare failure message, without a manifest label.
    fn section(&self, source: &HandlerSource) -> Result<EventHandlerSection, String> {
        let mut derived = self.derived.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = match derived.entry(source.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(derive(source).map_err(|error| format!("{error:#}")))
            },
        };
        outcome.clone()
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

/// Produces the module `source` names and derives its `event_handlers` section.
///
/// Errors name the source path but not the manifest: the caller adds the manifest label of the
/// package it is processing.
fn derive(source: &HandlerSource) -> Result<EventHandlerSection, Report> {
    let path = source.path();
    let wasm = match source {
        HandlerSource::GuestCrate(crate_dir) => guest::build(crate_dir)?,
        HandlerSource::Module(module) => std::fs::read(module).map_err(|error| {
            Report::msg(format!("cannot read the handler module '{}': {error}", module.display()))
        })?,
    };

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
