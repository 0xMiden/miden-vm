use std::{boxed::Box, net::TcpListener, path::Path, sync::Arc, vec::Vec};

use miden_assembly::DefaultSourceManager;
use miden_assembly_syntax::diagnostics::Report;
use miden_core::{Word, events::EventId};
use miden_debug_engine::{HybridPackageRegistry, normalize_source_path};
use miden_debug_types::{Location, SourceFile, SourceManager, SourceManagerExt, SourceSpan};
use miden_mast_package::Package;
use miden_package_registry::PackageRegistry;
use miden_processor::{
    BaseHost, DefaultHost, FutureMaybeSend, Host, HostLibrary, LoadedMastForest, ProcessorState,
    advice::AdviceMutation, event::EventError,
};

use crate::{DapConfig, DapExecutor, DebuggerConfig};

/// Start a DAP server for a local Miden program.
///
/// This is the non-transaction counterpart to `miden-client exec --start-debug-adapter`.
/// It accepts compiled package artifacts only.
pub fn run(config: Box<DebuggerConfig>) -> Result<(), Report> {
    let addr = config
        .start_debug_adapter
        .as_ref()
        .ok_or_else(|| Report::msg("missing --start-debug-adapter address"))?;
    let listener = DapExecutor::bind_listener(addr).map_err(Report::msg)?;
    run_on_listener(config, listener)
}

fn run_on_listener(config: Box<DebuggerConfig>, listener: TcpListener) -> Result<(), Report> {
    let addr = listener
        .local_addr()
        .map_err(|err| Report::msg(format!("failed to read DAP listener address: {err}")))?;
    DapConfig::set_global(
        DapConfig::new(format!("{addr}"))
            .with_source_path_prefixes(config.source_path_prefixes.clone()),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let registry = HybridPackageRegistry::new(
        config.sysroot.as_deref(),
        &config.search_path,
        &config.link_libraries,
    )?;
    let program = crate::program_loader::load_package(&config)?;
    verify_package_dependencies(&program, &registry)?;
    let typed_procedure = crate::debug::TypedProcedure::for_package_entrypoint(&program);
    let inputs = crate::program_loader::execution_inputs(&config, typed_procedure.as_ref())?;
    let mut host = StandaloneDapHost::new(source_manager);

    for package in registry.all() {
        let name = package.name.clone();
        host.load_library(package).map_err(|err| {
            Report::msg(format!("failed to load package '{name}' into DAP host: {err}"))
        })?;
    }

    let executor = DapExecutor::new(inputs.inputs, inputs.advice_inputs, inputs.options);
    executor
        .execute_on_listener(program, &mut host, listener)
        .map(|_| ())
        .map_err(|err| Report::msg(format!("program execution failed: {err}")))
}

struct StandaloneDapHost {
    inner: DefaultHost<DefaultSourceManager>,
    source_manager: Arc<DefaultSourceManager>,
}

impl StandaloneDapHost {
    fn new(source_manager: Arc<DefaultSourceManager>) -> Self {
        let inner = DefaultHost::default().with_source_manager(source_manager.clone());
        Self {
            inner,
            source_manager,
        }
    }

    fn load_library(
        &mut self,
        lib: impl Into<HostLibrary>,
    ) -> Result<(), miden_processor::ExecutionError> {
        self.inner.load_library(lib)
    }

    fn ensure_source_file(&self, location: &Location) -> Option<Arc<SourceFile>> {
        if let Some(file) = self.source_manager.get_by_uri(location.uri()) {
            return Some(file);
        }

        let path = normalize_source_path(location.uri().as_str());
        self.source_manager.load_file(Path::new(&path)).ok()
    }
}

impl BaseHost for StandaloneDapHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.ensure_source_file(location);
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&miden_core::events::EventName> {
        self.inner.resolve_event(event_id)
    }
}

impl Host for StandaloneDapHost {
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        self.inner.get_mast_forest(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        self.inner.on_event(process)
    }
}

fn verify_package_dependencies(
    package: &Package,
    registry: &HybridPackageRegistry,
) -> Result<(), Report> {
    for dependency in package.manifest.dependencies() {
        let version = miden_project::Version::new(dependency.version().clone(), dependency.digest);
        if !registry.is_version_available(&dependency.name, &version) {
            return Err(Report::msg(format!(
                "dependency {}@{version} not found in loaded libraries",
                dependency.name
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
