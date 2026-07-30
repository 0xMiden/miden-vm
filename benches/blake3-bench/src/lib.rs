use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use miden_core_lib::CoreLibrary;
use miden_vm::{
    Assembler, DefaultHost, ExecutionOptions, FastProcessor, HashFunction, Program, ProvingOptions,
    StackInputs, TraceBuildInputs, TraceProvingInputs, Verifier,
    advice::AdviceInputs,
    assembly::{
        DefaultSourceManager, Path as LibraryPath,
        ast::{Module, ModuleKind},
        package::debug_info::{DebugSourceNodeId, PackageDebugInfo},
    },
    internal::InputFile,
    prove_from_trace_sync, trace,
};
use serde::{Deserialize, Serialize};
use tracing::{Subscriber, span};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
};

pub const BENCH_GROUP: &str = "blake3_1to1";
pub const PRIMARY_METRIC: &str = "e2e_prove";

const PROGRAM_RELATIVE_PATH: &str = "miden-vm/masm-examples/hashing/blake3_1to1/blake3_1to1.masm";

#[derive(Clone)]
pub struct Blake3Fixture {
    pub program: Program,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
    pub debug_info: Option<PackageDebugInfo>,
    pub entrypoint_source_node: Option<DebugSourceNodeId>,
    source_manager: Arc<DefaultSourceManager>,
}

impl Blake3Fixture {
    pub fn load_from_repo(repo_root: &Path) -> Self {
        let program_path = repo_root.join(PROGRAM_RELATIVE_PATH);
        let input_file = InputFile::read(&None, &program_path)
            .unwrap_or_else(|err| panic!("failed to read Blake3 inputs: {err}"));

        let source_manager = Arc::new(DefaultSourceManager::default());
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let ast = parser
            .parse_file(Some(LibraryPath::exec_path()), &program_path, source_manager.clone())
            .unwrap_or_else(|err| {
                panic!("failed to parse Blake3 program at {}: {err}", program_path.display())
            });

        let mut assembler = Assembler::new(source_manager.clone());
        assembler
            .link_package(CoreLibrary::default().package(), miden_vm::assembly::Linkage::Dynamic)
            .expect("failed to load core library");
        let package = assembler
            .assemble_program("program", ast)
            .expect("failed to assemble Blake3 benchmark program");
        let debug_info = package.debug_info().expect("failed to read Blake3 debug info");
        let entrypoint_source_node = package.entrypoint_source_node();
        let program = package.unwrap_program();

        Self {
            program,
            stack_inputs: input_file.parse_stack_inputs().expect("failed to parse stack inputs"),
            advice_inputs: input_file.parse_advice_inputs().expect("failed to parse advice inputs"),
            debug_info,
            entrypoint_source_node,
            source_manager,
        }
    }
}

pub fn repo_root_from_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn execution_options() -> ExecutionOptions {
    ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .expect("CLI-compatible Blake3 execution options should be valid")
}

pub fn proving_options() -> ProvingOptions {
    ProvingOptions::with_96_bit_security(HashFunction::Blake3_256)
}

pub fn default_host() -> DefaultHost {
    DefaultHost::default()
        .with_library(&CoreLibrary::default())
        .expect("failed to load core library into host")
}

fn host_for_fixture(fixture: &Blake3Fixture) -> DefaultHost<DefaultSourceManager> {
    default_host().with_source_manager(fixture.source_manager.clone())
}

pub fn execute_trace_inputs(fixture: &Blake3Fixture) -> TraceBuildInputs {
    let mut host = host_for_fixture(fixture);
    let processor = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options(),
    )
    .expect("processor advice inputs should fit advice map limits");
    match (fixture.debug_info.as_ref(), fixture.entrypoint_source_node) {
        (Some(debug_info), Some(entrypoint_source_node)) => processor
            .execute_trace_inputs_with_package_debug_info_at_source_node_sync(
                &fixture.program,
                debug_info,
                entrypoint_source_node,
                &mut host,
            )
            .expect("failed to execute Blake3 benchmark"),
        (Some(debug_info), None) => processor
            .execute_trace_inputs_with_package_debug_info_sync(
                &fixture.program,
                debug_info,
                &mut host,
            )
            .expect("failed to execute Blake3 benchmark"),
        (None, _) => processor
            .execute_trace_inputs_sync(&fixture.program, &mut host)
            .expect("failed to execute Blake3 benchmark"),
    }
}

pub fn execute_program(fixture: &Blake3Fixture) {
    let mut host = host_for_fixture(fixture);
    let processor = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options(),
    )
    .expect("processor advice inputs should fit advice map limits");
    processor
        .execute_sync(&fixture.program, &mut host)
        .expect("failed to execute Blake3 benchmark");
}

pub fn prove_program(fixture: &Blake3Fixture) {
    let _span = tracing::info_span!("prove_program_sync").entered();
    prove_trace(execute_trace_inputs(fixture));
}

pub fn prove_trace(trace_inputs: TraceBuildInputs) {
    let _ = prove_trace_outputs(trace_inputs);
}

pub fn prove_and_verify_once(fixture: &Blake3Fixture) {
    let stack_inputs = fixture.stack_inputs;
    let trace_inputs = execute_trace_inputs(fixture);
    let (stack_outputs, proof) = prove_trace_outputs(trace_inputs);
    Verifier::new()
        .verify(fixture.program.to_info(), stack_inputs, stack_outputs, proof)
        .expect("failed to verify Blake3 benchmark proof");
}

fn prove_trace_outputs(
    trace_inputs: TraceBuildInputs,
) -> (miden_vm::StackOutputs, miden_vm::ExecutionProof) {
    prove_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options()))
        .expect("failed to prove Blake3 benchmark trace")
}

pub fn build_trace(trace_inputs: TraceBuildInputs) {
    trace::build_trace(trace_inputs).expect("failed to build Blake3 execution trace");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpanRecord {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub name: String,
    pub target: String,
    pub path: String,
    pub duration_ms: f64,
}

#[derive(Clone, Debug)]
struct SpanTiming {
    started_at: Instant,
    parent_id: Option<u64>,
    name: String,
    target: String,
    path: String,
}

#[derive(Clone, Default)]
struct SpanRecorder {
    records: Arc<Mutex<Vec<SpanRecord>>>,
}

impl SpanRecorder {
    fn records(&self) -> Vec<SpanRecord> {
        let mut records = self.records.lock().expect("span recorder lock poisoned").clone();
        records.sort_by_key(|record| record.id);
        records
    }
}

impl<S> Layer<S> for SpanRecorder
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        let parent = attrs
            .parent()
            .and_then(|parent_id| ctx.span(parent_id))
            .or_else(|| ctx.lookup_current());
        let parent_id = parent.as_ref().map(|span| span.id().into_u64());
        let parent_path = parent.and_then(|span| {
            span.extensions().get::<SpanTiming>().map(|timing| timing.path.clone())
        });
        let name = metadata.name().to_string();
        let path = parent_path.map_or_else(|| name.clone(), |parent| format!("{parent} > {name}"));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanTiming {
                started_at: Instant::now(),
                parent_id,
                name,
                target: metadata.target().to_string(),
                path,
            });
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(timing) = span.extensions().get::<SpanTiming>().cloned() else {
            return;
        };
        self.records.lock().expect("span recorder lock poisoned").push(SpanRecord {
            id: id.into_u64(),
            parent_id: timing.parent_id,
            name: timing.name,
            target: timing.target,
            path: timing.path,
            duration_ms: duration_ms(timing.started_at.elapsed()),
        });
    }
}

pub fn collect_trace_spans(fixture: &Blake3Fixture) -> Vec<SpanRecord> {
    let recorder = SpanRecorder::default();
    let subscriber = Registry::default().with(recorder.clone());
    tracing::subscriber::with_default(subscriber, || prove_program(fixture));
    recorder.records()
}

pub fn prove_span_duration(fixture: &Blake3Fixture) -> Duration {
    let spans = collect_trace_spans(fixture);
    let prove_span = spans
        .iter()
        .find(|span| span.name == "prove")
        .expect("failed to collect `prove` span from Blake3 proof run");
    Duration::from_secs_f64(prove_span.duration_ms / 1000.0)
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
