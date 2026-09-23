use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::Felt;
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};
use miden_event_handler::{AdviceRecorder, EventContext, InvocationKind};

#[allow(deprecated)] // Retained public conversion from the deprecated raw state view.
use crate::ProcessorState;
use crate::{
    BaseHost, LoadedMastForest, MastForestStore, MemMastForestStore, SyncHost, Word,
    event::EventError, mast::MastForest,
};

/// A snapshot of the processor state for consistency checking between processors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorStateSnapshot {
    clk: u32,
    in_root_context: bool,
    stack_state: Vec<Felt>,
    mem_state: Vec<(crate::MemoryAddress, Felt)>,
}

#[allow(deprecated)] // Retained public conversion from the deprecated raw state view.
impl From<&ProcessorState<'_>> for ProcessorStateSnapshot {
    fn from(state: &ProcessorState) -> Self {
        ProcessorStateSnapshot {
            clk: state.clock().into(),
            in_root_context: state.ctx() == crate::ContextId::root(),
            stack_state: state.get_stack_state(),
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

impl From<EventContext<'_>> for ProcessorStateSnapshot {
    fn from(context: EventContext<'_>) -> Self {
        Self {
            clk: context.clock(),
            in_root_context: context.in_root_context(),
            stack_state: context.stack_snapshot(),
            mem_state: context.memory_snapshot(),
        }
    }
}

/// A unified testing host that combines event handling, debug handling, and external node
/// resolution.
#[derive(Debug, Clone)]
pub struct TestHost<S: SourceManager = DefaultSourceManager> {
    /// List of event IDs that have been received
    pub event_handler: Vec<u64>,

    /// List of trace IDs that have been received
    pub trace_handler: Vec<u64>,

    /// Process state snapshots captured at emitted test checkpoints.
    snapshots: BTreeMap<u64, Vec<ProcessorStateSnapshot>>,

    /// Process state snapshots captured at trace checkpoints.
    trace_snapshots: BTreeMap<u64, Vec<ProcessorStateSnapshot>>,

    /// MAST forest store for external node resolution
    store: MemMastForestStore,

    /// Source manager for debugging information
    pub source_manager: Arc<S>,
}

impl TestHost {
    /// Creates a new TestHost with minimal functionality for basic testing.
    pub fn new() -> Self {
        Self {
            event_handler: Vec::new(),
            trace_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            trace_snapshots: BTreeMap::new(),
            store: MemMastForestStore::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Creates a new TestHost with a kernel forest for full consistency testing.
    pub fn with_kernel_forest(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest);
        Self {
            event_handler: Vec::new(),
            trace_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            trace_snapshots: BTreeMap::new(),
            store,
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Gets the processor state snapshots captured by emitted test checkpoints.
    pub fn snapshots(&self) -> &BTreeMap<u64, Vec<ProcessorStateSnapshot>> {
        &self.snapshots
    }

    /// Gets the processor state snapshots captured at trace checkpoints.
    pub fn trace_snapshots(&self) -> &BTreeMap<u64, Vec<ProcessorStateSnapshot>> {
        &self.trace_snapshots
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> BaseHost for TestHost<S>
where
    S: SourceManagerSync,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl<S> SyncHost for TestHost<S>
where
    S: SourceManagerSync,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest> {
        self.store.get(node_digest)
    }

    fn handle_event(
        &mut self,
        context: EventContext<'_>,
        _advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        let id = context.id().as_u64();
        let (handler, snapshots) = match context.kind() {
            InvocationKind::Event => (&mut self.event_handler, &mut self.snapshots),
            InvocationKind::Trace => (&mut self.trace_handler, &mut self.trace_snapshots),
        };
        handler.push(id);
        snapshots.entry(id).or_default().push(context.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_assembly::Assembler;

    use super::TestHost;
    use crate::{AdviceInputs, ExecutionOptions, FastProcessor, Program, StackInputs};

    #[test]
    fn test_host_records_trace_and_snapshot() {
        const TRACE_ID_1: u64 = 100;
        const TRACE_ID_2: u64 = 200;

        let source = format!(
            "\
    begin
        push.{TRACE_ID_1}
        trace
        drop
        push.{TRACE_ID_2}
        trace
        drop
    end"
        );
        let program: Program = Assembler::default()
            .assemble_program("program", &source)
            .unwrap()
            .unwrap_program();
        let mut host = TestHost::default();
        FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
        )
        .expect("failed to construct FastProcessor")
        .execute_sync(&program, &mut host)
        .unwrap();

        // Each trace id is recorded, in emission order.
        assert_eq!(host.trace_handler, vec![TRACE_ID_1, TRACE_ID_2]);
        // A snapshot is captured at each trace checkpoint, keyed by trace id.
        assert_eq!(host.trace_snapshots().get(&TRACE_ID_1).map(Vec::len), Some(1));
        assert_eq!(host.trace_snapshots().get(&TRACE_ID_2).map(Vec::len), Some(1));

        // Traces do not trigger non-trace handlers.
        assert!(host.event_handler.is_empty());
        assert!(host.snapshots().is_empty());
    }
}
