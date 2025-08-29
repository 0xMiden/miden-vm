use alloc::collections::BTreeMap;

use miden_assembly::SourceManager;
use miden_core::Word;
use miden_debug_types::{Location, SourceFile, SourceManagerSync, SourceSpan};
use pretty_assertions::assert_eq;

use super::*;
use crate::{
    AdviceMutation, AsyncHost, BaseHost, EventError, FutureMaybeSend, MastForestStore,
    MemMastForestStore, MemoryAddress, ProcessState, SyncHost,
};

#[test]
fn test_advice_provider() {
    let kernel_source = "
        export.foo
            push.2323 mem_store.100 trace.11
        end
    ";

    let program_source = "
    proc.truncate_stack.4
        loc_storew.0 dropw movupw.3
        sdepth neq.16
        while.true
            dropw movupw.3
            sdepth neq.16
        end
        loc_loadw.0
    end

    # mainly used to break basic blocks
    proc.noop
        swap swap
    end

    # Tests different cases of batch sizes
    proc.basic_block
        # batch with 1 group
        swap drop swap trace.1

        call.noop

        # batch with 2 groups
        push.1 drop trace.2

        call.noop

        # batch with 3 groups (rounded up to 4)
        push.1 push.2 drop drop trace.3

        call.noop

        # batch with 5 groups (rounded up to 8)
        push.1 push.2 push.3 push.4 drop drop drop drop trace.4

        call.noop

        # batch with 8 pushes (which forces a noop to be inserted in the last position of the batch)
        push.0 push.1 push.2 push.3 push.4 push.5 push.6 push.7 trace.5

        call.noop

        # basic block with >1 batches (where clk needs to be incremented in-between batches due to the inserted RESPAN)
        push.0 push.1 push.2 push.3 push.4 push.5 push.6    trace.6
        drop drop drop drop drop drop drop drop drop        trace.7
    end

    proc.exec_me
        push.22 mem_store.0
        trace.9
    end

    proc.dyncall_me
        push.23 mem_store.0
        trace.100
    end

    proc.dynexec_me
        push.24 mem_store.0
        trace.101
    end

    proc.will_syscall
        syscall.foo
    end

    proc.control_flow
        # if true
        push.1 trace.16 if.true
            swap swap trace.17
        else
            swap swap
        end

        # if false
        push.0 trace.18 if.true
            swap swap
        else
            swap swap trace.19
        end

        # loop
        push.3 push.1
        while.true
            trace.20
            sub.1 dup neq.0
        end

        trace.21
    end

    begin
        # Check that initial state is consistent
        trace.0 push.10 add drop trace.1

        # Check that basic blocks are handled correctly
        exec.basic_block

        # Check that memory state is restored properly after call
        push.42 mem_store.0 trace.8
        exec.exec_me
        trace.10

        # Check that syscalls are handled correctly
        call.will_syscall
        trace.12

        # Check that dyncalls are handled correctly
        procref.dyncall_me mem_storew.4 dropw push.4 dyncall trace.13
        procref.will_syscall mem_storew.8 dropw push.8 dyncall trace.14

        # Check that dynexecs are handled correctly
        procref.dynexec_me mem_storew.4 dropw push.4 dynexec trace.15

        # Check that control flow operations are handled correctly
        exec.control_flow

        exec.truncate_stack
        trace.22
    end
    ";

    let stack_inputs = Vec::new();

    let (program, kernel_lib) = {
        let source_manager = Arc::new(DefaultSourceManager::default());

        let kernel_lib =
            Assembler::new(source_manager.clone()).assemble_kernel(kernel_source).unwrap();
        let program = Assembler::with_kernel(source_manager, kernel_lib.clone())
            .assemble_program(program_source)
            .unwrap();

        (program, kernel_lib)
    };

    // fast processor
    let mut fast_host = ConsistencyHost::new(kernel_lib.mast_forest().clone());
    let processor = FastProcessor::new_debug(&stack_inputs, AdviceInputs::default());
    let fast_stack_outputs = processor.execute_sync(&program, &mut fast_host).unwrap();

    // slow processor
    let mut slow_host = ConsistencyHost::new(kernel_lib.mast_forest().clone());
    let mut slow_processor = Process::new(
        kernel_lib.kernel().clone(),
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_tracing(),
    );
    let slow_stack_outputs = slow_processor.execute(&program, &mut slow_host).unwrap();

    // check outputs
    assert_eq!(fast_stack_outputs, slow_stack_outputs);

    // check hosts. Check one trace event at a time to help debugging.
    for (trace_id, fast_snapshots) in fast_host.snapshots.iter() {
        let slow_snapshots = slow_host.snapshots.get(trace_id).unwrap_or_else(|| {
            panic!("fast host has snapshot(s) for trace id {trace_id}, but slow host doesn't")
        });
        assert_eq!(fast_snapshots, slow_snapshots, "trace id: {trace_id}");
    }
    for (trace_id, slow_snapshots) in slow_host.snapshots.iter() {
        let fast_snapshots = fast_host.snapshots.get(trace_id).unwrap_or_else(|| {
            panic!("slow host has snapshot(s) for trace id {trace_id}, but fast host doesn't")
        });
        assert_eq!(fast_snapshots, slow_snapshots, "trace_id: {trace_id}");
    }

    // Still check the snapshots explicitly just in case we have a bug in the logic above.
    assert_eq!(fast_host.snapshots, slow_host.snapshots);
}

// Host Implementation
// ==============================================================================================

/// A snapshot of the state of a process at a given clock cycle.
#[derive(Debug, PartialEq, Eq)]
struct ProcessStateSnapshot {
    clk: RowIndex,
    ctx: ContextId,
    fmp: u64,
    stack_state: Vec<Felt>,
    stack_words: [Word; 4],
    mem_state: Vec<(MemoryAddress, Felt)>,
}

impl From<&ProcessState<'_>> for ProcessStateSnapshot {
    fn from(state: &ProcessState) -> Self {
        ProcessStateSnapshot {
            clk: state.clk(),
            ctx: state.ctx(),
            fmp: state.fmp(),
            stack_state: state.get_stack_state(),
            stack_words: [
                state.get_stack_word(0),
                state.get_stack_word(4),
                state.get_stack_word(8),
                state.get_stack_word(12),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

#[derive(Debug)]
struct ConsistencyHost<S: SourceManager = DefaultSourceManager> {
    /// A map of trace ID to a list of snapshots. A single trace ID can be associated with multiple
    /// snapshots for example if it's used in a loop.
    snapshots: BTreeMap<u32, Vec<ProcessStateSnapshot>>,
    store: MemMastForestStore,
    source_manager: Arc<S>,
}

impl ConsistencyHost {
    fn new(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest.clone());
        let source_manager = Arc::new(DefaultSourceManager::default());
        Self {
            snapshots: BTreeMap::new(),
            store,
            source_manager,
        }
    }
}

impl<S> BaseHost for ConsistencyHost<S>
where
    S: SourceManager,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        let snapshot = ProcessStateSnapshot::from(&*process);
        self.snapshots.entry(trace_id).or_default().push(snapshot);

        Ok(())
    }
}

impl<S> SyncHost for ConsistencyHost<S>
where
    S: SourceManager,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(&mut self, _process: &ProcessState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

impl<S> AsyncHost for ConsistencyHost<S>
where
    S: SourceManagerSync,
{
    #[allow(clippy::manual_async_fn)]
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        let result = <Self as SyncHost>::get_mast_forest(self, node_digest);
        async move { result }
    }
    // Note: clippy complains about this not using the `async` keyword, but if we use `async`, it
    // doesn't compile.
    #[allow(clippy::manual_async_fn)]
    fn on_event(
        &mut self,
        _process: &ProcessState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async move { Ok(Vec::new()) }
    }
}
