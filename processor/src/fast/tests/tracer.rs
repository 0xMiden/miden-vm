use super::*;
use crate::{
    Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    execution::{InternalBreakReason, execute_impl},
    tracer::{OperationHelperRegisters, Tracer},
};

struct FailingClockTracer {
    fail_at_start: bool,
    failure_clock: usize,
    starts: usize,
    finalizations: usize,
}

impl Tracer for FailingClockTracer {
    type Processor = FastProcessor;
    type Forest = Arc<MastForest>;

    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        _continuation: Continuation<Self::Forest>,
        _continuation_stack: &ContinuationStack<Self::Forest>,
        _current_forest: &Self::Forest,
    ) -> Result<(), ProcessorError> {
        self.starts += 1;
        if self.fail_at_start && processor.clk == self.failure_clock {
            return Err(ProcessorError::Internal("start hook failed"));
        }
        Ok(())
    }

    fn finalize_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        _op_helper_registers: OperationHelperRegisters,
        _current_forest: &Self::Forest,
    ) -> Result<(), ProcessorError> {
        self.finalizations += 1;
        if !self.fail_at_start && processor.clk == self.failure_clock {
            return Err(ProcessorError::Internal("finalize hook failed"));
        }
        Ok(())
    }
}

struct CountingStopper(Cell<usize>);

impl Stopper for CountingStopper {
    type Processor = FastProcessor;
    type Forest = Arc<MastForest>;

    fn should_stop(
        &self,
        _processor: &FastProcessor,
        _continuation_stack: &ContinuationStack<Self::Forest>,
        _continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Self::Forest>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Self::Forest>> {
        self.0.set(self.0.get() + 1);
        ControlFlow::Continue(())
    }
}

#[rstest]
#[case::start_node(true, 0, 0)]
#[case::finalize_node(false, 0, 0)]
#[case::start_first_operation(true, 1, 0)]
#[case::finalize_first_operation(false, 1, 1)]
#[case::start_second_operation(true, 2, 1)]
#[case::finalize_second_operation(false, 2, 2)]
fn clock_hook_failure_stops_execution_at_its_boundary(
    #[case] fail_at_start: bool,
    #[case] failure_clock: usize,
    #[case] expected_stack_top: u32,
) {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Incr, Operation::Incr])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    let program = Program::new(Arc::new(forest), root);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/clock-hooks.masm");
    let source_file = source_manager
        .load_from_raw_parts(uri.clone(), SourceContent::new("masm", uri.clone(), "incr\nincr\n"));
    let mut builder = PackageDebugInfoBuilder::default();
    let asm_ops = [0, 5]
        .into_iter()
        .enumerate()
        .map(|(op_idx, start)| {
            debug_asm_op(
                &mut builder,
                op_idx as u32,
                Some(Location::new(uri.clone(), ByteIndex::new(start), ByteIndex::new(start + 4))),
                "clock_hooks",
                "incr",
                1,
            )
        })
        .collect();
    let source_root = builder.add_node(debug_source_node(root, vec![], 2, asm_ops)).unwrap();
    builder.add_root(source_root);
    let mut debug_info = Some(Arc::from(builder.build()));
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut continuation_stack = ContinuationStack::new_with_source_node_id(&program, source_root);
    let mut current_forest = program.mast_forest().clone();
    let mut host = DefaultHost::default().with_source_manager(source_manager);
    let mut tracer = FailingClockTracer {
        fail_at_start,
        failure_clock,
        starts: 0,
        finalizations: 0,
    };
    let stopper = CountingStopper(Cell::new(0));

    let flow = execute_impl(
        &mut processor,
        &mut continuation_stack,
        &mut current_forest,
        program.kernel(),
        &mut host,
        &mut tracer,
        &stopper,
        &mut debug_info,
        &mut Vec::new(),
    );
    let ControlFlow::Break(InternalBreakReason::User(BreakReason::Err(error))) = flow else {
        panic!("expected the clock hook to fail");
    };

    let expected_reason = if fail_at_start {
        "start hook failed"
    } else {
        "finalize hook failed"
    };
    assert_matches!(error.kind(), ProcessorError::Internal(reason) if *reason == expected_reason);
    assert_eq!(processor.clk, failure_clock);
    assert_eq!(processor.stack_get(0), Felt::from_u32(expected_stack_top));
    assert_eq!(tracer.starts, failure_clock + 1);
    assert_eq!(tracer.finalizations, failure_clock + usize::from(!fail_at_start));
    assert_eq!(stopper.0.get(), failure_clock);
    if fail_at_start {
        let start = if failure_clock < 2 { 0u32 } else { 5 };
        assert_eq!(error.source_span(), Some(SourceSpan::new(source_file.id(), start..start + 4)));
        assert_eq!(error.source_file().map(|file| file.id()), Some(source_file.id()));
    }
}
