use alloc::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{ast::DebugVarLocation, debuginfo::SourceManager};
use miden_core::operations::AssemblyOp;
use miden_processor::{
    ContextId, ExecutionError, FastProcessor, Felt, ResumeContext, StackOutputs,
    operation::Operation, trace::RowIndex,
};

pub(crate) use super::source::{CurrentCycleInfo, extract_current_op};
use super::{
    DebuggerHost, Event, ExecutionTrace,
    cycle::CycleInfo,
    source::SourceContext,
    stepper::{Stepped, Stepper},
};
use crate::{
    Breakpoint, BreakpointType, OperationMatcher,
    debug::{CallFrame, CallStack, ControlFlowOp, DebugVarTracker, InlineCallFrame, StepInfo},
    profiling::Profiler,
};

/// A special version of [crate::Executor] which provides finer-grained control over execution,
/// and captures a ton of information about the program being executed, so as to make it possible
/// to introspect everything about the program and the state of the VM at a given cycle.
///
/// This is used by the debugger to execute programs, and provide all of the functionality made
/// available by the TUI.
pub struct DebugExecutor {
    /// The stepper that runs the program: it owns the processor and the resume context, and
    /// describes every cycle before it runs
    stepper: Stepper,
    /// The host providing debugging callbacks
    pub host: DebuggerHost<dyn miden_assembly_syntax::debuginfo::SourceManager>,

    // State from last step (replaces VmState fields)
    /// The current operand stack state
    pub current_stack: Vec<Felt>,
    /// The operation that was just executed
    pub current_op: Option<Operation>,
    /// The assembly-level operation info for the current op
    pub current_asmop: Option<AssemblyOp>,

    /// The final outcome of the program being executed
    pub stack_outputs: StackOutputs,
    /// The set of contexts allocated during execution so far
    pub contexts: BTreeSet<ContextId>,
    /// The root context
    pub root_context: ContextId,
    /// The current context: the one after the last cycle a step completed without error, which
    /// after a limit trip is the cycle before `cycle`
    pub current_context: ContextId,
    /// The current call stack
    pub callstack: CallStack,
    /// The most recent live procedure name observed from assembly operation metadata.
    pub current_proc: Option<Arc<str>>,
    /// Debug variable tracker for source-level variable inspection
    pub debug_vars: DebugVarTracker,
    /// Number of debug variable location records observed during the most recent step.
    pub last_debug_var_count: usize,
    /// A sliding window of the last 5 operations successfully executed by the VM
    pub recent: VecDeque<Operation>,
    /// The current clock cycle: the stepper's, mirrored after each step so that a session that
    /// stands in for a remote execution can show its own. After a cycle that completes and
    /// then trips a limit it counts that cycle, while the stack, the operation, the assembly
    /// operation, the context, the recent operations, the procedure name and the contexts keep
    /// the state after the cycle before it; the call stack, the declarations and the profiler
    /// were already advanced for the tripping cycle
    pub cycle: usize,
    /// Whether or not execution has terminated. Set by a step that finishes or fails the
    /// program, or finds the stepper already stopped; a session that stands in for a remote
    /// execution sets it itself. Once set, a step does nothing
    pub stopped: bool,
    /// The profiler used by this executor
    pub profiler: Profiler,
}

impl super::query::DebugQuery for DebugExecutor {
    #[inline]
    fn state(&self) -> miden_processor::ProcessorState<'_> {
        self.stepper.processor().state()
    }

    fn current_context(&self) -> ContextId {
        self.current_context
    }

    fn current_clock(&self) -> RowIndex {
        self.stepper.processor().state().clock()
    }
}

impl DebugExecutor {
    /// Get the current operand stack as a slice - the top of the stack is the last item in the slice
    ///
    /// This returns the entire stack, not just the top 16 elements
    pub fn stack(&self) -> &[Felt] {
        self.stepper.processor().stack()
    }

    /// The processor being driven.
    pub fn processor(&self) -> &FastProcessor {
        self.stepper.processor()
    }

    /// The context the next step consumes; `None` once the stepper is stopped, successfully or
    /// not, or a step did not complete.
    pub fn resume_ctx(&self) -> Option<&ResumeContext> {
        self.stepper.resume_ctx()
    }

    /// An executor over `stepper` and `host`, whose call stack follows the frame events written
    /// to `events`, with `profiler` receiving the cycles.
    ///
    /// [`Executor::into_debug`](crate::Executor::into_debug) builds one over a package before
    /// its first step; a session that shows an execution running elsewhere builds one over
    /// [`Stepper::finished`] and sets the state it displays. The call stack and the
    /// declarations start empty, so `stepper` must not have stepped unless it is stopped.
    pub fn new(
        stepper: Stepper,
        host: DebuggerHost<dyn miden_assembly_syntax::debuginfo::SourceManager>,
        events: Arc<miden_utils_sync::RwLock<alloc::collections::BTreeMap<RowIndex, Event>>>,
        profiler: Profiler,
    ) -> Self {
        let root_context = ContextId::root();
        let debug_var_events = alloc::rc::Rc::new(core::cell::RefCell::new(Default::default()));
        let cycle = stepper.cycle();
        Self {
            stepper,
            host,
            current_stack: Vec::new(),
            current_op: None,
            current_asmop: None,
            stack_outputs: Default::default(),
            contexts: Default::default(),
            root_context,
            current_context: root_context,
            callstack: CallStack::new(events),
            current_proc: None,
            debug_vars: DebugVarTracker::new(debug_var_events),
            last_debug_var_count: 0,
            recent: VecDeque::with_capacity(5),
            cycle,
            stopped: false,
            profiler,
        }
    }
}

/// Wait for entry declarations in the current straight-line source occurrence, but never run
/// through a branch or a callee just because a later location exists somewhere in the function.
/// Only declarations observed this cycle count; kills and stale caller variables do not.
pub(crate) fn should_wait_for_entry_variables(
    resume_ctx: &ResumeContext,
    procedure: &str,
    variables: &DebugVarTracker,
    cycle: usize,
) -> bool {
    if variables
        .current_variables()
        .any(|variable| variable.clk == RowIndex::from(cycle as u32))
    {
        return false;
    }
    let Some(debug_info) = resume_ctx.debug_info() else {
        return false;
    };
    let next = extract_current_op(resume_ctx);
    let Some(source_node) = next.source_node_id.map(|node| &debug_info[node]) else {
        return false;
    };
    let Some(op_idx) = next.op_idx else {
        return false;
    };
    source_node.debug_vars.iter().any(|variable| {
        variable.op_idx as usize >= op_idx
            && !matches!(variable.value_location, DebugVarLocation::Unavailable)
            && source_node.asm_op_for_operation(variable.op_idx).is_some_and(|operation| {
                debug_info[operation.context_name_idx].as_ref() == procedure
            })
    })
}

impl DebugExecutor {
    /// Returns whether a function breakpoint should wait for pending entry-block declarations.
    pub fn should_wait_for_entry_variables(&self, procedure: &str) -> bool {
        self.stepper.resume_ctx().is_some_and(|resume_ctx| {
            should_wait_for_entry_variables(resume_ctx, procedure, &self.debug_vars, self.cycle)
        })
    }

    /// Advance the program state by one cycle.
    ///
    /// Once the program has terminated, successfully or not, it returns `Ok(None)`.
    ///
    /// Returns the call frame exited this cycle, if any
    pub fn step(&mut self) -> Result<Option<CallFrame>, ExecutionError> {
        self.step_impl(|_| {}, |_| {})
    }

    /// Advance the program state by one cycle, describing the cycle to `on_cycle` first.
    ///
    /// `on_cycle` runs before the cycle executes, after the profiler's instruments received the
    /// same record, so it sees a cycle that fails too. The step that finalizes a finished
    /// program runs no cycle and is not described. Unlike the [`Stepper`] it drives, a step
    /// after a failure is not an error: it returns `Ok(None)` like a step after the end. A
    /// step after a panic that unwound through a step, which only a caller that catches panics
    /// can make, returns the stepper's error once and `Ok(None)` after that. Otherwise like
    /// [`Self::step`].
    pub fn step_with(
        &mut self,
        on_cycle: impl FnOnce(&CycleInfo<'_>),
    ) -> Result<Option<CallFrame>, ExecutionError> {
        self.step_impl(|_| {}, on_cycle)
    }

    /// Observe the executor before a cycle, once the call stack and the declarations were
    /// brought up to date for it. The observer also runs when that cycle fails, and for the
    /// finalization step, but never after execution has stopped.
    pub(crate) fn step_with_observer(
        &mut self,
        observe: impl FnOnce(&Observation<'_>),
    ) -> Result<Option<CallFrame>, ExecutionError> {
        self.step_impl(observe, |_| {})
    }

    /// One step through the stepper: before the cycle runs, the call stack and the declarations
    /// are brought up to date, the internal observer sees them with the source context, then
    /// the instruments and `on_cycle` receive the cycle record; after it, the state for
    /// inspection is refreshed from the processor.
    pub(crate) fn step_impl(
        &mut self,
        observe: impl FnOnce(&Observation<'_>),
        on_cycle: impl FnOnce(&CycleInfo<'_>),
    ) -> Result<Option<CallFrame>, ExecutionError> {
        // A stepper that is stopped, because it was created so for a stand-in or because a
        // caller reset `stopped` after the program finished or failed, has nothing to run:
        // the state for inspection stays as it is.
        if self.stopped || self.stepper.stopped() {
            self.stopped = true;
            self.last_debug_var_count = 0;
            return Ok(None);
        }

        let next_cycle = RowIndex::from((self.cycle + 1) as u32);
        // What the step was about to run comes back with the result, for the state the cycle
        // leaves behind.
        let step_result = self.stepper.step_sync_described(&mut self.host, |step| {
            let source = step.source;
            let CurrentCycleInfo {
                op,
                control_flow_kind,
                ..
            } = source.cycle;
            let debug_var_infos = source.debug_vars();
            let asmop = source.asmop();
            self.callstack.observe_source_context(
                step.ctx,
                source.source_operation(),
                asmop.as_ref(),
            );
            let debug_var_count = debug_var_infos.len();
            self.debug_vars.observe_execution(
                self.callstack.invocation_ids(),
                self.callstack.current_invocation(),
                step.processor,
                next_cycle,
                debug_var_infos,
            );
            observe(&Observation {
                callstack: &self.callstack,
                debug_vars: &self.debug_vars,
                processor: step.processor,
                current_stack: &self.current_stack,
                current_context: self.current_context,
                source,
            });
            if let Some(cycle) = step.cycle {
                self.profiler.on_cycle(cycle);
                on_cycle(cycle);
            }
            DescribedStep {
                op,
                control_flow_kind,
                asmop,
                debug_var_count,
                inline_frames: source.inline_frames().to_vec(),
            }
        });
        match step_result {
            Ok(Some(Stepped {
                described:
                    DescribedStep {
                        op,
                        control_flow_kind,
                        asmop: source_asmop,
                        debug_var_count,
                        inline_frames,
                    },
                running: true,
            })) => {
                self.cycle = self.stepper.cycle();

                // Query processor state
                let state = self.stepper.processor().state();
                let ctx = state.ctx();
                self.current_stack = state.get_stack_state();

                if self.current_context != ctx {
                    self.contexts.insert(ctx);
                    self.current_context = ctx;
                }

                // Track operation
                self.current_op = op;
                self.current_asmop = source_asmop;
                if let Some(asmop) = self.current_asmop.as_ref() {
                    self.current_proc = Some(asmop.context_name().clone());
                }

                if let Some(op) = op {
                    if self.recent.len() == 5 {
                        self.recent.pop_front();
                    }
                    self.recent.push_back(op);
                    self.profiler.on_operation_execution_cycle(op, self.current_proc.as_deref());
                }

                // Update call stack
                let step_info = StepInfo {
                    op,
                    control: control_flow_kind,
                    asmop: self.current_asmop.as_ref(),
                    clk: RowIndex::from(self.cycle as u32),
                    ctx: self.current_context,
                    inline_frames: &inline_frames,
                };
                let exited = self.callstack.next(&step_info);

                self.last_debug_var_count = debug_var_count;

                Ok(exited)
            }
            // The stepper comes back empty only when it was already stopped, which the guard
            // above catches before the step.
            Ok(None) => unreachable!("a stopped stepper is caught before the step"),
            // The finalization step.
            Ok(Some(Stepped { running: false, .. })) => {
                // Program completed: no invocation remains available for inspection.
                self.debug_vars.reset();
                self.stopped = true;
                self.last_debug_var_count = 0;
                let state = self.stepper.processor().state();
                self.current_stack = state.get_stack_state();

                // Capture the final stack as StackOutputs (truncate to 16 elements)
                let len = self.current_stack.len().min(16);
                self.stack_outputs =
                    StackOutputs::new(&self.current_stack[..len]).expect("invalid stack outputs");

                // Write profiling reports in case its enabled
                #[cfg(feature = "std")]
                {
                    self.profiler.write_reports();
                }
                Ok(None)
            }
            Err(err) => {
                // A cycle that completes and then trips a limit is on the clock.
                self.cycle = self.stepper.cycle();
                self.stopped = true;
                self.last_debug_var_count = 0;
                Err(err)
            }
        }
    }

    /// Whether a captured invocation has returned and execution has reached a caller operation.
    /// Event-only targets may stop without source information.
    pub fn has_returned(&self, target: &crate::debug::ReturnTarget) -> bool {
        self.callstack.has_returned(target)
            && (!target.is_recovered()
                || !self.callstack.has_recovered_current_frame()
                || (self.current_op.is_some() && self.current_asmop.is_some()))
    }

    /// Advance the program state until `breakpoint` is hit.
    ///
    /// Once the program is stopped, successfully or not, it returns `Ok(())` without stepping.
    pub fn step_until(
        &mut self,
        breakpoint: BreakpointType,
        source_manager: &dyn SourceManager,
    ) -> Result<(), ExecutionError> {
        let start_cycle = self.cycle;
        let breakpoint = Breakpoint {
            id: 0,
            creation_cycle: start_cycle,
            ty: breakpoint,
        };
        let start_asmop = self.current_asmop.clone();
        let return_target =
            (breakpoint.ty == BreakpointType::Finish).then(|| self.callstack.return_target());
        while !self.stopped {
            self.step()?;
            if return_target.as_ref().is_some_and(|target| self.has_returned(target)) {
                return Ok(());
            }

            let (op, is_op_boundary, proc, loc) = {
                let op = self.current_op;
                let is_boundary = self.current_asmop.as_ref().map(|_info| true).unwrap_or(false);
                let (proc, loc) = match self.callstack.current_frame() {
                    Some(frame) => {
                        let loc = frame
                            .recent()
                            .back()
                            .and_then(|detail| detail.resolve(source_manager))
                            .cloned();
                        (frame.procedure(""), loc)
                    }
                    None => (None, None),
                };
                (op, is_boundary, proc, loc)
            };

            if let Some(op) = op
                && breakpoint.should_break_for(&op, &self.stepper.processor().state())
            {
                return Ok(());
            }

            if is_op_boundary
                && let Some(asmop) = self.current_asmop.as_ref()
                && matches!(&breakpoint.ty, BreakpointType::Opcode(OperationMatcher::Asm(expected)) if expected.as_str() == asmop.op().as_ref())
            {
                return Ok(());
            }

            // Check if `breakpoint` was triggered at this cycle
            let current_cycle = self.cycle;
            let cycles_stepped = current_cycle - start_cycle;
            if let Some(n) = breakpoint.cycles_to_skip(current_cycle)
                && cycles_stepped > 0
                && n == 0
            {
                return Ok(());
            }

            if cycles_stepped > 0
                && is_op_boundary
                && matches!(&breakpoint.ty, BreakpointType::Next)
                && self.current_asmop != start_asmop
            {
                return Ok(());
            }

            if let Some(loc) = loc.as_ref()
                && breakpoint.should_break_at(loc)
            {
                return Ok(());
            }

            if let Some(proc) = proc.as_deref()
                && breakpoint.should_break_in(proc)
            {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Consume the [DebugExecutor], converting it into an [ExecutionTrace] at the current cycle.
    pub fn into_execution_trace(self) -> ExecutionTrace {
        ExecutionTrace {
            processor: self.stepper.into_processor(),
            outputs: self.stack_outputs,
        }
    }
}

/// The executor as its internal observer sees it before a cycle: the trackers brought up to
/// date for the cycle, and the state the previous cycle left.
pub(crate) struct Observation<'a> {
    /// The call stack, with the cycle's recovered frames.
    pub callstack: &'a CallStack,
    /// The declarations, with the cycle's.
    pub debug_vars: &'a DebugVarTracker,
    /// The processor, before the cycle.
    pub processor: &'a FastProcessor,
    /// The operand stack after the previous cycle.
    pub current_stack: &'a [Felt],
    /// The memory context after the previous cycle.
    pub current_context: ContextId,
    /// The cycle's source metadata.
    pub source: &'a SourceContext,
}

impl super::query::DebugQuery for Observation<'_> {
    fn state(&self) -> miden_processor::ProcessorState<'_> {
        self.processor.state()
    }

    fn current_context(&self) -> ContextId {
        self.current_context
    }

    fn current_clock(&self) -> RowIndex {
        self.processor.state().clock()
    }
}

/// What a step was about to run, read from the source context before the cycle and needed for
/// the state the cycle leaves behind.
struct DescribedStep {
    /// The operation the cycle executes, if it executes one.
    op: Option<Operation>,
    /// The control-flow kind of the cycle.
    control_flow_kind: Option<ControlFlowOp>,
    /// The assembly operation the cycle belongs to.
    asmop: Option<AssemblyOp>,
    /// Number of declarations observed for the cycle.
    debug_var_count: usize,
    /// The inline call frames active for the cycle, innermost first.
    inline_frames: Vec<InlineCallFrame>,
}

#[cfg(test)]
mod tests;
