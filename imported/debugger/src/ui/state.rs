use std::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Path, PathBuf},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly::{DefaultSourceManager, SourceManager};
use miden_assembly_syntax::diagnostics::Report;
use miden_debug_engine::{DebugQuery, ReturnTarget, normalize_source_path};
use miden_debug_types::{Location, SourceManagerExt, SourceSpan};
use miden_mast_package::Package;
use miden_processor::{
    Felt, LoadedMastForest, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
};

use crate::{
    config::DebuggerConfig,
    debug::{
        Breakpoint, BreakpointType, InvocationId, OperationMatcher, ReadMemoryExpr,
        ResolvedLocation, TypedProcedure,
    },
    exec::{DebugExecutor, ExecutionConfig, Executor},
};

/// Whether the debugger is debugging a plain program or a transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DebugMode {
    /// Debugging a plain MASM program loaded from a package.
    Program,
    /// Debugging a Miden transaction with pre-recorded event replay.
    Transaction,
    /// Debugging remotely via a DAP server connection.
    Remote,
}

fn clone_event_replay_queue(event_replay: &[Vec<AdviceMutation>]) -> VecDeque<Vec<AdviceMutation>> {
    event_replay
        .iter()
        .map(|batch| crate::exec::clone_advice_mutations(batch))
        .collect()
}

pub struct State {
    pub source_manager: Arc<dyn SourceManager>,
    pub config: Box<DebuggerConfig>,
    pub input_mode: InputMode,
    pub breakpoints: Vec<Breakpoint>,
    pub breakpoints_hit: Vec<Breakpoint>,
    pub next_breakpoint_id: u8,
    pub stopped: bool,
    pub debug_mode: DebugMode,
    finish_targets: BTreeMap<(u8, usize), ReturnTarget>,
    selected_stack_frame: usize,
    session: SessionState,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum InputMode {
    #[default]
    Normal,
    #[allow(dead_code)]
    Insert,
    Command,
}

/// Source location attached to a source-level debug variable declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugVariableSource {
    pub path: String,
    pub line: u32,
    pub column: u32,
}

/// Structured view of a variable visible to debugger frontends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugVariableValue {
    pub name: String,
    pub value: Option<Felt>,
    pub display_value: Option<String>,
    pub location: String,
    pub source: Option<DebugVariableSource>,
}

struct LocalState {
    executor: DebugExecutor,
    execution_failed: Option<miden_processor::ExecutionError>,
    typed_procedure: Option<TypedProcedure>,
}

#[cfg(feature = "dap")]
struct RemoteState {
    client: std::cell::RefCell<crate::exec::DapClient>,
    executor: DebugExecutor,
    addr: String,
    /// Tracks which source files have had breakpoints synced to the DAP server,
    /// so we can send empty breakpoint lists when all breakpoints for a file are removed.
    synced_bp_files: std::collections::BTreeSet<String>,
}

enum SessionState {
    Local(Box<LocalState>),
    #[cfg(feature = "dap")]
    Remote(Box<RemoteState>),
}

#[cfg(feature = "dap")]
struct RemoteSnapshot {
    callstack: crate::debug::CallStack,
    current_stack: Vec<Felt>,
    cycle: usize,
}

#[cfg(feature = "dap")]
impl RemoteState {
    fn variables(
        &self,
        index: Option<usize>,
        show_all: bool,
    ) -> Result<Vec<DebugVariableValue>, String> {
        let mut client = self.client.borrow_mut();
        let frames = client.stack_trace()?;
        let frame = match index {
            Some(index) => frames.get(index),
            None => frames.iter().find(|frame| frame.presentation_hint.is_none()),
        };
        let Some(frame) = frame else {
            return Ok(Vec::new());
        };
        Ok(client
            .frame_variables(frame.id, show_all)?
            .into_iter()
            .map(|variable| DebugVariableValue {
                name: variable.name,
                value: variable.raw.and_then(|value| Felt::new(value).ok()),
                display_value: Some(variable.value),
                location: String::new(),
                source: None,
            })
            .collect())
    }

    fn format_variables(&self, index: usize, show_all: bool) -> Result<String, String> {
        let mut client = self.client.borrow_mut();
        let frames = client.stack_trace()?;
        let Some(frame) = frames.get(index) else {
            return Ok("No debug variables tracked".into());
        };
        client.evaluate_in_frame(if show_all { "vars all" } else { "vars" }, frame.id)
    }

    fn from_client(
        addr: &str,
        mut client: crate::exec::DapClient,
        source_manager: &Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        use miden_debug_engine::{Stepper, profiling::Profiler};
        use miden_processor::FastProcessor;

        use crate::exec::DebuggerHost;

        let ui_state = client.handshake().map_err(Report::msg)?;
        let snapshot = convert_ui_state(&ui_state, source_manager);

        // The remote session shows the server's state through an executor that steps nothing
        // of its own: its stepper is finished from the start.
        let stepper = Stepper::finished(FastProcessor::new(StackInputs::default()));
        let mut executor = DebugExecutor::new(
            stepper,
            DebuggerHost::new(source_manager.clone()),
            Arc::new(Default::default()),
            Profiler::default(),
        );
        executor.current_stack = snapshot.current_stack;
        executor.callstack = snapshot.callstack;
        executor.cycle = snapshot.cycle;

        Ok(Self {
            client: std::cell::RefCell::new(client),
            executor,
            addr: addr.to_string(),
            synced_bp_files: std::collections::BTreeSet::new(),
        })
    }

    fn read_memory(&mut self, expr: &ReadMemoryExpr) -> Result<String, String> {
        self.client.get_mut().read_memory(expr)
    }

    fn sync_breakpoints(&mut self, breakpoints: &[Breakpoint]) {
        use std::collections::BTreeMap;

        // Group Line breakpoints by their file pattern string.
        let mut by_file: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        // Collect Called and File patterns as function breakpoints.
        let mut func_names: Vec<String> = Vec::new();

        for bp in breakpoints {
            match &bp.ty {
                BreakpointType::Line { pattern, line } => {
                    by_file.entry(pattern.glob().to_string()).or_default().push(*line as i64);
                }
                BreakpointType::Called(pattern) | BreakpointType::File(pattern) => {
                    func_names.push(pattern.glob().to_string());
                }
                _ => {}
            }
        }

        // Send empty breakpoint lists for files that were previously synced but no longer have
        // breakpoints.
        let stale_files: Vec<String> = self
            .synced_bp_files
            .iter()
            .filter(|f| !by_file.contains_key(f.as_str()))
            .cloned()
            .collect();
        for file in &stale_files {
            let _ = self.client.get_mut().set_breakpoints(file, &[]);
        }

        // Send breakpoints for each file.
        for (file, lines) in &by_file {
            let _ = self.client.get_mut().set_breakpoints(file, lines);
        }

        // Send function/pattern breakpoints (replaces the full set each time).
        let _ = self.client.get_mut().set_function_breakpoints(&func_names);

        // Update tracked set.
        self.synced_bp_files = by_file.into_keys().collect();
    }

    fn resume(&mut self, breakpoints: &[Breakpoint]) -> Result<crate::exec::DapStopReason, String> {
        // Sync user-defined breakpoints to the DAP server before choosing a step command.
        self.sync_breakpoints(breakpoints);

        let has_step = breakpoints.iter().any(|bp| matches!(bp.ty, BreakpointType::Step));
        let has_next = breakpoints
            .iter()
            .any(|bp| matches!(bp.ty, BreakpointType::Next | BreakpointType::NextLine));
        let has_finish = breakpoints.iter().any(|bp| matches!(bp.ty, BreakpointType::Finish));

        if has_step {
            self.client.get_mut().step_in()
        } else if has_next {
            self.client.get_mut().step_over()
        } else if has_finish {
            self.client.get_mut().step_out()
        } else {
            self.client.get_mut().continue_()
        }
    }

    fn refresh_executor(
        &mut self,
        source_manager: &Arc<dyn SourceManager>,
        pushed: &crate::exec::DapUiState,
    ) {
        // Standard DAP `stopped` events tell us execution paused, but do not
        // carry the refreshed VM state (stack, callstack, cycle). The server
        // pushes a custom `miden/uiState` event with the bundled snapshot
        // immediately before each `stopped` event, so we consume that here
        // instead of issuing an extra evaluate round-trip.
        let snapshot = convert_ui_state(pushed, source_manager);
        self.executor.current_stack = snapshot.current_stack;
        self.executor.callstack = snapshot.callstack;
        self.executor.cycle = snapshot.cycle;
    }

    fn reconnect(&mut self, source_manager: &Arc<dyn SourceManager>) -> Result<(), Report> {
        let timeout = std::time::Duration::from_secs(30);
        let mut new_client =
            crate::exec::DapClient::connect_with_retry(&self.addr, timeout).map_err(Report::msg)?;
        let ui_state = new_client.handshake().map_err(Report::msg)?;
        let snapshot = convert_ui_state(&ui_state, source_manager);

        self.client = std::cell::RefCell::new(new_client);
        self.executor.current_stack = snapshot.current_stack;
        self.executor.callstack = snapshot.callstack;
        self.executor.cycle = snapshot.cycle;
        Ok(())
    }
}

impl State {
    fn new_local(
        source_manager: Arc<dyn SourceManager>,
        config: Box<DebuggerConfig>,
        debug_mode: DebugMode,
        local: LocalState,
    ) -> Self {
        Self {
            source_manager,
            config,
            input_mode: InputMode::Normal,
            breakpoints: vec![],
            breakpoints_hit: vec![],
            next_breakpoint_id: 0,
            stopped: true,
            debug_mode,
            finish_targets: BTreeMap::new(),
            selected_stack_frame: 0,
            session: SessionState::Local(Box::new(local)),
        }
    }

    pub fn new(config: Box<DebuggerConfig>) -> Result<Self, Report> {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let local = create_local_state(&config, source_manager.clone())?;

        Ok(Self::new_local(source_manager, config, DebugMode::Program, local))
    }

    /// Create a new debugger state for transaction debugging.
    ///
    /// This uses pre-recorded event mutations to replay host events during
    /// step-by-step debugging, since the debugger's host doesn't have access
    /// to the real transaction host.
    pub fn new_for_transaction(
        package: Arc<Package>,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: miden_processor::ExecutionOptions,
        source_manager: Arc<dyn SourceManager>,
        mast_forests: Vec<LoadedMastForest>,
        event_replay: Vec<Vec<AdviceMutation>>,
    ) -> Result<Self, Report> {
        // Create debug executor with the exact recorded inputs and options.
        let executor = Executor::from_config(ExecutionConfig {
            inputs: stack_inputs,
            advice_inputs,
            options,
        });
        let debug_executor = executor.into_debug_with_replay(
            package,
            source_manager.clone(),
            mast_forests,
            clone_event_replay_queue(&event_replay),
        );

        Ok(Self::new_local(
            source_manager,
            Box::default(),
            DebugMode::Transaction,
            LocalState {
                executor: debug_executor,
                execution_failed: None,
                typed_procedure: None,
            },
        ))
    }

    pub fn reload(&mut self) -> Result<(), Report> {
        if self.debug_mode == DebugMode::Transaction {
            return Err(Report::msg("reload is not supported in transaction debug mode"));
        }
        if self.debug_mode == DebugMode::Remote {
            #[cfg(feature = "dap")]
            {
                let source_manager = self.source_manager.clone();
                let SessionState::Remote(remote) = &mut self.session else {
                    return Err(Report::msg("no remote debug session"));
                };
                let result = remote.client.get_mut().restart_phase2().map_err(Report::msg)?;
                match result {
                    crate::exec::DapStopReason::Restarting => {
                        remote.reconnect(&source_manager)?;
                    }
                    crate::exec::DapStopReason::Stopped(snapshot) => {
                        // Fallback: server treated it as Phase 1.
                        remote.refresh_executor(&source_manager, &snapshot);
                    }
                    crate::exec::DapStopReason::Terminated => {
                        return Err(Report::msg("server terminated without restart signal"));
                    }
                }
            }
            #[cfg(not(feature = "dap"))]
            return Err(Report::msg("remote debug mode requires the `dap` feature"));
        } else {
            log::debug!("reloading program");
            let local = create_local_state(&self.config, self.source_manager.clone())?;

            self.session = SessionState::Local(Box::new(local));
            let breakpoints = core::mem::take(&mut self.breakpoints);
            self.breakpoints.reserve(breakpoints.len());
            self.next_breakpoint_id = 0;
            for bp in breakpoints {
                // Drop in-flight step breakpoints (next/next-line/finish): they
                // refer to execution state (e.g. a frame flagged break-on-exit)
                // that no longer exists after a restart. Carrying one over would
                // also permanently suppress user breakpoints, since they are
                // skipped while an internal breakpoint is pending.
                if bp.is_internal() {
                    continue;
                }
                self.create_breakpoint(bp.ty);
            }
        }

        self.finish_reload();
        Ok(())
    }

    fn finish_reload(&mut self) {
        self.finish_targets.clear();
        self.executor_mut().stopped = false;
        self.selected_stack_frame = 0;
        self.breakpoints_hit.clear();
        self.stopped = true;
    }

    /// Resume local execution until the VM terminates, errors, or a breakpoint is hit.
    pub fn run_until_stopped(&mut self) {
        // Breakpoints can be deleted between resumes. Keep invocation ownership tied to the
        // original breakpoint, including its creation cycle when an identifier is reused.
        self.finish_targets.retain(|&(id, cycle), _| {
            self.breakpoints.iter().any(|bp| {
                bp.id == id && bp.creation_cycle == cycle && bp.ty == BreakpointType::Finish
            })
        });
        let start_cycle = self.executor().cycle;
        let start_asmop = self.executor().current_asmop.clone();
        let start_proc = self.current_procedure();
        let start_line_loc = self.current_display_location();
        let source_path_prefixes = self.source_path_prefixes();
        let minimum_source_line =
            start_proc.as_deref().zip(start_line_loc.as_ref()).and_then(|(proc, loc)| {
                self.minimum_source_line_for_proc(proc, loc.source_file.uri().as_str())
            });
        let mut previous_proc = self.current_procedure();
        let mut previous_source_loc = self.current_user_source_location();
        let mut previous_internal_loc = self.current_internal_source_location();
        let mut pending_called_breakpoints = Vec::new();
        let mut breakpoints = core::mem::take(&mut self.breakpoints);
        self.breakpoints_hit.clear();
        self.stopped = false;

        let stopped = loop {
            if self.executor().stopped {
                break true;
            }

            match self.executor_mut().step() {
                Ok(_) => (),
                Err(err) => {
                    self.set_execution_failed(err);
                    break true;
                }
            }

            if breakpoints.is_empty() {
                continue;
            }

            let is_op_boundary = self.executor().current_asmop.is_some();
            let user_source_loc = self.current_user_source_location();
            let internal_source_loc = self.current_internal_source_location();
            let line_loc = self.current_display_location();
            let proc = self.current_procedure();
            let current_cycle = self.executor().cycle;
            let cycles_stepped = current_cycle - start_cycle;
            let has_internal_breakpoint = breakpoints.iter().any(|bp| bp.is_internal());
            let current_op = self.executor().current_op;
            let current_asmop_str = if breakpoints
                .iter()
                .any(|bp| matches!(&bp.ty, BreakpointType::Opcode(OperationMatcher::Asm(_))))
            {
                self.executor().current_asmop.as_ref().map(|asmop| asmop.op().to_string())
            } else {
                None
            };

            breakpoints.retain_mut(|bp| {
                if bp.ty == BreakpointType::Finish {
                    let key = (bp.id, bp.creation_cycle);
                    if self
                        .finish_targets
                        .get(&key)
                        .is_some_and(|target| self.executor().has_returned(target))
                    {
                        self.finish_targets.remove(&key);
                        self.breakpoints_hit.push(core::mem::take(bp));
                        return false;
                    }
                    return true;
                }

                if let Some(n) = bp.cycles_to_skip(current_cycle) {
                    if cycles_stepped > 0 && n == 0 {
                        let retained = !bp.is_one_shot();
                        if retained {
                            self.breakpoints_hit.push(bp.clone());
                        } else {
                            self.breakpoints_hit.push(core::mem::take(bp));
                        }
                        return retained;
                    }
                    return true;
                }

                if cycles_stepped > 0
                    && is_op_boundary
                    && matches!(&bp.ty, BreakpointType::Next)
                    && self.executor().current_asmop != start_asmop
                {
                    self.breakpoints_hit.push(core::mem::take(bp));
                    return false;
                }

                if cycles_stepped > 0
                    && is_op_boundary
                    && matches!(&bp.ty, BreakpointType::NextLine)
                    && Self::is_next_source_line(
                        start_proc.as_deref(),
                        start_line_loc.as_ref(),
                        proc.as_deref(),
                        line_loc.as_ref(),
                        &source_path_prefixes,
                        minimum_source_line,
                    )
                {
                    self.breakpoints_hit.push(core::mem::take(bp));
                    return false;
                }

                if has_internal_breakpoint && !bp.is_internal() {
                    return true;
                }

                // Opcode breakpoints: raw operation matchers fire on the op just
                // executed; assembly-level matchers compare against the current
                // asmop at instruction boundaries.
                if cycles_stepped > 0
                    && (current_op
                        .is_some_and(|op| bp.should_break_for(&op, &self.executor().state()))
                        || (is_op_boundary
                            && matches!(
                                (&bp.ty, current_asmop_str.as_deref()),
                                (
                                    BreakpointType::Opcode(OperationMatcher::Asm(expected)),
                                    Some(current),
                                ) if expected == current
                            )))
                {
                    self.breakpoints_hit.push(bp.clone());
                    return true;
                }

                // Line/File breakpoints fire on the transition onto a matching
                // source position, so that a breakpoint inside a loop fires once
                // per iteration and `continue` from a stop can leave the line.
                if let Some(loc) = user_source_loc.as_ref()
                    && bp.should_break_at(loc)
                    && !previous_source_loc.as_ref().is_some_and(|prev| bp.should_break_at(prev))
                {
                    let retained = !bp.is_one_shot();
                    if retained {
                        self.breakpoints_hit.push(bp.clone());
                    } else {
                        self.breakpoints_hit.push(core::mem::take(bp));
                    }
                    return retained;
                }

                // The user-level position above intentionally skips frames executing
                // compiler-internal code, so a breakpoint that explicitly targets an internal
                // source file (e.g. a compiler intrinsic) is matched against the raw innermost
                // position instead. Intrinsics stay debuggable like any other MASM, and since
                // user source files never classify as internal, this cannot reintroduce
                // mid-statement stops for user-level breakpoints.
                if let Some(loc) = internal_source_loc.as_ref()
                    && bp.should_break_at(loc)
                    && !previous_internal_loc.as_ref().is_some_and(|prev| bp.should_break_at(prev))
                {
                    let retained = !bp.is_one_shot();
                    if retained {
                        self.breakpoints_hit.push(bp.clone());
                    } else {
                        self.breakpoints_hit.push(core::mem::take(bp));
                    }
                    return retained;
                }

                if matches!(&bp.ty, BreakpointType::Called(_))
                    && let Some(proc) = proc.as_deref()
                {
                    let matched = bp.should_break_in(proc);
                    if !matched {
                        pending_called_breakpoints.retain(|id| *id != bp.id);
                        return true;
                    }

                    let was_matched = previous_proc
                        .as_deref()
                        .is_some_and(|previous| bp.should_break_in(previous));
                    let matched_at_start =
                        start_proc.as_deref().is_some_and(|start| bp.should_break_in(start));
                    let pending = pending_called_breakpoints.contains(&bp.id);
                    let entered_matching_proc = !was_matched && !matched_at_start;

                    if entered_matching_proc
                        && self.should_defer_called_breakpoint(proc, line_loc.as_ref())
                    {
                        if !pending {
                            pending_called_breakpoints.push(bp.id);
                        }
                        return true;
                    }

                    if entered_matching_proc
                        || (pending
                            && !self.should_defer_called_breakpoint(proc, line_loc.as_ref()))
                    {
                        pending_called_breakpoints.retain(|id| *id != bp.id);
                        let retained = !bp.is_one_shot();
                        if retained {
                            self.breakpoints_hit.push(bp.clone());
                        } else {
                            self.breakpoints_hit.push(core::mem::take(bp));
                        }
                        return retained;
                    }
                }

                true
            });

            if !self.breakpoints_hit.is_empty() {
                break true;
            }

            previous_proc = proc;
            previous_source_loc = user_source_loc;
            previous_internal_loc = internal_source_loc;
        };

        self.breakpoints = breakpoints;
        self.stopped = stopped;
        self.selected_stack_frame = 0;
    }

    pub fn create_breakpoint(&mut self, ty: BreakpointType) {
        let id = self.next_breakpoint_id();
        let creation_cycle = self.executor().cycle;
        log::trace!("created breakpoint with id {id} at cycle {creation_cycle}");
        if matches!(ty, BreakpointType::Finish) && matches!(self.session, SessionState::Local(_)) {
            let target = self.executor().callstack.return_target();
            self.finish_targets.insert((id, creation_cycle), target);
        }
        self.breakpoints.push(Breakpoint {
            id,
            creation_cycle,
            ty,
        });
    }

    fn next_breakpoint_id(&mut self) -> u8 {
        let mut candidate = self.next_breakpoint_id;
        let initial = candidate;
        let mut next = candidate.wrapping_add(1);
        loop {
            assert_ne!(initial, next, "unable to allocate a breakpoint id: too many breakpoints");
            if self
                .breakpoints
                .iter()
                .chain(self.breakpoints_hit.iter())
                .any(|bp| bp.id == candidate)
            {
                candidate = next;
                next = candidate.wrapping_add(1);
                continue;
            }
            self.next_breakpoint_id = next;
            break candidate;
        }
    }

    pub fn executor(&self) -> &DebugExecutor {
        match &self.session {
            SessionState::Local(local) => &local.executor,
            #[cfg(feature = "dap")]
            SessionState::Remote(remote) => &remote.executor,
        }
    }

    pub fn executor_mut(&mut self) -> &mut DebugExecutor {
        match &mut self.session {
            SessionState::Local(local) => &mut local.executor,
            #[cfg(feature = "dap")]
            SessionState::Remote(remote) => &mut remote.executor,
        }
    }

    pub fn current_procedure(&self) -> Option<Arc<str>> {
        let live_proc = self
            .executor()
            .current_asmop
            .as_ref()
            .map(|op| op.context_name().clone())
            .or_else(|| self.executor().current_proc.clone());
        let frame_proc =
            self.executor().callstack.current_frame().and_then(|frame| frame.procedure(""));
        live_proc.or(frame_proc)
    }

    pub fn current_location(&self) -> Option<ResolvedLocation> {
        self.executor()
            .callstack
            .current_frame()
            .and_then(|frame| frame.recent().back())
            .and_then(|detail| self.resolve_op_location(detail.location()?))
    }

    pub fn current_display_location(&self) -> Option<ResolvedLocation> {
        let frame = self.executor().callstack.current_frame()?;
        for detail in frame.recent().iter().rev() {
            if let Some(location) = detail.location()
                && let Some(resolved) = self.resolve_op_location(location)
            {
                return Some(resolved);
            }
        }
        None
    }

    pub fn logical_stack_frames(&self) -> Vec<crate::debug::LogicalStackFrame> {
        self.executor().callstack.logical_frames("")
    }

    pub fn selected_stack_frame(&self) -> usize {
        self.selected_stack_frame
    }

    pub fn select_stack_frame(&mut self, index: usize) -> Result<(), String> {
        let count = self.logical_stack_frames().len();
        if index >= count {
            return Err(format!("invalid frame index {index}; backtrace has {count} frames"));
        }
        self.selected_stack_frame = index;
        Ok(())
    }

    pub fn reset_stack_selection(&mut self) {
        self.selected_stack_frame = 0;
    }

    pub fn select_older_stack_frame(&mut self) {
        let last = self.logical_stack_frames().len().saturating_sub(1);
        self.selected_stack_frame = self.selected_stack_frame.saturating_add(1).min(last);
    }

    pub fn select_newer_stack_frame(&mut self) {
        self.selected_stack_frame = self.selected_stack_frame.saturating_sub(1);
    }

    pub fn selected_display_location(&self) -> Option<ResolvedLocation> {
        self.logical_stack_frames()
            .iter()
            .rev()
            .nth(self.selected_stack_frame)
            .and_then(|frame| frame.resolved(&*self.source_manager))
    }

    /// Return the current source position as seen from the nearest non-internal
    /// (user) call frame.
    ///
    /// Excursions into compiler intrinsics do not change this position, which
    /// makes it suitable for matching source-level (line/file) breakpoints: a
    /// statement that calls into `::intrinsics::*` helpers mid-line still reads
    /// as a single visit to that line.
    fn current_user_source_location(&self) -> Option<ResolvedLocation> {
        for frame in self.executor().callstack.frames().iter().rev() {
            for detail in frame.recent().iter().rev() {
                if let Some(location) = detail.location()
                    && let Some(resolved) = self.resolve_op_location(location)
                {
                    if crate::debug::is_internal_source_uri(resolved.source_file.uri()) {
                        // This frame is executing compiler-internal code; its
                        // caller carries the user-source position.
                        break;
                    }
                    return Some(resolved);
                }
            }
        }
        None
    }

    /// The innermost resolvable source position, only when it refers to compiler-internal
    /// code (intrinsics, the Rust standard library).
    ///
    /// [Self::current_user_source_location] intentionally skips such frames so that a user
    /// statement calling into helpers reads as a single visit to its line; this accessor is the
    /// counterpart that lets breakpoints explicitly targeting internal sources keep firing —
    /// compiler intrinsics remain debuggable like any other MASM.
    fn current_internal_source_location(&self) -> Option<ResolvedLocation> {
        self.current_location()
            .filter(|loc| crate::debug::is_internal_source_uri(loc.source_file.uri()))
    }

    pub fn is_next_source_line(
        start_proc: Option<&str>,
        start_loc: Option<&ResolvedLocation>,
        current_proc: Option<&str>,
        current_loc: Option<&ResolvedLocation>,
        source_path_prefixes: &[String],
        minimum_source_line: Option<u32>,
    ) -> bool {
        let same_proc = match (start_proc, current_proc) {
            (Some(start), Some(current)) => start == current,
            (Some(_), None) => false,
            _ => true,
        };
        if !same_proc {
            return false;
        }

        if let (Some(minimum_source_line), Some(current)) = (minimum_source_line, current_loc)
            && current.line < minimum_source_line
        {
            return false;
        }

        match (start_loc, current_loc) {
            (Some(start), Some(current)) => {
                source_paths_match(
                    start.source_file.uri().as_str(),
                    current.source_file.uri().as_str(),
                    source_path_prefixes,
                ) && start.line != current.line
            }
            (None, Some(_)) => true,
            _ => false,
        }
    }

    pub(crate) fn minimum_source_line_for_proc(
        &self,
        procedure: &str,
        source_path: &str,
    ) -> Option<u32> {
        let executor = self.executor();
        let ctx = executor.resume_ctx()?;
        let mast_forest = ctx.current_forest();
        let debug_info = ctx.debug_info()?;

        let source_path_prefixes = self.source_path_prefixes();

        let mut lines = BTreeSet::<u32>::default();
        for function_info in debug_info.functions() {
            if debug_info[function_info.name_idx].as_ref() != procedure {
                continue;
            }
            let source_node_id = function_info.source_node.into_option().or_else(|| {
                mast_forest.find_procedure_root(function_info.mast_root).and_then(|exec_node| {
                    debug_info.unique_source_root_for_exec_node(exec_node).ok().flatten()
                })
            })?;
            for asm_op in debug_info[source_node_id].asm_ops.iter() {
                let Some(location_idx) = asm_op.location_idx.into_option() else {
                    continue;
                };
                let location = debug_info.get_location(location_idx).unwrap();
                let Some(resolved_location) = self.resolve_op_location(&location) else {
                    continue;
                };
                if resolved_location.line > 1
                    && source_paths_match(
                        resolved_location.source_file.uri().as_str(),
                        source_path,
                        &source_path_prefixes,
                    )
                {
                    lines.insert(resolved_location.line);
                }
            }
        }
        lines.pop_first()
    }

    pub(crate) fn source_path_prefixes(&self) -> Vec<String> {
        let mut prefixes = self
            .config
            .source_path_prefixes
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if let Ok(cwd) = std::env::current_dir() {
            let cwd = cwd.to_string_lossy().into_owned();
            if !prefixes
                .iter()
                .any(|prefix| normalize_source_path(prefix) == normalize_source_path(&cwd))
            {
                prefixes.push(cwd);
            }
        }
        prefixes
    }

    fn resolve_op_location(&self, loc: &Location) -> Option<ResolvedLocation> {
        let source_file = self.load_source_file_for_uri(loc.uri())?;
        let span = SourceSpan::new(source_file.id(), loc.start..loc.end);
        let file_line_col = source_file.location(span);
        Some(ResolvedLocation {
            source_file,
            line: file_line_col.line.to_u32(),
            col: file_line_col.column.to_u32(),
            span,
        })
    }

    fn load_source_file_for_uri(
        &self,
        uri: &miden_debug_types::Uri,
    ) -> Option<Arc<miden_debug_types::SourceFile>> {
        let uri_str = uri.as_str();
        let normalized_uri = uri_str.strip_prefix("file://").unwrap_or(uri_str);
        let path = Path::new(normalized_uri);
        if path.exists() {
            return self.source_manager.load_file(path).ok();
        }

        if let Some(source_file) = self.source_manager.get_by_uri(uri) {
            return Some(source_file);
        }

        for candidate in source_path_candidates(normalized_uri, &self.source_path_prefixes()) {
            if candidate.exists()
                && let Ok(source_file) = self.source_manager.load_file(&candidate)
            {
                return Some(source_file);
            }
        }

        None
    }

    pub fn should_defer_called_breakpoint(
        &self,
        proc: &str,
        current_loc: Option<&ResolvedLocation>,
    ) -> bool {
        let executor = self.executor();
        if executor.debug_vars.current_variables().any(|variable| {
            variable.clk == miden_processor::trace::RowIndex::from(executor.cycle as u32)
        }) {
            return false;
        }
        (!is_internal_procedure(proc)
            && current_loc
                .is_none_or(|loc| crate::debug::is_internal_source_uri(loc.source_file.uri())))
            || executor.should_wait_for_entry_variables(proc)
    }

    pub fn execution_failed(&self) -> Option<&miden_processor::ExecutionError> {
        match &self.session {
            SessionState::Local(local) => local.execution_failed.as_ref(),
            #[cfg(feature = "dap")]
            SessionState::Remote(_) => None,
        }
    }

    fn execution_completed(&self) -> bool {
        self.executor().stopped && self.execution_failed().is_none()
    }

    /// Decode the completed program's result using its component-model entrypoint signature.
    pub fn typed_result(&self) -> Result<Option<String>, String> {
        if !self.execution_completed() {
            return Ok(None);
        }
        let local = match &self.session {
            SessionState::Local(local) => local,
            #[cfg(feature = "dap")]
            SessionState::Remote(_) => return Ok(None),
        };
        let Some(procedure) = local.typed_procedure.as_ref() else {
            return Ok(None);
        };

        procedure
            .decode_result(local.executor.stack_outputs.get_num_elements(16))
            .map_err(|err| format!("failed to decode program result: {err}"))
    }

    pub fn set_execution_failed(&mut self, error: miden_processor::ExecutionError) {
        match &mut self.session {
            SessionState::Local(local) => local.execution_failed = Some(error),
            #[cfg(feature = "dap")]
            SessionState::Remote(_) => {
                panic!("cannot record local execution failure while in remote mode")
            }
        }
    }
}

macro_rules! write_with_format_type {
    ($out:ident, $read_expr:ident, $value:expr) => {
        match $read_expr.format {
            crate::debug::FormatType::Decimal => write!(&mut $out, "{}", $value).unwrap(),
            crate::debug::FormatType::Hex => write!(&mut $out, "{:#x}", $value).unwrap(),
            crate::debug::FormatType::Binary => write!(&mut $out, "{:#b}", $value).unwrap(),
        }
    };
}

impl State {
    pub fn read_memory(&mut self, expr: &ReadMemoryExpr) -> Result<String, String> {
        use core::fmt::Write;

        use miden_assembly_syntax::ast::types::Type;

        use crate::debug::FormatType;

        #[cfg(feature = "dap")]
        if self.debug_mode == DebugMode::Remote {
            let SessionState::Remote(remote) = &mut self.session else {
                return Err("no remote debug session".into());
            };
            return remote.read_memory(expr);
        }

        #[cfg(not(feature = "dap"))]
        if self.debug_mode == DebugMode::Remote {
            return Err("remote debug mode requires the `dap` feature".into());
        }

        let executor = self.executor();
        let cycle = miden_processor::trace::RowIndex::from(executor.cycle);
        let context = executor.current_context;
        let memory = executor.processor().memory();
        let read_element = |addr: u32| -> Option<Felt> {
            memory
                .read_element(context, Felt::new(addr as u64).expect("value exceeds field modulus"))
                .ok()
        };
        let mut output = String::new();
        if expr.count > 1 {
            return Err("-count with value > 1 is not yet implemented".into());
        } else if matches!(expr.ty, Type::Felt) {
            if !expr.addr.is_element_aligned() {
                return Err(
                    "read failed: type 'felt' must be aligned to an element boundary".into()
                );
            }
            let felt = read_element(expr.addr.addr).unwrap_or(Felt::ZERO);
            write_with_format_type!(output, expr, felt.as_canonical_u64());
        } else if matches!(
            expr.ty,
            Type::Array(ref array_ty) if array_ty.element_type() == &Type::Felt && array_ty.len() == 4
        ) {
            if !expr.addr.is_word_aligned() {
                return Err("read failed: type 'word' must be aligned to a word boundary".into());
            }
            let word = memory
                .read_word(
                    context,
                    Felt::new(expr.addr.addr as u64).expect("value exceeds field modulus"),
                    cycle,
                )
                .unwrap_or_default();
            output.push('[');
            for (i, elem) in word.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                write_with_format_type!(output, expr, elem.as_canonical_u64());
            }
            output.push(']');
        } else {
            if !expr.addr.is_element_aligned() {
                return Err("invalid read: unaligned reads are not supported yet".into());
            }

            const U32_MASK: u64 = u32::MAX as u64;
            let size = expr.ty.size_in_bytes();
            let size_in_felts = expr.ty.size_in_felts();
            let mut bytes = Vec::with_capacity(size);
            let mut needed = size;
            for i in 0..size_in_felts {
                let addr = expr.addr.addr.checked_add(i as u32).ok_or_else(|| {
                    "invalid read: attempted to read beyond end of linear memory".to_string()
                })?;
                let elem = read_element(addr).unwrap_or_default();
                let elem_bytes = ((elem.as_canonical_u64() & U32_MASK) as u32).to_le_bytes();
                let take = core::cmp::min(needed, 4);
                bytes.extend(&elem_bytes[..take]);
                needed -= take;
            }

            match &expr.ty {
                Type::I1 => match expr.format {
                    FormatType::Decimal => write!(&mut output, "{}", bytes[0] != 0).unwrap(),
                    FormatType::Hex => {
                        write!(&mut output, "{:#0x}", (bytes[0] != 0) as u8).unwrap()
                    }
                    FormatType::Binary => {
                        write!(&mut output, "{:#0b}", (bytes[0] != 0) as u8).unwrap()
                    }
                },
                Type::I8 => write_with_format_type!(output, expr, bytes[0] as i8),
                Type::U8 => write_with_format_type!(output, expr, bytes[0]),
                Type::I16 => {
                    write_with_format_type!(output, expr, i16::from_le_bytes([bytes[0], bytes[1]]))
                }
                Type::U16 => {
                    write_with_format_type!(output, expr, u16::from_le_bytes([bytes[0], bytes[1]]))
                }
                Type::I32 => write_with_format_type!(
                    output,
                    expr,
                    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                ),
                Type::U32 => write_with_format_type!(
                    output,
                    expr,
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                ),
                ty @ (Type::I64 | Type::U64) => {
                    let val = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                    if matches!(ty, Type::I64) {
                        write_with_format_type!(output, expr, val as i64)
                    } else {
                        write_with_format_type!(output, expr, val)
                    }
                }
                ty => {
                    return Err(format!(
                        "support for reads of type '{ty}' are not implemented yet"
                    ));
                }
            }
        }

        Ok(output)
    }

    /// Variables of the executing invocation, independently of the selected display frame.
    /// Successful completion has no live variables; failures retain inspectable state.
    pub fn current_variables(&self, show_all: bool) -> Vec<DebugVariableValue> {
        if self.execution_completed() {
            return Vec::new();
        }
        #[cfg(feature = "dap")]
        if let SessionState::Remote(remote) = &self.session {
            return remote.variables(None, show_all).unwrap_or_default();
        }
        let Some(invocation) = self.executor().debug_vars.current_invocation() else {
            return Vec::new();
        };
        let location = self.current_display_location();
        self.invocation_variables(invocation, location.as_ref(), show_all)
    }

    /// Variables owned by the physical invocation at a top-first logical stack index.
    /// Inline and unrecovered frames have no separately inspectable locals in this pass.
    pub fn variables_for_frame(&self, index: usize, show_all: bool) -> Vec<DebugVariableValue> {
        if self.execution_completed() {
            return Vec::new();
        }
        #[cfg(feature = "dap")]
        if let SessionState::Remote(remote) = &self.session {
            return remote.variables(Some(index), show_all).unwrap_or_default();
        }
        let frames = self.logical_stack_frames();
        let Some(frame) = frames.iter().rev().nth(index) else {
            return Vec::new();
        };
        let Some(invocation) = frame.invocation_id() else {
            return Vec::new();
        };
        let location = frame.resolved(&*self.source_manager);
        self.invocation_variables(invocation, location.as_ref(), show_all)
    }

    fn invocation_variables(
        &self,
        invocation: InvocationId,
        source_location: Option<&ResolvedLocation>,
        show_all: bool,
    ) -> Vec<DebugVariableValue> {
        let executor = self.executor();
        let tracker = &executor.debug_vars;
        let source_path_prefixes = self.source_path_prefixes();
        tracker
            .variables_for(invocation)
            .filter_map(|snapshot| {
                let name = snapshot.info.name();
                if !show_all && is_compiler_generated_name(name) {
                    return None;
                }
                if !show_all
                    && let (Some(current), Some(var_loc)) =
                        (source_location, snapshot.info.location())
                    && let Some(var_loc) = self.resolve_op_location(var_loc)
                    && !source_var_location_is_visible(
                        var_loc.source_file.uri().as_str(),
                        var_loc.line,
                        current.source_file.uri().as_str(),
                        current.line,
                        &source_path_prefixes,
                    )
                {
                    return None;
                }
                let resolved = tracker.resolve(invocation, name, executor.processor())?;
                let source = snapshot.info.location().and_then(|loc| {
                    let loc = self.resolve_op_location(loc)?;
                    Some(DebugVariableSource {
                        path: loc.source_file.uri().as_str().to_string(),
                        line: loc.line,
                        column: loc.col,
                    })
                });
                Some(DebugVariableValue {
                    name: name.to_string(),
                    value: resolved.raw,
                    display_value: Some(resolved.value),
                    location: snapshot.info.value_location().to_string(),
                    source,
                })
            })
            .collect()
    }

    /// Format the selected frame's variables for display.
    ///
    /// When `show_all` is false, compiler-generated locals (named `local0`, `local1`, etc.)
    /// are hidden. Use `show_all` = true (`:vars all`) to include them.
    pub fn format_variables(&self, show_all: bool) -> String {
        use core::fmt::Write;

        if self.execution_completed() {
            return "Program has terminated; no live variables".to_string();
        }

        let frames = self.logical_stack_frames();
        if frames
            .iter()
            .rev()
            .nth(self.selected_stack_frame)
            .is_some_and(|frame| frame.kind() == crate::debug::LogicalFrameKind::Inline)
        {
            return "Locals are unavailable for inline frames".to_string();
        }
        #[cfg(feature = "dap")]
        if let SessionState::Remote(remote) = &self.session {
            return remote
                .format_variables(self.selected_stack_frame, show_all)
                .unwrap_or_else(|err| format!("Unable to inspect locals: {err}"));
        }
        if self.variables_for_frame(self.selected_stack_frame, true).is_empty() {
            return "No debug variables tracked".to_string();
        }
        let variables = self.variables_for_frame(self.selected_stack_frame, show_all);
        if variables.is_empty() {
            "No source-level variables (use ':vars all' to show compiler locals)".to_string()
        } else {
            let mut output = String::new();
            for variable in variables {
                if !output.is_empty() {
                    output.push_str(", ");
                }

                if let Some(value) = variable.display_value {
                    write!(&mut output, "{}={value}", variable.name).unwrap();
                    continue;
                }

                match variable.value {
                    Some(felt) => {
                        write!(&mut output, "{}={}", variable.name, felt.as_canonical_u64())
                            .unwrap();
                    }
                    None => {
                        write!(&mut output, "{}={}", variable.name, variable.location).unwrap();
                    }
                }
            }
            output
        }
    }
}

fn is_internal_procedure(proc: &str) -> bool {
    proc.contains("::intrinsics::")
}

/// Returns true if the variable name looks compiler-generated (e.g. "local0", "local12").
/// Source-level variables have DWARF-derived names like "a", "sum", "_info".
fn is_compiler_generated_name(name: &str) -> bool {
    name.strip_prefix("local")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
}

fn source_var_location_is_visible(
    var_path: &str,
    var_line: u32,
    current_path: &str,
    current_line: u32,
    source_path_prefixes: &[String],
) -> bool {
    source_paths_match(var_path, current_path, source_path_prefixes) && var_line < current_line
}

fn strip_source_prefix(path: &str, prefix: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let prefix = prefix.trim_start_matches('/').trim_end_matches('/');
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(ToOwned::to_owned)
}

fn source_paths_match(left: &str, right: &str, trim_prefixes: &[String]) -> bool {
    let left = normalize_source_path(left);
    let right = normalize_source_path(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }

    if left == right {
        return true;
    }

    for prefix in trim_prefixes {
        if strip_source_prefix(&left, prefix).is_some_and(|stripped| stripped == right) {
            return true;
        }
        if strip_source_prefix(&right, prefix).is_some_and(|stripped| stripped == left) {
            return true;
        }
    }

    false
}

fn source_path_candidates(uri: &str, source_path_prefixes: &[String]) -> Vec<PathBuf> {
    let normalized = normalize_source_path(uri);
    if normalized.is_empty() || Path::new(&normalized).is_absolute() {
        return Vec::new();
    }

    source_path_prefixes
        .iter()
        .map(|prefix| Path::new(prefix).join(&normalized))
        .collect()
}

// DAP CLIENT MODE
// ================================================================================================

#[cfg(feature = "dap")]
impl State {
    /// Create a new debugger state for remote DAP debugging.
    ///
    /// Connects to a DAP server, performs the handshake, and queries the
    /// initial state to populate the executor fields that the TUI panes read.
    pub fn new_for_dap(addr: &str) -> Result<Self, Report> {
        let client = crate::exec::DapClient::connect(addr).map_err(Report::msg)?;
        Self::from_dap_client(addr, client)
    }

    pub(crate) fn from_dap_client(
        addr: &str,
        client: crate::exec::DapClient,
    ) -> Result<Self, Report> {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let remote = RemoteState::from_client(addr, client, &source_manager)?;

        Ok(Self {
            source_manager,
            config: Box::default(),
            input_mode: InputMode::Normal,
            breakpoints: vec![],
            breakpoints_hit: vec![],
            next_breakpoint_id: 0,
            stopped: true,
            debug_mode: DebugMode::Remote,
            finish_targets: BTreeMap::new(),
            selected_stack_frame: 0,
            session: SessionState::Remote(Box::new(remote)),
        })
    }

    pub fn step_remote(&mut self) -> Result<crate::exec::DapStopReason, Report> {
        let source_manager = self.source_manager.clone();
        let SessionState::Remote(remote) = &mut self.session else {
            return Err(Report::msg("no remote debug session"));
        };
        let result = remote.resume(&self.breakpoints).map_err(Report::msg)?;

        self.breakpoints.retain(|bp| !bp.is_one_shot());

        match &result {
            crate::exec::DapStopReason::Stopped(snapshot) => {
                remote.refresh_executor(&source_manager, snapshot);
                self.selected_stack_frame = 0;
                self.stopped = true;
            }
            crate::exec::DapStopReason::Terminated => {
                remote.executor.stopped = true;
                self.stopped = true;
            }
            crate::exec::DapStopReason::Restarting => {
                return Err(Report::msg("unexpected Phase 2 restart signal during step"));
            }
        }

        Ok(result)
    }
}

/// Convert a server-pushed [`DapUiState`](crate::exec::DapUiState) snapshot into a
/// [`RemoteSnapshot`] that the TUI executor can consume.
#[cfg(feature = "dap")]
fn convert_ui_state(
    snapshot: &crate::exec::DapUiState,
    source_manager: &Arc<dyn SourceManager>,
) -> RemoteSnapshot {
    use crate::debug::{CallFrame, CallStack};

    let call_frames: Vec<CallFrame> = snapshot
        .callstack
        .iter()
        .rev()
        .map(|frame| {
            let resolved = resolve_remote_frame(frame, source_manager);
            CallFrame::from_remote(Some(frame.name.clone()), resolved)
        })
        .collect();

    let current_stack = snapshot
        .current_stack
        .iter()
        .copied()
        .map(|v| Felt::new(v).expect("value exceeds field modulus"))
        .collect();

    RemoteSnapshot {
        callstack: CallStack::from_remote_frames(call_frames),
        current_stack,
        cycle: snapshot.cycle,
    }
}

/// Resolve a remote frame to a [ResolvedLocation] by loading the source file from disk.
#[cfg(feature = "dap")]
fn resolve_remote_frame(
    frame: &crate::exec::DapUiFrame,
    source_manager: &Arc<dyn SourceManager>,
) -> Option<crate::debug::ResolvedLocation> {
    use std::path::Path;

    use miden_debug_types::{SourceManagerExt, SourceSpan, Uri};

    let path_str = frame.source_path.as_ref()?;
    let path = crate::debug::resolve_source_path(&Uri::new(path_str))
        .unwrap_or_else(|| Path::new(path_str).to_path_buf());
    let source_file = source_manager.load_file(&path).ok()?;
    let line = frame.line.max(1) as u32;
    let col = frame.column.max(1) as u32;

    // Compute a span from the line number — use the byte range of the line
    let content = source_file.content();
    let line_index = miden_debug_types::LineIndex::from(line.saturating_sub(1));
    let range = content.line_range(line_index)?;
    let span = SourceSpan::new(source_file.id(), range);

    Some(crate::debug::ResolvedLocation {
        source_file,
        line,
        col,
        span,
    })
}

fn create_local_state(
    config: &DebuggerConfig,
    source_manager: Arc<dyn SourceManager>,
) -> Result<LocalState, Report> {
    let loaded = crate::program_loader::load_debug_executor(config, source_manager, "state")?;
    Ok(LocalState {
        executor: loaded.executor,
        execution_failed: None,
        typed_procedure: loaded.typed_procedure,
    })
}

#[cfg(test)]
mod tests;
