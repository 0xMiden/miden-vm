use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    eprintln,
    io::{BufReader, BufWriter},
    net::TcpListener,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use dap::prelude::*;
#[cfg(test)]
use miden_assembly_syntax::ast::{DebugVarInfo, DebugVarLocation};
use miden_core::{Word, operations::AssemblyOp};
use miden_debug_types::{Location, Uri};
use miden_mast_package::{
    MastForest, Package,
    debug_info::{DebugFileIdx, PackageDebugInfo},
};
use miden_processor::{
    BaseHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, FutureMaybeSend,
    Host, LoadedMastForest, ProcessorState, ResumeContext, StackInputs, StackOutputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, TraceError},
    trace::RowIndex,
};

use super::{
    EventMutationRecorder, MastForestRecorder, RecordingHost, ReplaySnapshot,
    ReplaySnapshotRecorder, ReplaySnapshotWrite, poll_immediately, source::SourceContext,
    state::should_wait_for_entry_variables,
};
use crate::{
    debug::{
        DebugVarSnapshot, DebugVarTracker, FormatType, InvocationId, LogicalFrameKind,
        ReadMemoryExpr, RecoveredCallStack, procedure_matches, procedure_pattern,
    },
    normalize_source_path,
};

// DAP CONFIG
// ================================================================================================

static DAP_CONFIG: OnceLock<DapConfig> = OnceLock::new();

/// Configuration for the DAP debug server.
#[derive(Clone, Debug)]
pub struct DapConfig {
    /// The address to listen on, e.g. "127.0.0.1:4711".
    pub listen_addr: String,
    /// Source path prefixes passed from the compiler/debug plugin. If debug info
    /// stores paths after `-Ztrim-path-prefix`, clients may still send absolute
    /// editor paths; these prefixes describe that explicit mapping.
    source_path_prefixes: Vec<String>,
    /// Shared flag: set by the server when a Phase 2 restart (terminate-and-reconnect) is
    /// requested, read by the caller to decide whether to recompile and re-enter.
    restart_requested: Arc<AtomicBool>,
    /// When set, the advice mutations produced by the host's event handlers are recorded into
    /// this shared log during the session. See [DapConfig::record_event_mutations].
    event_recorder: Option<EventMutationRecorder>,
    /// When set, a [ReplaySnapshot] of the session is written to this path once execution
    /// completes. See [DapConfig::record_snapshot].
    snapshot_path: Option<PathBuf>,
    /// Shared status for the configured replay snapshot write.
    snapshot_recorder: Option<ReplaySnapshotRecorder>,
}

impl DapConfig {
    pub fn new(listen_addr: impl Into<String>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            source_path_prefixes: Vec::new(),
            restart_requested: Arc::new(AtomicBool::new(false)),
            event_recorder: None,
            snapshot_path: None,
            snapshot_recorder: None,
        }
    }

    pub fn with_source_path_prefixes(mut self, prefixes: Vec<PathBuf>) -> Self {
        self.source_path_prefixes = prefixes
            .into_iter()
            .map(|prefix| normalize_source_path(&prefix.to_string_lossy()))
            .filter(|prefix| !prefix.is_empty())
            .collect();
        self
    }

    /// Record the advice mutations produced by the host's event handlers during the session.
    ///
    /// Returns a shared handle that outlives the executor: the [DapExecutor] is constructed
    /// internally (e.g. by a transaction executor) from the global configuration and consumed
    /// by execution, so the handle obtained here — by whoever installs the configuration via
    /// [DapConfig::set_global] — is how the recorded log is read once execution returns.
    ///
    /// One entry is recorded per `on_event` invocation, in execution order, including empty
    /// mutation sets. The log always describes the final run (it is cleared whenever the
    /// session restarts execution from the beginning) and can be fed into an event-replay
    /// debugging session (e.g. `Executor::into_debug_with_replay` or
    /// `State::new_for_transaction`) to re-execute the same program without the original
    /// host's event handlers.
    pub fn record_event_mutations(&mut self) -> EventMutationRecorder {
        self.event_recorder.get_or_insert_with(EventMutationRecorder::new).clone()
    }

    /// Write a [ReplaySnapshot] of the session to `path` once execution completes.
    ///
    /// The snapshot captures the program, its stack and advice inputs, the MAST forests the host
    /// resolved, and the recorded event log — everything an event-replay debugging session needs
    /// to re-execute the same program later without the original host (e.g.
    /// `miden-debug --replay <path>`). It always describes the final run, since the recorded state
    /// is reset whenever the session restarts execution from the beginning.
    pub fn record_snapshot(&mut self, path: impl Into<PathBuf>) -> ReplaySnapshotRecorder {
        self.snapshot_path = Some(path.into());
        self.snapshot_recorder.get_or_insert_with(ReplaySnapshotRecorder::new).clone()
    }

    /// Returns `true` if the server has signalled a Phase 2 restart.
    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::Acquire)
    }

    /// Clear the restart flag (called by the caller after acting on it).
    pub fn reset_restart(&self) {
        self.restart_requested.store(false, Ordering::Release);
    }

    /// Set the global DAP configuration. Must be called before `execute_transaction()`.
    ///
    /// Only the first call takes effect; subsequent calls are ignored.
    pub fn set_global(config: DapConfig) {
        DAP_CONFIG.set(config).ok();
    }
}

impl Default for DapConfig {
    fn default() -> Self {
        Self::new("127.0.0.1:4711")
    }
}

// DAP HOST WRAPPER
// ================================================================================================

/// A single frame in the DAP call stack.
#[derive(Debug, Clone)]
struct DapCallFrame {
    name: Arc<str>,
    source_path: Option<String>,
    line: i64,
    column: i64,
    inline_frames: Vec<DapInlineFrame>,
}

#[derive(Debug, Clone)]
struct DapInlineFrame {
    name: String,
    source_path: Option<String>,
    line: i64,
    column: i64,
}

#[derive(Debug, Clone)]
struct DapPresentedFrame {
    name: Arc<str>,
    source_path: Option<String>,
    line: i64,
    column: i64,
    inline: bool,
    invocation: Option<InvocationId>,
}

/// Tracks recovered frames and event-based fallback frames while forwarding host operations.
/// Event handling also records advice mutations and loaded forests for execution replay.
struct DapHostWrapper<'a, H> {
    inner: RecordingHost<'a, H>,
    call_depth: usize,
    frames: Vec<DapCallFrame>,
    recovered: RecoveredCallStack,
}

impl<'a, H> DapHostWrapper<'a, H> {
    fn new(
        inner: &'a mut H,
        event_recorder: Option<EventMutationRecorder>,
        forest_recorder: Option<MastForestRecorder>,
    ) -> Self {
        Self {
            inner: RecordingHost::new(inner, event_recorder, forest_recorder),
            call_depth: 0,
            frames: Vec::new(),
            recovered: RecoveredCallStack::default(),
        }
    }
}

impl<H: Host> BaseHost for DapHostWrapper<'_, H> {
    fn get_label_and_source_file(
        &self,
        location: &miden_debug_types::Location,
    ) -> (miden_debug_types::SourceSpan, Option<Arc<miden_debug_types::SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }

    fn resolve_event(
        &self,
        event_id: miden_core::events::EventId,
    ) -> Option<&miden_core::events::EventName> {
        self.inner.resolve_event(event_id)
    }

    fn resolve_trace(
        &self,
        trace_id: miden_core::events::EventId,
    ) -> Option<&miden_core::events::EventName> {
        self.inner.resolve_trace(trace_id)
    }
}

impl<H: Host> Host for DapHostWrapper<'_, H> {
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
        use miden_core::events::EventId;
        match crate::Event::from(EventId::from_felt(process.get_stack_item(0))) {
            crate::Event::FrameStart => {
                self.call_depth += 1;
                self.frames.push(DapCallFrame {
                    name: Arc::default(),
                    source_path: None,
                    line: 0,
                    column: 0,
                    inline_frames: Vec::new(),
                });
            }
            crate::Event::FrameEnd => {
                self.call_depth = self.call_depth.saturating_sub(1);
                self.frames.pop();
            }
            _ => (),
        }
        self.inner.on_event(process)
    }

    fn on_trace(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        self.inner.on_trace(process)
    }
}

macro_rules! write_with_format_type {
    ($out:ident, $read_expr:ident, $value:expr) => {
        match $read_expr.format {
            FormatType::Decimal => write!(&mut $out, "{}", $value).unwrap(),
            FormatType::Hex => write!(&mut $out, "{:#x}", $value).unwrap(),
            FormatType::Binary => write!(&mut $out, "{:#b}", $value).unwrap(),
        }
    };
}

fn read_memory_at_current_state(
    processor: &mut FastProcessor,
    cycle: usize,
    expr: &ReadMemoryExpr,
) -> Result<String, String> {
    use core::fmt::Write;

    use miden_assembly_syntax::ast::types::Type;

    if expr.count > 1 {
        return Err("-count with value > 1 is not yet implemented".into());
    }

    let cycle = RowIndex::from(u32::try_from(cycle).map_err(|_| "cycle value overflowed u32")?);
    let ctx = processor.state().ctx();
    let mut output = String::new();

    if matches!(expr.ty, Type::Felt) {
        if !expr.addr.is_element_aligned() {
            return Err("read failed: type 'felt' must be aligned to an element boundary".into());
        }

        let felt = processor
            .memory()
            .read_element(
                ctx,
                miden_processor::Felt::new(u64::from(expr.addr.addr))
                    .expect("value exceeds field modulus"),
            )
            .ok()
            .unwrap_or(miden_processor::Felt::ZERO);
        write_with_format_type!(output, expr, felt.as_canonical_u64());
        return Ok(output);
    }

    if matches!(
        expr.ty,
        Type::Array(ref array_ty) if array_ty.element_type() == &Type::Felt && array_ty.len() == 4
    ) {
        if !expr.addr.is_word_aligned() {
            return Err("read failed: type 'word' must be aligned to a word boundary".into());
        }

        let word = processor
            .memory()
            .read_word(
                ctx,
                miden_processor::Felt::new(u64::from(expr.addr.addr))
                    .expect("value exceeds field modulus"),
                cycle,
            )
            .ok()
            .unwrap_or_default();

        output.push('[');
        for (i, elem) in word.iter().enumerate() {
            if i > 0 {
                output.push_str(", ");
            }
            write_with_format_type!(output, expr, elem.as_canonical_u64());
        }
        output.push(']');
        return Ok(output);
    }

    if !expr.addr.is_element_aligned() {
        return Err("invalid read: unaligned reads are not supported yet".into());
    }

    let mut elems = Vec::with_capacity(expr.ty.size_in_felts());
    for i in 0..expr.ty.size_in_felts() {
        let addr = expr
            .addr
            .addr
            .checked_add(u32::try_from(i).map_err(|_| "address overflow")?)
            .ok_or_else(|| {
                "invalid read: attempted to read beyond end of linear memory".to_string()
            })?;
        let felt = processor
            .memory()
            .read_element(
                ctx,
                miden_processor::Felt::new(u64::from(addr)).expect("value exceeds field modulus"),
            )
            .ok()
            .unwrap_or_default();
        elems.push(felt);
    }

    let mut bytes = Vec::with_capacity(expr.ty.size_in_bytes());
    let mut needed = expr.ty.size_in_bytes();
    for elem in elems {
        let elem_bytes = super::query::felt_to_le_bytes(elem);
        let take = core::cmp::min(needed, 4);
        bytes.extend(&elem_bytes[..take]);
        needed -= take;
    }

    match &expr.ty {
        Type::I1 => match expr.format {
            FormatType::Decimal => write!(&mut output, "{}", bytes[0] != 0).unwrap(),
            FormatType::Hex => write!(&mut output, "{:#0x}", (bytes[0] != 0) as u8).unwrap(),
            FormatType::Binary => write!(&mut output, "{:#0b}", (bytes[0] != 0) as u8).unwrap(),
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
                write_with_format_type!(output, expr, val as i64);
            } else {
                write_with_format_type!(output, expr, val);
            }
        }
        ty => return Err(format!("support for reads of type '{ty}' are not implemented yet")),
    }

    Ok(output)
}

fn build_ui_state<H: Host>(
    processor: &mut FastProcessor,
    host: &DapHostWrapper<'_, H>,
    current_asmop: Option<&AssemblyOp>,
    cycle: usize,
) -> crate::exec::DapUiState {
    let callstack = presented_frames(host, current_asmop, cycle)
        .into_iter()
        .map(|frame| crate::exec::DapUiFrame {
            name: frame.name,
            source_path: frame.source_path,
            line: frame.line,
            column: frame.column,
            inline: frame.inline,
        })
        .collect();

    let current_stack = processor
        .state()
        .get_stack_state()
        .iter()
        .map(|felt| felt.as_canonical_u64())
        .collect();

    crate::exec::DapUiState {
        cycle,
        current_stack,
        callstack,
    }
}

fn presented_frames<H: Host>(
    host: &DapHostWrapper<'_, H>,
    current_asmop: Option<&AssemblyOp>,
    cycle: usize,
) -> Vec<DapPresentedFrame> {
    if host.recovered.has_current_frame() {
        return host
            .recovered
            .logical_frames("")
            .into_iter()
            .rev()
            .map(|frame| {
                let (source_path, line, column) = frame
                    .assembly_location()
                    .and_then(|location| resolve_location_with_column(location, host))
                    .map_or((None, 0, 0), |(path, line, column)| (Some(path), line, column));
                DapPresentedFrame {
                    name: Arc::from(frame.display_name()),
                    source_path,
                    line,
                    column,
                    inline: frame.kind() == LogicalFrameKind::Inline,
                    invocation: frame.invocation_id(),
                }
            })
            .collect();
    }
    if host.frames.is_empty() {
        let (name, source_path, line, column) = match current_asmop {
            Some(asmop) => {
                let loc = resolve_asmop_location_with_column(asmop, host);
                let (source_path, line, column) =
                    loc.map_or((None, 0, 0), |(path, line, column)| (Some(path), line, column));
                (asmop.context_name().clone(), source_path, line, column)
            }
            None => (Arc::from(format!("cycle {cycle}")), None, 0, 0),
        };
        return vec![DapPresentedFrame {
            name,
            source_path,
            line,
            column,
            inline: false,
            invocation: None,
        }];
    }

    present_recorded_frames(&host.frames)
}

fn present_recorded_frames(frames: &[DapCallFrame]) -> Vec<DapPresentedFrame> {
    let mut presented = Vec::new();
    for frame in frames.iter().rev() {
        for (inline_index, inline) in frame.inline_frames.iter().enumerate() {
            let (source_path, line, column) = if inline_index == 0 {
                (frame.source_path.clone(), frame.line, frame.column)
            } else {
                let call_site = &frame.inline_frames[inline_index - 1];
                (call_site.source_path.clone(), call_site.line, call_site.column)
            };
            presented.push(DapPresentedFrame {
                name: Arc::from(format!("[inlined] {}", inline.name)),
                source_path,
                line,
                column,
                inline: true,
                invocation: None,
            });
        }

        let (source_path, line, column) = frame.inline_frames.last().map_or_else(
            || (frame.source_path.clone(), frame.line, frame.column),
            |inline| (inline.source_path.clone(), inline.line, inline.column),
        );
        presented.push(DapPresentedFrame {
            name: frame.name.clone(),
            source_path,
            line,
            column,
            inline: false,
            invocation: None,
        });
    }

    presented
}

// BREAKPOINT STORAGE
// ================================================================================================

/// A source breakpoint stored from a SetBreakpoints request.
#[derive(Debug, Clone)]
struct StoredBreakpoint {
    id: i64,
    /// The source file path as sent by the client.
    path: String,
    /// 1-indexed line number.
    requested_line: i64,
    line: Option<i64>,
}

impl StoredBreakpoint {
    fn as_dap(&self) -> types::Breakpoint {
        types::Breakpoint {
            id: Some(self.id),
            verified: self.line.is_some(),
            message: match self.line {
                Some(line) if line != self.requested_line => {
                    Some(format!("Moved to executable line {line}."))
                }
                Some(_) => None,
                None => Some(
                    "Pending until executable debug information for this source is loaded.".into(),
                ),
            },
            line: Some(self.line.unwrap_or(self.requested_line)),
            source: Some(types::Source {
                path: Some(self.path.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Default)]
struct SourceBreakpoints {
    entries: Vec<StoredBreakpoint>,
    packages: BTreeMap<usize, Arc<PackageDebugInfo>>,
    updates: Vec<events::BreakpointEventBody>,
    prefixes: Vec<String>,
    next_id: i64,
}

impl SourceBreakpoints {
    fn executable_lines<H: Host>(&self, path: &str, host: &H) -> BTreeSet<i64> {
        self.packages
            .values()
            .flat_map(|info| breakable_source_lines(info, host, path, &self.prefixes))
            .collect()
    }

    fn send_updates<R: std::io::Read, W: std::io::Write>(&mut self, server: &mut Server<R, W>) {
        for update in self.updates.drain(..) {
            server.send_event(Event::Breakpoint(update)).ok();
        }
    }

    fn observe<H: Host>(&mut self, info: Arc<PackageDebugInfo>, host: &H) {
        let key = Arc::as_ptr(&info) as usize;
        let Entry::Vacant(entry) = self.packages.entry(key) else {
            return;
        };
        entry.insert(info);
        let mut lines_by_source = BTreeMap::new();
        for breakpoint in &self.entries {
            lines_by_source
                .entry(breakpoint.path.clone())
                .or_insert_with(|| self.executable_lines(&breakpoint.path, host));
        }
        for breakpoint in &mut self.entries {
            let line = resolve_breakpoint_line(
                &lines_by_source[&breakpoint.path],
                breakpoint.requested_line,
            );
            if breakpoint.line != line {
                breakpoint.line = line;
                self.updates.push(events::BreakpointEventBody {
                    reason: types::BreakpointEventReason::Changed,
                    breakpoint: breakpoint.as_dap(),
                });
            }
        }
    }

    fn replace<H: Host>(
        &mut self,
        path: &str,
        requested: &[types::SourceBreakpoint],
        host: &H,
    ) -> Vec<types::Breakpoint> {
        self.entries
            .retain(|breakpoint| !source_paths_match(&breakpoint.path, path, &self.prefixes));
        let lines = self.executable_lines(path, host);
        requested
            .iter()
            .map(|request| {
                self.next_id += 1;
                let breakpoint = StoredBreakpoint {
                    id: self.next_id,
                    path: path.into(),
                    requested_line: request.line,
                    line: (request.line > 0)
                        .then(|| resolve_breakpoint_line(&lines, request.line))
                        .flatten(),
                };
                let mut response = breakpoint.as_dap();
                if request.line <= 0 || path.is_empty() {
                    response.verified = false;
                    response.message =
                        Some("A source path and a positive line number are required.".into());
                } else {
                    self.entries.push(breakpoint);
                }
                response
            })
            .collect()
    }
}

/// A function/pattern breakpoint stored from a SetFunctionBreakpoints request.
///
/// Procedure names use the same component-aware suffix rules as local breakpoints. The original
/// pattern is retained for clients that use a source path as a function breakpoint.
#[derive(Debug, Clone)]
struct StoredFunctionBreakpoint {
    /// Compiled procedure pattern using the same matching rules as local breakpoints.
    procedure_pattern: crate::glob::GlobMatcher,
    /// Original pattern for matching source paths.
    source_pattern: crate::glob::GlobMatcher,
}

struct ContinueBreakpoints<'a> {
    function: &'a [StoredFunctionBreakpoint],
    source_path_prefixes: &'a [String],
}

// RESOLVE ASMOP LOCATION
// ================================================================================================

/// Resolve an `AssemblyOp`'s location to a (file_path, line_number) pair using the host.
fn resolve_asmop_location<H: Host>(asmop: &AssemblyOp, host: &H) -> Option<(String, i64)> {
    resolve_asmop_location_with_column(asmop, host).map(|(path, line, _)| (path, line))
}

fn resolve_asmop_location_with_column<H: Host>(
    asmop: &AssemblyOp,
    host: &H,
) -> Option<(String, i64, i64)> {
    resolve_location_with_column(asmop.location()?, host)
}

fn resolve_location<H: Host>(location: &Location, host: &H) -> Option<(String, i64)> {
    resolve_location_with_column(location, host).map(|(path, line, _)| (path, line))
}

fn resolve_location_with_column<H: Host>(
    location: &Location,
    host: &H,
) -> Option<(String, i64, i64)> {
    let (span, source_file) = host.get_label_and_source_file(location);
    if let Some(source_file) = source_file {
        let file_line_col = source_file.location(span);
        let path = file_line_col.uri.as_ref().to_string();
        let line = file_line_col.line.to_u32() as i64;
        let column = file_line_col.column.to_u32() as i64;
        return Some((path, line, column));
    }

    crate::debug::resolve_location_from_filesystem(location)
        .map(|(path, line)| (path.display().to_string(), line as i64, 0))
}

fn should_defer_function_breakpoint(resolved: Option<&(String, i64)>, context_name: &str) -> bool {
    !is_internal_procedure(context_name)
        && resolved.is_none_or(|(path, _)| {
            crate::debug::is_internal_source_uri(&miden_debug_types::Uri::new(path))
        })
}

fn is_internal_procedure(context_name: &str) -> bool {
    context_name.contains("::intrinsics::")
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

fn breakable_source_lines<H: Host>(
    debug_info: &PackageDebugInfo,
    host: &H,
    source_path: &str,
    trim_prefixes: &[String],
) -> BTreeSet<i64> {
    let mut lines = BTreeSet::new();

    // Find the source file index by path
    let Some(file_idx) = debug_info
        .files()
        .iter()
        .position(|f| {
            let path = debug_info[f.path_idx].as_ref();
            source_paths_match(path, source_path, trim_prefixes)
        })
        .map(|idx| DebugFileIdx::from(idx as u32))
    else {
        return lines;
    };

    let spans = debug_info
        .nodes()
        .iter()
        .flat_map(|node| &node.asm_ops)
        .filter_map(|operation| operation.location_idx.into_option())
        .map(|index| debug_info[index])
        .filter(|location| location.file_idx == file_idx)
        .map(|location| (location.start, location.end))
        .collect::<Vec<_>>();

    // Extract the first span from those locations so we can request the source file from the host
    let Some(((start, end), spans)) = spans.split_first() else {
        return lines;
    };

    // Get the source file content if available
    let path_idx = debug_info[file_idx].path_idx;
    let path = debug_info[path_idx].clone();
    let location = Location::new(path.into(), *start, *end);
    let (_, source_file) = host.get_label_and_source_file(&location);
    let bytes = match source_file {
        Some(file) => file.as_str().as_bytes().to_vec(),
        None => {
            let Some(path) = crate::debug::resolve_source_path(location.uri()) else {
                return lines;
            };
            let Ok(bytes) = std::fs::read(path) else {
                return lines;
            };
            bytes
        }
    };
    let line_starts = core::iter::once(0)
        .chain(
            bytes
                .iter()
                .enumerate()
                .filter_map(|(index, byte)| (*byte == b'\n').then_some(index + 1)),
        )
        .collect::<Vec<_>>();
    for (start, _) in core::iter::once((*start, *end)).chain(spans.iter().copied()) {
        let start = start.to_usize();
        if start < bytes.len() {
            lines.insert(line_starts.partition_point(|line_start| *line_start <= start) as i64);
        }
    }

    lines
}

fn minimum_source_line_for_proc<H: Host>(
    mast_forest: &MastForest,
    debug_info: &PackageDebugInfo,
    host: &H,
    procedure: &str,
    source_path: &str,
    trim_prefixes: &[String],
) -> Option<i64> {
    // Find the function info record for `procedure`, which will give us the root source node for
    // that procedure
    let function_node_idx = debug_info.functions().iter().find_map(|f| {
        if debug_info[f.name_idx].as_ref() == procedure {
            // Look up the source node either exactly, or by MAST root as a fallback
            f.source_node.into_option().or_else(|| {
                mast_forest.find_procedure_root(f.mast_root).and_then(|exec_node| {
                    debug_info.unique_source_root_for_exec_node(exec_node).ok().flatten()
                })
            })
        } else {
            None
        }
    })?;

    // Extract the smallest byte index from the locations associated with the source node or
    // its children
    let node = &debug_info[function_node_idx];
    let mut file_index = None;
    let mut min_index = None;
    for location_idx in node.asm_ops.iter().filter_map(|op| op.location_idx.into_option()) {
        let loc = debug_info[location_idx];
        if file_index.is_some_and(|idx| loc.file_idx != idx) {
            continue;
        }
        let path_idx = debug_info[loc.file_idx].path_idx;
        let path = debug_info[path_idx].as_ref();
        if source_paths_match(path, source_path, trim_prefixes) {
            file_index = Some(loc.file_idx);
            min_index = Some(match min_index.take() {
                Some(prev_min) => core::cmp::min(prev_min, loc.start),
                None => loc.start,
            });
        }
    }

    // If we haven't found a minimum index yet, search through immediate children of this node
    if min_index.is_none() {
        for child in node.children.iter().copied().map(|idx| &debug_info[idx]) {
            for location_idx in child.asm_ops.iter().filter_map(|op| op.location_idx.into_option())
            {
                let loc = debug_info[location_idx];
                if file_index.is_some_and(|idx| loc.file_idx != idx) {
                    continue;
                }
                let path_idx = debug_info[loc.file_idx].path_idx;
                let path = debug_info[path_idx].as_ref();
                if source_paths_match(path, source_path, trim_prefixes) {
                    file_index = Some(loc.file_idx);
                    min_index = Some(match min_index.take() {
                        Some(prev_min) => core::cmp::min(prev_min, loc.start),
                        None => loc.start,
                    });
                }
            }
            // Stop as soon as we find a child with location information
            if min_index.is_some() {
                break;
            }
        }
    }

    let file_index = file_index?;
    let min_index = min_index?;
    let path_index = debug_info[file_index].path_idx;
    let path = debug_info[path_index].clone();

    let location = Location::new(path.into(), min_index, min_index + 1);
    let (_, Some(source_file)) = host.get_label_and_source_file(&location) else {
        return None;
    };

    let source_content = source_file.content();
    let last_line = source_content.last_line_index();
    let last_line_range = source_content.line_range(last_line).unwrap();
    if min_index >= last_line_range.end {
        None
    } else if last_line_range.contains(&min_index) {
        Some(last_line.to_u32() as i64 + 1)
    } else {
        let line = source_content.line_index(min_index);
        Some(line.to_u32() as i64 + 1)
    }
}

fn resolve_breakpoint_line(lines: &BTreeSet<i64>, requested_line: i64) -> Option<i64> {
    if lines.contains(&requested_line) {
        return Some(requested_line);
    }

    lines
        .range(requested_line..)
        .next()
        .copied()
        .or_else(|| lines.range(..requested_line).next_back().copied())
}

fn is_compiler_generated_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("local") else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
}

fn is_visible_source_var<H: Host>(
    var: &DebugVarSnapshot,
    current_location: Option<(&str, i64)>,
    host: &DapHostWrapper<'_, H>,
    source_path_prefixes: &[String],
    show_all: bool,
) -> bool {
    if show_all {
        return true;
    }

    let name = var.info.name();
    if is_compiler_generated_name(name) {
        return false;
    }

    let Some(current) = current_location else {
        return true;
    };

    let Some(var_loc) = var.info.location() else {
        return true;
    };

    let Some((var_path, var_line)) = resolve_location(var_loc, host) else {
        return true;
    };
    source_var_location_is_visible(&var_path, var_line, current.0, current.1, source_path_prefixes)
}

fn source_var_location_is_visible(
    var_path: &str,
    var_line: i64,
    current_path: &str,
    current_line: i64,
    source_path_prefixes: &[String],
) -> bool {
    source_paths_match(var_path, current_path, source_path_prefixes) && var_line < current_line
}

/// Resolve values through the same invocation-owned view used by local inspection.
fn resolved_debug_variables<H: Host>(
    processor: &FastProcessor,
    host: &DapHostWrapper<'_, H>,
    frame: &DapPresentedFrame,
    debug_state: &DapDebugVarState,
    source_path_prefixes: &[String],
    show_all: bool,
) -> Vec<(String, crate::debug::ResolvedDebugVariable)> {
    let Some(invocation) = frame.invocation else {
        return Vec::new();
    };
    debug_state
        .debug_vars
        .variables_for(invocation)
        .filter(|var| {
            is_visible_source_var(
                var,
                frame.source_path.as_deref().map(|path| (path, frame.line)),
                host,
                source_path_prefixes,
                show_all,
            )
        })
        .filter_map(|var| {
            let resolved =
                debug_state.debug_vars.resolve(invocation, var.info.name(), processor)?;
            Some((var.info.name().to_string(), resolved))
        })
        .collect()
}

fn debug_variables<H: Host>(
    processor: &FastProcessor,
    host: &DapHostWrapper<'_, H>,
    frame: &DapPresentedFrame,
    debug_state: &DapDebugVarState,
    source_path_prefixes: &[String],
    show_all: bool,
) -> Vec<types::Variable> {
    resolved_debug_variables(processor, host, frame, debug_state, source_path_prefixes, show_all)
        .into_iter()
        .map(|(name, resolved)| types::Variable {
            name,
            value: resolved.value,
            type_field: Some(resolved.type_name),
            variables_reference: 0,
            ..Default::default()
        })
        .collect()
}

fn format_debug_variables<H: Host>(
    processor: &FastProcessor,
    host: &DapHostWrapper<'_, H>,
    frame: &DapPresentedFrame,
    debug_state: &DapDebugVarState,
    source_path_prefixes: &[String],
    show_all: bool,
) -> String {
    let variables =
        debug_variables(processor, host, frame, debug_state, source_path_prefixes, show_all);
    if variables.is_empty() {
        if show_all {
            "No debug variables tracked".into()
        } else {
            "No source-level variables (use 'vars all' to show compiler locals)".into()
        }
    } else {
        variables
            .into_iter()
            .map(|var| format!("{}={}", var.name, var.value))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Update the top frame on the host's frame stack with the current asmop's name and location.
///
/// If the frame stack is empty (e.g. before the first FrameStart trace event), a root frame
/// is pushed so there is always at least one frame visible in the stack trace.
fn update_top_frame<H: Host>(host: &mut DapHostWrapper<'_, H>, current_asmop: Option<&AssemblyOp>) {
    let (name, source_path, line, column) = match current_asmop {
        Some(asmop) => {
            let loc = resolve_asmop_location_with_column(asmop, &*host);
            let (source_path, line, column) =
                loc.map_or((None, 0, 0), |(path, line, column)| (Some(path), line, column));
            (asmop.context_name().clone(), source_path, line, column)
        }
        None => (Arc::default(), None, 0, 0),
    };

    if host.frames.is_empty() {
        host.frames.push(DapCallFrame {
            name,
            source_path,
            line,
            column,
            inline_frames: Vec::new(),
        });
    } else if let Some(top) = host.frames.last_mut() {
        top.name = name;
        top.source_path = source_path;
        top.line = line;
        top.column = column;
    }
}

fn update_top_frame_with_debug<H: Host>(
    host: &mut DapHostWrapper<'_, H>,
    current_asmop: Option<&AssemblyOp>,
    inline_frames: &[crate::debug::InlineCallFrame],
) {
    update_top_frame(host, current_asmop);

    let inline_frames = inline_frames
        .iter()
        .map(|frame| {
            let (source_path, line, column) =
                resolve_location_with_column(frame.call_site(), &*host)
                    .map_or((None, 0, 0), |(source_path, line, column)| {
                        (Some(source_path), line, column)
                    });
            DapInlineFrame {
                name: frame.display_name().to_string(),
                source_path,
                line,
                column,
            }
        })
        .collect();

    if let Some(top) = host.frames.last_mut() {
        top.inline_frames = inline_frames;
    }
}

// DAP EXECUTOR
// ================================================================================================

/// A [`ProgramExecutor`] that starts a DAP TCP server and steps through the program
/// interactively.
///
/// When used with `TransactionExecutor`, instead of running to completion, `execute()` binds a TCP
/// listener and waits for a DAP client (e.g. VS Code) to connect. The client then controls
/// execution via standard DAP commands (continue, step, breakpoints, inspect stack/memory).
pub struct DapExecutor {
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    options: ExecutionOptions,
    config: DapConfig,
    event_recorder: Option<EventMutationRecorder>,
    forest_recorder: Option<MastForestRecorder>,
}

/// Handles are valid for one suspension only. Keep the allocator across restarts so an old
/// frame or scope can never accidentally select a new invocation.
#[derive(Default)]
struct DapInspection {
    next_handle: i64,
    frames: Vec<(i64, DapPresentedFrame)>,
    scopes: BTreeMap<i64, DapScope>,
}

#[derive(Clone)]
enum DapScope {
    Locals {
        frame: DapPresentedFrame,
        other: bool,
    },
    Stack,
    Memory,
}

impl DapInspection {
    fn invalidate(&mut self) {
        self.frames.clear();
        self.scopes.clear();
    }

    fn allocate(&mut self) -> i64 {
        self.next_handle += 1;
        self.next_handle
    }

    fn ensure_frames<H: Host>(
        &mut self,
        host: &DapHostWrapper<'_, H>,
        asmop: Option<&AssemblyOp>,
        cycle: usize,
    ) {
        if self.frames.is_empty() {
            self.frames = presented_frames(host, asmop, cycle)
                .into_iter()
                .map(|frame| (self.allocate(), frame))
                .collect();
        }
    }

    fn frame(&self, id: i64) -> Option<&DapPresentedFrame> {
        self.frames.iter().find_map(|(handle, frame)| (*handle == id).then_some(frame))
    }

    fn scope(&mut self, scope: DapScope) -> i64 {
        let id = self.allocate();
        self.scopes.insert(id, scope);
        id
    }
}

struct DapDebugVarState {
    debug_vars: DebugVarTracker,
    source_breakpoints: SourceBreakpoints,
}

impl DapDebugVarState {
    fn new() -> Self {
        Self {
            debug_vars: DebugVarTracker::new(Rc::new(RefCell::new(BTreeMap::new()))),
            source_breakpoints: SourceBreakpoints::default(),
        }
    }
}

impl DapExecutor {
    pub fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self {
        let config = DAP_CONFIG.get().cloned().unwrap_or_default();
        // Writing a snapshot requires both the event log and the resolved forests. Ensure an
        // event recorder exists (reusing the config's shared one if present) and turn on forest
        // recording whenever a snapshot path is configured.
        let (event_recorder, forest_recorder) = if config.snapshot_path.is_some() {
            (
                Some(config.event_recorder.clone().unwrap_or_default()),
                Some(MastForestRecorder::new()),
            )
        } else {
            (config.event_recorder.clone(), None)
        };
        DapExecutor {
            stack_inputs,
            advice_inputs,
            options,
            config,
            event_recorder,
            forest_recorder,
        }
    }

    /// Record the advice mutations produced by each event handler invocation of the wrapped
    /// host during execution.
    ///
    /// Returns a handle to the shared log. When recording was enabled on the installed
    /// [DapConfig] (see [DapConfig::record_event_mutations]), this is the same log, so
    /// embedders that never see the executor instance read the recording through their config
    /// handle instead.
    ///
    /// One entry is recorded per `on_event` invocation, in execution order, including empty
    /// mutation sets, so the log can be fed directly into an event replay queue (e.g.
    /// `Executor::into_debug_with_replay` or `State::new_for_transaction`) to debug the same
    /// execution later without access to the original host. The log is cleared automatically
    /// whenever the DAP session restarts execution from the beginning, so after execution
    /// completes it always describes the final run.
    pub fn record_event_mutations(&mut self) -> EventMutationRecorder {
        self.event_recorder.get_or_insert_with(EventMutationRecorder::new).clone()
    }

    pub fn execute_async<H: Host + Send>(
        self,
        program: Arc<Package>,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        async move { self.run_dap_server(program, host) }
    }
}

impl DapExecutor {
    /// Bind the DAP listen socket, reporting failures (bad address, port in
    /// use, ...) as errors instead of aborting the process.
    pub fn bind_listener(listen_addr: &str) -> Result<TcpListener, String> {
        use std::net::ToSocketAddrs;

        use socket2::{Domain, Socket, Type};
        let addr: std::net::SocketAddr = listen_addr
            .to_socket_addrs()
            .map_err(|e| format!("invalid listen address '{listen_addr}': {e}"))?
            .next()
            .ok_or_else(|| {
                format!("listen address '{listen_addr}' did not resolve to any address")
            })?;
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)
            .map_err(|e| format!("failed to create socket: {e}"))?;
        socket.set_reuse_address(true).ok();
        socket
            .bind(&addr.into())
            .map_err(|e| format!("DAP server failed to bind to {addr}: {e}"))?;
        socket
            .listen(1)
            .map_err(|e| format!("DAP server failed to listen on {addr}: {e}"))?;
        Ok(socket.into())
    }

    fn run_dap_server<H: Host>(
        self,
        root_package: Arc<Package>,
        host: &mut H,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let listener = match Self::bind_listener(&self.config.listen_addr) {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("{err}");
                return Err(ExecutionError::Internal("failed to start DAP server"));
            }
        };
        self.execute_on_listener(root_package, host, listener)
    }

    /// Execute a program using an already-bound listener, accepting one DAP client.
    ///
    /// This blocks until the session finishes. The caller owns listener setup and can publish
    /// its address before starting execution, including when binding an ephemeral port.
    pub fn execute_on_listener<H: Host>(
        self,
        root_package: Arc<Package>,
        host: &mut H,
        listener: TcpListener,
    ) -> Result<ExecutionOutput, ExecutionError> {
        assert!(root_package.is_program(), "cannot execute a non-executable package");

        // Clone inputs so they can be reused across restarts.
        let Self {
            stack_inputs,
            advice_inputs,
            options,
            config,
            ..
        } = self;
        log::info!(
            "DAP server listening on {}. Waiting for client connection...",
            listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or(config.listen_addr.clone())
        );

        // Accept one client connection (persists across restarts).
        let (stream, addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(err) => {
                log::error!("DAP server accept failed: {err}");
                return Err(ExecutionError::Internal("DAP server accept failed"));
            }
        };
        log::info!("DAP client connected from {addr}");

        let reader = BufReader::new(match stream.try_clone() {
            Ok(stream) => stream,
            Err(err) => {
                log::error!("failed to clone TCP stream: {err}");
                return Err(ExecutionError::Internal("failed to clone TCP stream"));
            }
        });
        let writer = BufWriter::new(stream);

        let mut server = Server::new(reader, writer);
        let mut function_breakpoints: Vec<StoredFunctionBreakpoint> = Vec::new();
        let mut is_restart = false;
        let mut inspection = DapInspection::default();
        // VS Code's flow waits for `configurationDone` before stopping the VM at
        // the entry point; Zed's flow never sends `configurationDone`. Track
        // whether the entry stop has already been announced so it fires
        // exactly once regardless of which client we're talking to.
        let mut entry_announced = false;
        let restart_flag = config.restart_requested.clone();
        let source_path_prefixes = config.source_path_prefixes.clone();
        let mut debug_state = DapDebugVarState::new();
        debug_state.source_breakpoints.prefixes = source_path_prefixes.clone();

        // Outer restart loop — on restart, the DapHostWrapper borrow is dropped,
        // a fresh FastProcessor is created, and the inner event loop re-enters.
        //
        // NOTE: The inner host `H` (e.g. from miden-client's transaction executor)
        // retains mutations from prior execution. A restarted session may therefore
        // diverge from a pristine fresh session. Phase 2 (terminate-and-reconnect)
        // solves this by creating a completely fresh host.
        loop {
            inspection.invalidate();
            let mut processor = FastProcessor::new_with_options(
                stack_inputs,
                advice_inputs.clone(),
                options.clone(),
            )
            .expect("advice inputs should fit advice map limits");

            let resume_ctx =
                processor.get_initial_resume_context_for_package(root_package.clone())?;
            // Each pass through this loop starts execution from the beginning, so any mutations
            // or forests recorded by a previous (restarted) run no longer apply.
            if let Some(recorder) = self.event_recorder.as_ref() {
                recorder.clear();
            }
            if let Some(recorder) = self.forest_recorder.as_ref() {
                recorder.clear();
            }
            let mut wrapper = DapHostWrapper::new(
                host,
                self.event_recorder.clone(),
                self.forest_recorder.clone(),
            );

            let mut resume_ctx = Some(resume_ctx);
            let mut cycle: usize = 0;
            let mut current_asmop: Option<AssemblyOp> = None;
            let mut current_inline_frames = Vec::new();
            debug_state.debug_vars = DapDebugVarState::new().debug_vars;

            // Extract initial asmop and populate the root frame.
            if let Some(ctx) = resume_ctx.as_ref() {
                let source = SourceContext::new(ctx);
                if let Some(info) = source.debug_info() {
                    debug_state.source_breakpoints.observe(info.clone(), &wrapper);
                }
                current_asmop = source.asmop();
                wrapper.recovered.update(ctx, source.source_operation(), current_asmop.as_ref());
                current_inline_frames = source.inline_frames().to_vec();
                debug_state.debug_vars.observe_execution(
                    wrapper.recovered.invocation_ids(),
                    wrapper.recovered.current_invocation(),
                    &processor,
                    RowIndex::from(0),
                    Vec::new(),
                );
            }
            update_top_frame_with_debug(
                &mut wrapper,
                current_asmop.as_ref(),
                &current_inline_frames,
            );

            // On restart, emit initial state immediately (no handshake needed).
            if is_restart {
                send_ui_state_snapshot(
                    &mut server,
                    &mut processor,
                    &wrapper,
                    current_asmop.as_ref(),
                    cycle,
                );
                server
                    .send_event(Event::Stopped(events::StoppedEventBody {
                        reason: types::StoppedEventReason::Entry,
                        description: Some("Restarted at program entry".into()),
                        thread_id: Some(1),
                        preserve_focus_hint: None,
                        text: None,
                        all_threads_stopped: Some(true),
                        hit_breakpoint_ids: None,
                    }))
                    .ok();
            }

            let mut restart_requested = false;
            let mut phase2_requested = false;

            loop {
                let req = match server.poll_request() {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(e) => {
                        log::error!("DAP protocol error: {e:#?}");
                        break;
                    }
                };

                let evaluation_frame = if let Command::Evaluate(ref args) = req.command {
                    if let Some(frame_id) = args.frame_id {
                        let Some(frame) = inspection.frame(frame_id).cloned() else {
                            server.respond(req.error("Unknown or expired frame handle")).ok();
                            continue;
                        };
                        Some(frame)
                    } else {
                        presented_frames(&wrapper, current_asmop.as_ref(), cycle)
                            .into_iter()
                            .find(|frame| !frame.inline)
                    }
                } else {
                    None
                };

                match req.command {
                    // --- Handshake ---
                    Command::Initialize(_) => {
                        let caps = types::Capabilities {
                            supports_configuration_done_request: Some(true),
                            supports_stepping_granularity: Some(true),
                            supports_restart_request: Some(true),
                            supports_function_breakpoints: Some(true),
                            supports_evaluate_for_hovers: Some(true),
                            ..Default::default()
                        };
                        let resp = req.success(ResponseBody::Initialize(caps));
                        server.respond(resp).ok();
                        server.send_event(Event::Initialized).ok();
                    }

                    Command::Launch(_) => {
                        server.respond(req.success(ResponseBody::Launch)).ok();
                        // Re-emit Initialized — some clients only listen for it after
                        // launch/attach has been acknowledged. VS Code tolerates the
                        // duplicate (it ignores Initialized after the first one).
                        server.send_event(Event::Initialized).ok();
                        announce_entry_stop(
                            &mut server,
                            &mut processor,
                            &wrapper,
                            current_asmop.as_ref(),
                            cycle,
                            &mut entry_announced,
                        );
                    }

                    // VS Code's default flow issues `attach` when launch.json uses
                    // `request: "attach"`. The server is already bound to a TCP port and
                    // running against a compiled script, so there is nothing to do beyond
                    // acknowledging the request — mirror the `Launch` handling.
                    Command::Attach(_) => {
                        server.respond(req.success(ResponseBody::Attach)).ok();
                        // See the Launch arm — re-emit Initialized for clients that
                        // miss the first one.
                        server.send_event(Event::Initialized).ok();
                        // Zed never sends `configurationDone`, so announce the entry
                        // stop here as well. The `entry_announced` guard makes this
                        // a no-op when `configurationDone` later fires (VS Code path).
                        announce_entry_stop(
                            &mut server,
                            &mut processor,
                            &wrapper,
                            current_asmop.as_ref(),
                            cycle,
                            &mut entry_announced,
                        );
                    }

                    Command::ConfigurationDone => {
                        if let Ok(resp) = req.ack() {
                            server.respond(resp).ok();
                        }
                        announce_entry_stop(
                            &mut server,
                            &mut processor,
                            &wrapper,
                            current_asmop.as_ref(),
                            cycle,
                            &mut entry_announced,
                        );
                    }

                    Command::Restart(ref args) => {
                        // `args.is_some()` means the client sent a non-null
                        // `RestartArguments` envelope; `arguments.arguments.is_some()`
                        // means that envelope carries an explicit launch/attach payload.
                        // Only the latter signals "Phase 2: recompile from disk".
                        let has_arguments =
                            args.as_ref().and_then(|a| a.arguments.as_ref()).is_some();
                        server.respond(req.success(ResponseBody::Restart)).ok();
                        if has_arguments {
                            // Phase 2: terminate-and-reconnect for recompilation.
                            restart_flag.store(true, Ordering::Release);
                            server
                                .send_event(Event::Terminated(Some(events::TerminatedEventBody {
                                    restart: Some(serde_json::Value::Bool(true)),
                                })))
                                .ok();
                            phase2_requested = true;
                            break;
                        } else {
                            // Phase 1: in-process reset (same program, same host).
                            restart_requested = true;
                            break;
                        }
                    }

                    Command::Disconnect(_) => {
                        if let Ok(resp) = req.ack() {
                            server.respond(resp).ok();
                        }
                        break;
                    }

                    // --- Execution Control ---
                    Command::Continue(_) => {
                        inspection.invalidate();
                        let resp =
                            req.success(ResponseBody::Continue(responses::ContinueResponse {
                                all_threads_continued: Some(true),
                            }));
                        server.respond(resp).ok();

                        let continue_breakpoints = ContinueBreakpoints {
                            function: &function_breakpoints,
                            source_path_prefixes: &source_path_prefixes,
                        };
                        let result = step_until_breakpoint(
                            &mut processor,
                            &mut wrapper,
                            &mut resume_ctx,
                            &mut cycle,
                            &mut current_asmop,
                            &continue_breakpoints,
                            &mut debug_state,
                        );
                        debug_state.source_breakpoints.send_updates(&mut server);
                        match result {
                            StepResult::Stepped | StepResult::Breakpoint(_) => {
                                send_ui_state_snapshot(
                                    &mut server,
                                    &mut processor,
                                    &wrapper,
                                    current_asmop.as_ref(),
                                    cycle,
                                );
                                server
                                    .send_event(Event::Stopped(events::StoppedEventBody {
                                        reason: types::StoppedEventReason::Breakpoint,
                                        description: Some("Hit breakpoint".into()),
                                        thread_id: Some(1),
                                        preserve_focus_hint: None,
                                        text: None,
                                        all_threads_stopped: Some(true),
                                        hit_breakpoint_ids: None,
                                    }))
                                    .ok();
                            }
                            StepResult::Terminated => {
                                server.send_event(Event::Terminated(None)).ok();
                            }
                            StepResult::Error(e) => {
                                server.send_event(Event::Terminated(None)).ok();
                                // Capture the failed run so it can still be replayed offline.
                                if let Some(path) = config.snapshot_path.as_ref() {
                                    write_replay_snapshot(ReplaySnapshotWriteContext {
                                        path,
                                        snapshot_recorder: config.snapshot_recorder.as_ref(),
                                        event_recorder: self.event_recorder.as_ref(),
                                        forest_recorder: self.forest_recorder.as_ref(),
                                        program: root_package.clone(),
                                        stack_inputs,
                                        advice_inputs: &advice_inputs,
                                        options,
                                    });
                                }
                                return Err(e);
                            }
                        }
                    }

                    Command::Next(ref args) => {
                        inspection.invalidate();
                        let is_instruction_step = matches!(
                            args.granularity,
                            Some(types::SteppingGranularity::Instruction)
                        );
                        let resp = req.success(ResponseBody::Next);
                        server.respond(resp).ok();

                        let step_result = if is_instruction_step {
                            step_over(
                                &mut processor,
                                &mut wrapper,
                                &mut resume_ctx,
                                &mut cycle,
                                &mut current_asmop,
                                &mut debug_state,
                            )
                        } else {
                            step_next_line(
                                &mut processor,
                                &mut wrapper,
                                &mut resume_ctx,
                                &mut cycle,
                                &mut current_asmop,
                                &source_path_prefixes,
                                &mut debug_state,
                            )
                        };

                        debug_state.source_breakpoints.send_updates(&mut server);
                        match step_result {
                            StepResult::Stepped | StepResult::Breakpoint(_) => {
                                if resume_ctx.is_none() {
                                    server.send_event(Event::Terminated(None)).ok();
                                } else {
                                    send_ui_state_snapshot(
                                        &mut server,
                                        &mut processor,
                                        &wrapper,
                                        current_asmop.as_ref(),
                                        cycle,
                                    );
                                    send_stopped_step(&mut server);
                                }
                            }
                            StepResult::Terminated => {
                                server.send_event(Event::Terminated(None)).ok();
                            }
                            StepResult::Error(e) => {
                                server.send_event(Event::Terminated(None)).ok();
                                // Capture the failed run so it can still be replayed offline.
                                if let Some(path) = config.snapshot_path.as_ref() {
                                    write_replay_snapshot(ReplaySnapshotWriteContext {
                                        path,
                                        snapshot_recorder: config.snapshot_recorder.as_ref(),
                                        event_recorder: self.event_recorder.as_ref(),
                                        forest_recorder: self.forest_recorder.as_ref(),
                                        program: root_package.clone(),
                                        stack_inputs,
                                        advice_inputs: &advice_inputs,
                                        options,
                                    });
                                }
                                return Err(e);
                            }
                        }
                    }

                    Command::StepIn(_) => {
                        inspection.invalidate();
                        let resp = req.success(ResponseBody::StepIn);
                        server.respond(resp).ok();

                        let result = step_one(
                            &mut processor,
                            &mut wrapper,
                            &mut resume_ctx,
                            &mut cycle,
                            &mut current_asmop,
                            &mut debug_state,
                        );
                        debug_state.source_breakpoints.send_updates(&mut server);
                        match result {
                            StepResult::Stepped | StepResult::Breakpoint(_) => {
                                if resume_ctx.is_none() {
                                    server.send_event(Event::Terminated(None)).ok();
                                } else {
                                    send_ui_state_snapshot(
                                        &mut server,
                                        &mut processor,
                                        &wrapper,
                                        current_asmop.as_ref(),
                                        cycle,
                                    );
                                    send_stopped_step(&mut server);
                                }
                            }
                            StepResult::Terminated => {
                                server.send_event(Event::Terminated(None)).ok();
                            }
                            StepResult::Error(e) => {
                                server.send_event(Event::Terminated(None)).ok();
                                // Capture the failed run so it can still be replayed offline.
                                if let Some(path) = config.snapshot_path.as_ref() {
                                    write_replay_snapshot(ReplaySnapshotWriteContext {
                                        path,
                                        snapshot_recorder: config.snapshot_recorder.as_ref(),
                                        event_recorder: self.event_recorder.as_ref(),
                                        forest_recorder: self.forest_recorder.as_ref(),
                                        program: root_package.clone(),
                                        stack_inputs,
                                        advice_inputs: &advice_inputs,
                                        options,
                                    });
                                }
                                return Err(e);
                            }
                        }
                    }

                    Command::StepOut(_) => {
                        inspection.invalidate();
                        let resp = req.success(ResponseBody::StepOut);
                        server.respond(resp).ok();

                        let result = step_out(
                            &mut processor,
                            &mut wrapper,
                            &mut resume_ctx,
                            &mut cycle,
                            &mut current_asmop,
                            &mut debug_state,
                        );
                        debug_state.source_breakpoints.send_updates(&mut server);
                        match result {
                            StepResult::Stepped | StepResult::Breakpoint(_) => {
                                if resume_ctx.is_none() {
                                    server.send_event(Event::Terminated(None)).ok();
                                } else {
                                    send_ui_state_snapshot(
                                        &mut server,
                                        &mut processor,
                                        &wrapper,
                                        current_asmop.as_ref(),
                                        cycle,
                                    );
                                    send_stopped_step(&mut server);
                                }
                            }
                            StepResult::Terminated => {
                                server.send_event(Event::Terminated(None)).ok();
                            }
                            StepResult::Error(e) => {
                                server.send_event(Event::Terminated(None)).ok();
                                // Capture the failed run so it can still be replayed offline.
                                if let Some(path) = config.snapshot_path.as_ref() {
                                    write_replay_snapshot(ReplaySnapshotWriteContext {
                                        path,
                                        snapshot_recorder: config.snapshot_recorder.as_ref(),
                                        event_recorder: self.event_recorder.as_ref(),
                                        forest_recorder: self.forest_recorder.as_ref(),
                                        program: root_package.clone(),
                                        stack_inputs,
                                        advice_inputs: &advice_inputs,
                                        options,
                                    });
                                }
                                return Err(e);
                            }
                        }
                    }

                    // --- State Inspection ---
                    Command::Threads => {
                        let resp = req.success(ResponseBody::Threads(responses::ThreadsResponse {
                            threads: vec![types::Thread {
                                id: 1,
                                name: "main".into(),
                            }],
                        }));
                        server.respond(resp).ok();
                    }

                    Command::StackTrace(ref _args) => {
                        inspection.ensure_frames(&wrapper, current_asmop.as_ref(), cycle);
                        let frames = inspection
                            .frames
                            .iter()
                            .map(|(id, frame)| {
                                let source = frame.source_path.as_ref().map(|path| types::Source {
                                    name: Some(path.rsplit('/').next().unwrap_or(path).to_string()),
                                    path: Some(path.clone()),
                                    ..Default::default()
                                });
                                types::StackFrame {
                                    id: *id,
                                    name: frame.name.clone(),
                                    source,
                                    line: frame.line,
                                    column: frame.column,
                                    presentation_hint: frame
                                        .inline
                                        .then_some(types::StackFramePresentationhint::Subtle),
                                    ..Default::default()
                                }
                            })
                            .collect::<Vec<_>>();

                        let total = frames.len() as i64;
                        let resp =
                            req.success(ResponseBody::StackTrace(responses::StackTraceResponse {
                                stack_frames: frames,
                                total_frames: Some(total),
                            }));
                        server.respond(resp).ok();
                    }

                    Command::Scopes(ref args) => {
                        let Some(frame) = inspection.frame(args.frame_id).cloned() else {
                            server.respond(req.error("Unknown or expired frame handle")).ok();
                            continue;
                        };
                        let mut scopes = Vec::new();
                        if frame
                            .invocation
                            .is_some_and(|id| debug_state.debug_vars.has_invocation(id))
                        {
                            let visible = debug_variables(
                                &processor,
                                &wrapper,
                                &frame,
                                &debug_state,
                                &source_path_prefixes,
                                false,
                            );
                            let all = debug_variables(
                                &processor,
                                &wrapper,
                                &frame,
                                &debug_state,
                                &source_path_prefixes,
                                true,
                            );
                            for (name, other, count) in [
                                ("Local Variables", false, visible.len()),
                                ("Other Locals", true, all.len() - visible.len()),
                            ] {
                                if other && count == 0 {
                                    continue;
                                }
                                scopes.push(types::Scope {
                                    name: name.into(),
                                    variables_reference: inspection.scope(DapScope::Locals {
                                        frame: frame.clone(),
                                        other,
                                    }),
                                    presentation_hint: Some(types::ScopePresentationhint::Locals),
                                    named_variables: Some(count as i64),
                                    expensive: false,
                                    ..Default::default()
                                });
                            }
                        }
                        // Raw VM state describes the running invocation, never a suspended caller.
                        if inspection
                            .frames
                            .iter()
                            .find(|(_, frame)| !frame.inline)
                            .is_some_and(|(id, _)| *id == args.frame_id)
                        {
                            for (name, scope) in
                                [("Operand Stack", DapScope::Stack), ("Memory", DapScope::Memory)]
                            {
                                scopes.push(types::Scope {
                                    name: name.into(),
                                    variables_reference: inspection.scope(scope),
                                    expensive: false,
                                    ..Default::default()
                                });
                            }
                        }
                        server
                            .respond(req.success(ResponseBody::Scopes(responses::ScopesResponse {
                                scopes,
                            })))
                            .ok();
                    }

                    Command::Variables(ref args) => {
                        let Some(scope) = inspection.scopes.get(&args.variables_reference) else {
                            server.respond(req.error("Unknown or expired variable handle")).ok();
                            continue;
                        };
                        let variables = match scope {
                            DapScope::Locals { frame, other } => {
                                let mut variables = debug_variables(
                                    &processor,
                                    &wrapper,
                                    frame,
                                    &debug_state,
                                    &source_path_prefixes,
                                    *other,
                                );
                                if *other {
                                    let visible = debug_variables(
                                        &processor,
                                        &wrapper,
                                        frame,
                                        &debug_state,
                                        &source_path_prefixes,
                                        false,
                                    );
                                    variables.retain(|var| {
                                        !visible.iter().any(|item| item.name == var.name)
                                    });
                                }
                                variables
                            }
                            DapScope::Stack => {
                                let state = processor.state();
                                let stack = state.get_stack_state();
                                stack
                                    .iter()
                                    .enumerate()
                                    .map(|(i, felt)| types::Variable {
                                        name: format!("[{i}]"),
                                        value: format!("{}", felt.as_canonical_u64()),
                                        type_field: Some("Felt".into()),
                                        variables_reference: 0,
                                        ..Default::default()
                                    })
                                    .collect()
                            }
                            DapScope::Memory => {
                                let state = processor.state();
                                let ctx = state.ctx();
                                let mem = state.get_mem_state(ctx);
                                mem.iter()
                                    .map(|(addr, felt)| {
                                        let addr_u32: u32 = (*addr).into();
                                        types::Variable {
                                            name: format!("0x{addr_u32:08x}"),
                                            value: format!("{}", felt.as_canonical_u64()),
                                            type_field: Some("Felt".into()),
                                            variables_reference: 0,
                                            ..Default::default()
                                        }
                                    })
                                    .collect()
                            }
                        };

                        let resp =
                            req.success(ResponseBody::Variables(responses::VariablesResponse {
                                variables,
                            }));
                        server.respond(resp).ok();
                    }

                    // --- Breakpoints ---
                    Command::SetBreakpoints(ref args) => {
                        let source_path = args.source.path.clone().unwrap_or_default();
                        let confirmed = debug_state.source_breakpoints.replace(
                            &source_path,
                            args.breakpoints.as_deref().unwrap_or_default(),
                            &wrapper,
                        );

                        let resp = req.success(ResponseBody::SetBreakpoints(
                            responses::SetBreakpointsResponse {
                                breakpoints: confirmed,
                            },
                        ));
                        server.respond(resp).ok();
                    }

                    Command::SetFunctionBreakpoints(ref args) => {
                        function_breakpoints.clear();
                        let mut confirmed = Vec::new();
                        for fbp in &args.breakpoints {
                            let procedure_pattern = procedure_pattern(&fbp.name);
                            let source_pattern = crate::glob::GlobBuilder::new(&fbp.name).build();
                            let verified = match (procedure_pattern, source_pattern) {
                                (Ok(procedure_pattern), Ok(source_pattern)) => {
                                    function_breakpoints.push(StoredFunctionBreakpoint {
                                        procedure_pattern,
                                        source_pattern: source_pattern.compile_matcher(),
                                    });
                                    true
                                }
                                _ => false,
                            };
                            confirmed.push(types::Breakpoint {
                                verified,
                                ..Default::default()
                            });
                        }

                        let resp = req.success(ResponseBody::SetFunctionBreakpoints(
                            responses::SetFunctionBreakpointsResponse {
                                breakpoints: confirmed,
                            },
                        ));
                        server.respond(resp).ok();
                    }

                    // --- Evaluate (custom state query) ---
                    Command::Evaluate(ref args) if args.expression == "__miden_ui_state" => {
                        let state_json = serde_json::to_string(&build_ui_state(
                            &mut processor,
                            &wrapper,
                            current_asmop.as_ref(),
                            cycle,
                        ))
                        .expect("bundled DAP UI state should serialize");
                        let resp =
                            req.success(ResponseBody::Evaluate(responses::EvaluateResponse {
                                result: state_json,
                                type_field: Some("json".into()),
                                presentation_hint: None,
                                variables_reference: 0,
                                named_variables: None,
                                indexed_variables: None,
                                memory_reference: None,
                            }));
                        server.respond(resp).ok();
                    }

                    Command::Evaluate(ref args)
                        if matches!(
                            args.expression.as_str(),
                            "__miden_variables" | "__miden_variables all"
                        ) =>
                    {
                        let variables = resolved_debug_variables(
                            &processor,
                            &wrapper,
                            evaluation_frame
                                .as_ref()
                                .expect("a default physical frame always exists"),
                            &debug_state,
                            &source_path_prefixes,
                            args.expression.ends_with(" all"),
                        )
                        .into_iter()
                        .map(|(name, resolved)| crate::exec::DapVariableValue {
                            name,
                            value: resolved.value,
                            raw: resolved.raw.map(|felt| felt.as_canonical_u64()),
                        })
                        .collect::<Vec<_>>();
                        server
                            .respond(
                                req.success(ResponseBody::Evaluate(responses::EvaluateResponse {
                                    result: serde_json::to_string(&variables)
                                        .expect("bundled DAP variables should serialize"),
                                    type_field: Some("json".into()),
                                    presentation_hint: None,
                                    variables_reference: 0,
                                    named_variables: None,
                                    indexed_variables: None,
                                    memory_reference: None,
                                })),
                            )
                            .ok();
                    }

                    Command::Evaluate(ref args)
                        if args.expression.starts_with("__miden_read_memory ") =>
                    {
                        let expr = args
                            .expression
                            .strip_prefix("__miden_read_memory ")
                            .expect("prefix checked above");

                        match expr.parse::<ReadMemoryExpr>().and_then(|expr| {
                            read_memory_at_current_state(&mut processor, cycle, &expr)
                        }) {
                            Ok(result) => {
                                let resp = req.success(ResponseBody::Evaluate(
                                    responses::EvaluateResponse {
                                        result,
                                        type_field: Some("string".into()),
                                        presentation_hint: None,
                                        variables_reference: 0,
                                        named_variables: None,
                                        indexed_variables: None,
                                        memory_reference: None,
                                    },
                                ));
                                server.respond(resp).ok();
                            }
                            Err(err) => {
                                server.respond(req.error(&err)).ok();
                            }
                        }
                    }

                    Command::Evaluate(ref args)
                        if matches!(
                            args.expression.as_str(),
                            "vars" | ":vars" | "vars all" | ":vars all"
                        ) =>
                    {
                        let result = format_debug_variables(
                            &processor,
                            &wrapper,
                            evaluation_frame
                                .as_ref()
                                .expect("a default physical frame always exists"),
                            &debug_state,
                            &source_path_prefixes,
                            args.expression.ends_with(" all"),
                        );
                        let resp =
                            req.success(ResponseBody::Evaluate(responses::EvaluateResponse {
                                result,
                                type_field: Some("string".into()),
                                presentation_hint: None,
                                variables_reference: 0,
                                named_variables: None,
                                indexed_variables: None,
                                memory_reference: None,
                            }));
                        server.respond(resp).ok();
                    }

                    Command::Evaluate(ref args) => {
                        if let Some(variable) = debug_variables(
                            &processor,
                            &wrapper,
                            evaluation_frame
                                .as_ref()
                                .expect("a default physical frame always exists"),
                            &debug_state,
                            &source_path_prefixes,
                            false,
                        )
                        .into_iter()
                        .find(|variable| variable.name == args.expression)
                        {
                            let resp =
                                req.success(ResponseBody::Evaluate(responses::EvaluateResponse {
                                    result: variable.value,
                                    type_field: variable.type_field,
                                    presentation_hint: None,
                                    variables_reference: 0,
                                    named_variables: None,
                                    indexed_variables: None,
                                    memory_reference: None,
                                }));
                            server.respond(resp).ok();
                        } else {
                            server.respond(req.error("Unsupported expression")).ok();
                        }
                    }

                    // --- Unhandled ---
                    _ => {
                        server.respond(req.error("Unsupported command")).ok();
                    }
                }
                debug_state.source_breakpoints.send_updates(&mut server);
            }

            if phase2_requested {
                log::debug!("DAP Phase 2 restart: returning from execute() for recompilation...");
                return Ok(ExecutionOutput {
                    stack: StackOutputs::new(&[]).expect("empty stack outputs"),
                    advice: Default::default(),
                    memory: Default::default(),
                    precompile_root: miden_core::deferred::TRUE_DIGEST,
                    precompile_witness: None,
                });
            }

            if restart_requested {
                is_restart = true;
                log::debug!("DAP restart requested. Resetting processor...");
                // wrapper is dropped here, releasing the &mut H borrow.
                // The outer loop creates a fresh processor and wrapper.
                continue;
            }

            // Normal exit (disconnect or connection closed).
            log::debug!("DAP session ended. Building execution output...");

            // Run the program to completion if it hasn't finished.
            if let Some(ctx) = resume_ctx {
                let mut ctx = Some(ctx);
                while let Some(resume) = ctx.take() {
                    let debug_info = resume.debug_info();
                    let step_result = if let Some(debug_info) = debug_info.as_deref() {
                        poll_immediately(processor.step_with_package_debug_info(
                            &mut wrapper,
                            resume,
                            debug_info,
                        ))
                    } else {
                        poll_immediately(processor.step(&mut wrapper, resume))
                    };
                    match step_result {
                        Ok(Some(new_ctx)) => {
                            ctx = Some(new_ctx);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            // Capture the run up to the failure so it can still be replayed.
                            if let Some(path) = config.snapshot_path.as_ref() {
                                write_replay_snapshot(ReplaySnapshotWriteContext {
                                    path,
                                    snapshot_recorder: config.snapshot_recorder.as_ref(),
                                    event_recorder: self.event_recorder.as_ref(),
                                    forest_recorder: self.forest_recorder.as_ref(),
                                    program: root_package.clone(),
                                    stack_inputs,
                                    advice_inputs: &advice_inputs,
                                    options,
                                });
                            }
                            return Err(e);
                        }
                    }
                }
            }

            // If a snapshot path is configured, persist a self-contained replay snapshot of this
            // (final) run: program, inputs, resolved forests, and the recorded event log.
            if let Some(path) = config.snapshot_path.as_ref() {
                write_replay_snapshot(ReplaySnapshotWriteContext {
                    path,
                    snapshot_recorder: config.snapshot_recorder.as_ref(),
                    event_recorder: self.event_recorder.as_ref(),
                    forest_recorder: self.forest_recorder.as_ref(),
                    program: root_package.clone(),
                    stack_inputs,
                    advice_inputs: &advice_inputs,
                    options,
                });
            }

            // Build ExecutionOutput from the processor's final state.
            let stack_top: Vec<_> = processor.stack_top().iter().rev().copied().collect();
            let stack = StackOutputs::new(&stack_top)
                .unwrap_or_else(|_| StackOutputs::new(&[]).expect("empty stack outputs"));

            return super::stepper::execution_output(processor, stack);
        } // end outer restart loop
    }
}

/// Build and write a [ReplaySnapshot] of the current run to `path`.
///
/// Reads the recorders without draining them (via their `snapshot()`), so a caller that also
/// reads the shared event recorder afterwards — e.g. an embedder reporting how many mutation sets
/// were recorded — still sees the full log. Called on every terminal outcome, clean exit or a
/// failed step, so a failing transaction is captured and replayable too.
struct ReplaySnapshotWriteContext<'a> {
    path: &'a Path,
    snapshot_recorder: Option<&'a ReplaySnapshotRecorder>,
    event_recorder: Option<&'a EventMutationRecorder>,
    forest_recorder: Option<&'a MastForestRecorder>,
    program: Arc<Package>,
    stack_inputs: StackInputs,
    advice_inputs: &'a AdviceInputs,
    options: ExecutionOptions,
}

fn write_replay_snapshot(context: ReplaySnapshotWriteContext<'_>) {
    let event_log = context.event_recorder.map(EventMutationRecorder::snapshot).unwrap_or_default();
    let mast_forests =
        context.forest_recorder.map(MastForestRecorder::snapshot).unwrap_or_default();
    let snapshot = ReplaySnapshot {
        package: context.program.clone(),
        stack_inputs: context.stack_inputs,
        advice_inputs: context.advice_inputs.clone(),
        options: context.options,
        mast_forests,
        event_log,
    };
    match snapshot.write_to_file(context.path) {
        Ok(()) => {
            let write = ReplaySnapshotWrite {
                path: Uri::from(context.path.to_path_buf()),
                event_count: snapshot.event_log.len(),
                forest_count: snapshot.mast_forests.len(),
            };
            if let Some(recorder) = context.snapshot_recorder {
                recorder.record_success(write.clone());
            }
            eprintln!(
                "Wrote replay snapshot ({} event(s), {} forest(s)) to {}",
                write.event_count, write.forest_count, write.path
            );
        }
        Err(err) => {
            if let Some(recorder) = context.snapshot_recorder {
                recorder.record_error(Uri::from(context.path.to_path_buf()), err.to_string());
            }
            eprintln!("Failed to write replay snapshot to {}: {err}", context.path.display());
        }
    }
}

// STEPPING HELPERS
// ================================================================================================

fn advance_one<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    ctx: ResumeContext,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    debug_state: &mut DapDebugVarState,
) -> Result<Option<ResumeContext>, ExecutionError> {
    let source = SourceContext::new(&ctx);
    if let Some(info) = source.debug_info() {
        debug_state.source_breakpoints.observe(info.clone(), &*host);
    }
    let executed_asmop = source.executed_asmop();
    let debug_var_infos = source.debug_vars();
    let source_asmop = source.asmop();
    host.recovered.update(&ctx, source.source_operation(), source_asmop.as_ref());
    debug_state.debug_vars.observe_execution(
        host.recovered.invocation_ids(),
        host.recovered.current_invocation(),
        processor,
        RowIndex::from((*cycle + 1) as u32),
        debug_var_infos,
    );
    let result = if let Some(debug_info) = source.debug_info() {
        poll_immediately(processor.step_with_package_debug_info(host, ctx, debug_info))
    } else {
        poll_immediately(processor.step(host, ctx))
    };
    match result {
        Ok(Some(new_ctx)) => {
            *cycle += 1;
            *current_asmop = executed_asmop;
            update_top_frame_with_debug(host, current_asmop.as_ref(), source.inline_frames());
            Ok(Some(new_ctx))
        }
        Ok(None) => {
            *cycle += 1;
            *current_asmop = None;
            debug_state.debug_vars.reset();
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn is_next_source_line(
    start_proc: Option<&str>,
    start_loc: Option<&(String, i64)>,
    current_proc: Option<&str>,
    current_loc: Option<&(String, i64)>,
    source_path_prefixes: &[String],
    minimum_source_line: Option<i64>,
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
        && current.1 < minimum_source_line
    {
        return false;
    }

    match (start_loc, current_loc) {
        (Some(start), Some(current)) => {
            source_paths_match(&start.0, &current.0, source_path_prefixes) && start.1 != current.1
        }
        (None, Some(_)) => true,
        _ => false,
    }
}

/// Execute a single VM step.
fn step_one<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    resume_ctx: &mut Option<ResumeContext>,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    debug_state: &mut DapDebugVarState,
) -> StepResult {
    let ctx = match resume_ctx.take() {
        Some(ctx) => ctx,
        None => return StepResult::Terminated,
    };

    match advance_one(processor, host, ctx, cycle, current_asmop, debug_state) {
        Ok(Some(new_ctx)) => {
            *resume_ctx = Some(new_ctx);
            update_top_frame(host, current_asmop.as_ref());
            StepResult::Stepped
        }
        Ok(None) => StepResult::Terminated,
        Err(e) => StepResult::Error(e),
    }
}

/// Step over: advance until the current assembly operation changes.
fn step_over<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    resume_ctx: &mut Option<ResumeContext>,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    debug_state: &mut DapDebugVarState,
) -> StepResult {
    let original_asmop = current_asmop.clone();

    loop {
        let ctx = match resume_ctx.take() {
            Some(ctx) => ctx,
            None => return StepResult::Terminated,
        };

        match advance_one(processor, host, ctx, cycle, current_asmop, debug_state) {
            Ok(Some(new_ctx)) => {
                *resume_ctx = Some(new_ctx);

                if *current_asmop != original_asmop {
                    update_top_frame(host, current_asmop.as_ref());
                    return StepResult::Stepped;
                }
            }
            Ok(None) => return StepResult::Terminated,
            Err(e) => return StepResult::Error(e),
        }
    }
}

/// Step over source lines: advance until the current source line changes.
fn step_next_line<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    resume_ctx: &mut Option<ResumeContext>,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    source_path_prefixes: &[String],
    debug_state: &mut DapDebugVarState,
) -> StepResult {
    let original_asmop = current_asmop.clone();
    let start_proc = original_asmop.as_ref().map(|asmop| asmop.context_name().clone());
    let start_loc = original_asmop.as_ref().and_then(|asmop| resolve_asmop_location(asmop, host));
    let minimum_source_line = if let (Some(ctx), Some(proc), Some((source_path, _line))) =
        (resume_ctx.as_ref(), start_proc.as_deref(), start_loc.as_ref())
        && let Some(debug_info) = ctx.debug_info()
    {
        minimum_source_line_for_proc(
            ctx.current_forest(),
            &debug_info,
            host,
            proc,
            source_path,
            source_path_prefixes,
        )
    } else {
        None
    };

    loop {
        let ctx = match resume_ctx.take() {
            Some(ctx) => ctx,
            None => return StepResult::Terminated,
        };

        match advance_one(processor, host, ctx, cycle, current_asmop, debug_state) {
            Ok(Some(new_ctx)) => {
                *resume_ctx = Some(new_ctx);

                let current_proc = current_asmop.as_ref().map(|asmop| asmop.context_name().clone());
                let current_loc =
                    current_asmop.as_ref().and_then(|asmop| resolve_asmop_location(asmop, host));
                let has_source_context = start_loc.is_some() || current_loc.is_some();
                let reached_next = if has_source_context {
                    is_next_source_line(
                        start_proc.as_deref(),
                        start_loc.as_ref(),
                        current_proc.as_deref(),
                        current_loc.as_ref(),
                        source_path_prefixes,
                        minimum_source_line,
                    )
                } else {
                    *current_asmop != original_asmop
                };

                if reached_next {
                    update_top_frame(host, current_asmop.as_ref());
                    return StepResult::Stepped;
                }
            }
            Ok(None) => return StepResult::Terminated,
            Err(e) => return StepResult::Error(e),
        }
    }
}

/// Step out: advance until the captured invocation returns.
fn step_out<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    resume_ctx: &mut Option<ResumeContext>,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    debug_state: &mut DapDebugVarState,
) -> StepResult {
    let target = host.recovered.return_target(host.call_depth);

    loop {
        let ctx = match resume_ctx.take() {
            Some(ctx) => ctx,
            None => return StepResult::Terminated,
        };

        match advance_one(processor, host, ctx, cycle, current_asmop, debug_state) {
            Ok(Some(new_ctx)) => {
                *resume_ctx = Some(new_ctx);

                // A recovered return can first appear on a control cycle. Stop at the
                // caller's next assembly operation so source stepping has a usable location.
                if target.has_returned(&host.recovered, host.call_depth)
                    && (!target.is_recovered()
                        || !host.recovered.has_current_frame()
                        || current_asmop.is_some())
                {
                    update_top_frame(host, current_asmop.as_ref());
                    return StepResult::Stepped;
                }
            }
            Ok(None) => return StepResult::Terminated,
            Err(e) => return StepResult::Error(e),
        }
    }
}

/// Continue: step until a breakpoint is hit or the program terminates.
fn step_until_breakpoint<H: Host>(
    processor: &mut FastProcessor,
    host: &mut DapHostWrapper<'_, H>,
    resume_ctx: &mut Option<ResumeContext>,
    cycle: &mut usize,
    current_asmop: &mut Option<AssemblyOp>,
    breakpoints: &ContinueBreakpoints<'_>,
    debug_state: &mut DapDebugVarState,
) -> StepResult {
    loop {
        let ctx = match resume_ctx.take() {
            Some(ctx) => ctx,
            None => return StepResult::Terminated,
        };

        match advance_one(processor, host, ctx, cycle, current_asmop, debug_state) {
            Ok(Some(new_ctx)) => {
                *resume_ctx = Some(new_ctx);

                if let Some(asmop) = current_asmop.as_ref() {
                    let resolved = resolve_asmop_location(asmop, host);

                    // Check line breakpoints
                    if let Some((ref path, line)) = resolved {
                        for bp in &debug_state.source_breakpoints.entries {
                            if bp.line == Some(line)
                                && source_paths_match(
                                    path,
                                    &bp.path,
                                    breakpoints.source_path_prefixes,
                                )
                            {
                                update_top_frame(host, current_asmop.as_ref());
                                return StepResult::Breakpoint(line);
                            }
                        }
                    }

                    // Check function breakpoints against procedure names and source paths.
                    if !breakpoints.function.is_empty() {
                        let context_name = asmop.context_name();
                        for fbp in breakpoints.function {
                            if procedure_matches(&fbp.procedure_pattern, context_name) {
                                if should_defer_function_breakpoint(resolved.as_ref(), context_name)
                                    || resume_ctx.as_ref().is_some_and(|resume_ctx| {
                                        should_wait_for_entry_variables(
                                            resume_ctx,
                                            context_name,
                                            &debug_state.debug_vars,
                                            *cycle,
                                        )
                                    })
                                {
                                    continue;
                                }
                                update_top_frame(host, current_asmop.as_ref());
                                let line = resolved.as_ref().map_or(0, |(_, l)| *l);
                                return StepResult::Breakpoint(line);
                            }
                            if let Some((ref path, line)) = resolved
                                && fbp.source_pattern.is_match(&Uri::new(path))
                            {
                                update_top_frame(host, current_asmop.as_ref());
                                return StepResult::Breakpoint(line);
                            }
                        }
                    }
                }
            }
            Ok(None) => return StepResult::Terminated,
            Err(e) => return StepResult::Error(e),
        }
    }
}

/// Push a `miden/uiState` snapshot event to the DAP client.
///
/// This custom event carries the bundled UI state (cycle, stack, callstack) so
/// the client can refresh without an extra evaluate round-trip. It is emitted
/// immediately before the standard `stopped` event because the DAP `stopped`
/// event itself does not carry VM state — it only signals that execution paused.
fn send_ui_state_snapshot<R: std::io::Read, W: std::io::Write, H: Host>(
    server: &mut Server<R, W>,
    processor: &mut FastProcessor,
    host: &DapHostWrapper<'_, H>,
    current_asmop: Option<&AssemblyOp>,
    cycle: usize,
) {
    let ui_state = build_ui_state(processor, host, current_asmop, cycle);
    if let Ok(json) = serde_json::to_value(&ui_state) {
        server.send_event(Event::MidenUiState(json)).ok();
    }
}

/// Announce the entry-point stop to the DAP client (UI snapshot + `Stopped(entry)`),
/// flipping `already_announced` so subsequent calls become no-ops.
///
/// Called from both `Attach`/`Launch` (so clients like Zed that skip
/// `configurationDone` still see the initial stop) and from `ConfigurationDone`
/// (the VS Code path).
fn announce_entry_stop<R: std::io::Read, W: std::io::Write, H: Host>(
    server: &mut Server<R, W>,
    processor: &mut FastProcessor,
    host: &DapHostWrapper<'_, H>,
    current_asmop: Option<&AssemblyOp>,
    cycle: usize,
    already_announced: &mut bool,
) {
    if *already_announced {
        return;
    }
    *already_announced = true;
    // Some DAP clients (Zed) only react to `stopped` events for thread IDs they
    // already know about; explicitly announce thread 1 as started before the
    // initial stop. VS Code tolerates the extra event.
    server
        .send_event(Event::Thread(events::ThreadEventBody {
            reason: types::ThreadEventReason::Started,
            thread_id: 1,
        }))
        .ok();
    send_ui_state_snapshot(server, processor, host, current_asmop, cycle);
    server
        .send_event(Event::Stopped(events::StoppedEventBody {
            reason: types::StoppedEventReason::Entry,
            description: Some("Paused at program entry".into()),
            thread_id: Some(1),
            preserve_focus_hint: None,
            text: None,
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: None,
        }))
        .ok();
}

/// Send a "stopped(step)" event to the DAP client.
fn send_stopped_step<R: std::io::Read, W: std::io::Write>(server: &mut Server<R, W>) {
    server
        .send_event(Event::Stopped(events::StoppedEventBody {
            reason: types::StoppedEventReason::Step,
            description: None,
            thread_id: Some(1),
            preserve_focus_hint: None,
            text: None,
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: None,
        }))
        .ok();
}

/// Result of a stepping operation.
#[allow(dead_code)]
enum StepResult {
    /// Successfully advanced one or more steps.
    Stepped,
    /// Hit a breakpoint at the given line.
    Breakpoint(i64),
    /// Program terminated normally.
    Terminated,
    /// An execution error occurred.
    Error(ExecutionError),
}

#[cfg(test)]
mod protocol_tests;

#[cfg(test)]
mod tests;
