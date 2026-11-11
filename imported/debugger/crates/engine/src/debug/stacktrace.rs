use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{cell::OnceCell, fmt};
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};

use miden_core::operations::AssemblyOp;
use miden_debug_types::{Location, SourceFile, SourceManager, SourceSpan, Uri};
use miden_mast_package::debug_info::{
    DebugFunctionIdx, DebugFunctionInfo, DebugSourceInlineCall, DebugSourceNodeId, PackageDebugInfo,
};
use miden_processor::{ContextId, SourceInlineCallContext, operation::Operation, trace::RowIndex};
use miden_utils_sync::RwLock;

use crate::Event;

mod recovered;
pub use recovered::{InvocationId, RecoveredCallStack, ReturnTarget};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControlFlowOp {
    Span,
    Respan,
    Join,
    Split,
    End,
}

pub struct StepInfo<'a> {
    pub op: Option<Operation>,
    pub control: Option<ControlFlowOp>,
    pub asmop: Option<&'a AssemblyOp>,
    pub clk: RowIndex,
    pub ctx: ContextId,
    pub inline_frames: &'a [InlineCallFrame],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineCallFrame {
    name: Arc<str>,
    call_site: Location,
}

impl InlineCallFrame {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn call_site(&self) -> &Location {
        &self.call_site
    }

    pub fn display_name(&self) -> String {
        demangle(&self.name)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LogicalFrameKind {
    Physical,
    Inline,
}

#[derive(Debug, Clone)]
enum LogicalFrameLocation {
    Assembly(Location),
    Resolved(ResolvedLocation),
}

#[derive(Debug, Clone)]
pub struct LogicalStackFrame {
    name: Arc<str>,
    kind: LogicalFrameKind,
    location: Option<LogicalFrameLocation>,
    physical_index: Option<usize>,
    origin: Option<miden_processor::DebugFrameOrigin>,
    invocation: Option<InvocationId>,
    source: Option<LogicalFrameSource>,
}

#[derive(Debug, Clone)]
enum LogicalFrameSource {
    Physical(miden_processor::DebugCallFrame),
    Inline {
        owner: InvocationId,
        info: Arc<PackageDebugInfo>,
        function_idx: DebugFunctionIdx,
        call_site: Location,
    },
}

impl LogicalStackFrame {
    /// Compare source invocations independently of presentation names and current locations.
    pub(crate) fn is_same_source_frame(&self, other: &Self) -> bool {
        match (&self.source, &other.source) {
            (
                Some(LogicalFrameSource::Physical(left)),
                Some(LogicalFrameSource::Physical(right)),
            ) => left.is_same_frame(right),
            (
                Some(LogicalFrameSource::Inline {
                    owner: left_owner,
                    info: left_info,
                    function_idx: left_function,
                    call_site: left_site,
                }),
                Some(LogicalFrameSource::Inline {
                    owner: right_owner,
                    info: right_info,
                    function_idx: right_function,
                    call_site: right_site,
                }),
            ) => {
                left_owner == right_owner
                    && Arc::ptr_eq(left_info, right_info)
                    && left_function == right_function
                    && left_site == right_site
            }
            _ => false,
        }
    }

    pub(crate) fn debug_info(&self) -> Option<&PackageDebugInfo> {
        match self.source.as_ref()? {
            LogicalFrameSource::Physical(frame) => Some(frame.debug_info()),
            LogicalFrameSource::Inline { info, .. } => Some(info),
        }
    }

    pub(crate) fn function(&self) -> Option<&DebugFunctionInfo> {
        match self.source.as_ref()? {
            LogicalFrameSource::Physical(frame) => Some(frame.function()),
            LogicalFrameSource::Inline {
                info, function_idx, ..
            } => info.get_function(*function_idx),
        }
    }

    /// Physical source invocations have local ownership; inline and event-only rows do not.
    pub fn invocation_id(&self) -> Option<InvocationId> {
        self.invocation
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> LogicalFrameKind {
        self.kind
    }

    pub fn physical_index(&self) -> Option<usize> {
        self.physical_index
    }

    pub fn origin(&self) -> Option<miden_processor::DebugFrameOrigin> {
        self.origin
    }

    pub fn assembly_location(&self) -> Option<&Location> {
        match self.location.as_ref()? {
            LogicalFrameLocation::Assembly(location) => Some(location),
            LogicalFrameLocation::Resolved(_) => None,
        }
    }

    pub fn display_name(&self) -> String {
        if self
            .origin
            .is_some_and(|origin| origin != miden_processor::DebugFrameOrigin::Source)
        {
            return format!("[inferred] {}", self.name);
        }
        match self.kind {
            LogicalFrameKind::Physical => self.name.to_string(),
            LogicalFrameKind::Inline => format!("[inlined] {}", self.name),
        }
    }

    pub fn resolved(&self, source_manager: &dyn SourceManager) -> Option<ResolvedLocation> {
        match self.location.as_ref()? {
            LogicalFrameLocation::Assembly(location) => {
                resolve_assembly_location(source_manager, location)
            }
            LogicalFrameLocation::Resolved(resolved) => Some(resolved.clone()),
        }
    }
}

/// Resolves the inline frames active for an operation.
///
/// Rows owned by the current package come first. Contexts inherited across dynamic/external
/// package boundaries follow in the VM-provided innermost-to-outermost order.
pub fn inline_frames_for_operation<'a>(
    current: Option<(&PackageDebugInfo, DebugSourceNodeId, u32)>,
    inherited: impl IntoIterator<Item = &'a SourceInlineCallContext>,
) -> Vec<InlineCallFrame> {
    let mut frames = Vec::new();
    if let Some((debug_info, source_node, op_idx)) = current {
        append_inline_frames(
            &mut frames,
            debug_info,
            debug_info.inline_calls_for_operation(source_node, op_idx),
        );
    }
    for context in inherited {
        append_inline_frames(&mut frames, context.debug_info(), context.inline_calls());
    }
    frames
}

fn append_inline_frames<'a>(
    frames: &mut Vec<InlineCallFrame>,
    debug_info: &PackageDebugInfo,
    rows: impl IntoIterator<Item = &'a DebugSourceInlineCall>,
) {
    frames.extend(rows.into_iter().filter_map(|row| {
        let function = debug_info.get_function(row.callee_idx)?;
        let name = debug_info.get_string(function.name_idx)?;
        let call_site = debug_info.get_location(row.loc_idx)?;
        Some(InlineCallFrame { name, call_site })
    }));
}

#[derive(Debug, Clone)]
struct SpanContext {
    frame_index: usize,
    location: Option<Location>,
}

pub struct CallStack {
    events: Arc<RwLock<BTreeMap<RowIndex, Event>>>,
    contexts: BTreeSet<Arc<str>>,
    frames: Vec<CallFrame>,
    block_stack: Vec<Option<SpanContext>>,
    recovered: RecoveredCallStack,
    frame_transition: Option<FrameTransition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameTransition {
    Entered,
    Exited,
}

impl CallStack {
    pub fn new(events: Arc<RwLock<BTreeMap<RowIndex, Event>>>) -> Self {
        Self {
            events,
            contexts: BTreeSet::default(),
            frames: vec![],
            block_stack: vec![],
            recovered: RecoveredCallStack::default(),
            frame_transition: None,
        }
    }

    /// Build a [CallStack] from pre-built frames — used in DAP client mode.
    #[cfg(feature = "dap")]
    pub fn from_remote_frames(frames: Vec<CallFrame>) -> Self {
        Self {
            events: Arc::new(Default::default()),
            contexts: BTreeSet::default(),
            frames,
            block_stack: vec![],
            recovered: RecoveredCallStack::default(),
            frame_transition: None,
        }
    }

    pub fn stacktrace<'a>(
        &'a self,
        recent: &'a VecDeque<Operation>,
        source_manager: &'a dyn SourceManager,
    ) -> StackTrace<'a> {
        StackTrace::new(self, recent, source_manager)
    }

    pub fn current_frame(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    pub fn current_frame_mut(&mut self) -> Option<&mut CallFrame> {
        self.frames.last_mut()
    }

    pub fn frames(&self) -> &[CallFrame] {
        self.frames.as_slice()
    }

    /// Capture the current invocation for return stepping, with event fallback when needed.
    pub fn return_target(&self) -> ReturnTarget {
        self.recovered.return_target(self.frames.len())
    }

    pub fn has_returned(&self, target: &ReturnTarget) -> bool {
        target.has_returned(&self.recovered, self.frames.len())
    }

    pub fn current_invocation(&self) -> Option<InvocationId> {
        self.recovered.current_invocation()
    }

    pub fn invocation_ids(&self) -> impl Iterator<Item = InvocationId> + '_ {
        self.recovered.invocation_ids()
    }

    pub fn has_recovered_current_frame(&self) -> bool {
        self.recovered.has_current_frame()
    }

    pub fn observe_source_context(
        &mut self,
        context: &miden_processor::ResumeContext,
        current: Option<(DebugSourceNodeId, u32)>,
        asmop: Option<&AssemblyOp>,
    ) {
        self.recovered.update(context, current, asmop);
    }

    pub fn logical_frames(&self, strip_prefix: &str) -> Vec<LogicalStackFrame> {
        if self.recovered.has_current_frame() {
            return self.recovered.logical_frames(strip_prefix);
        }
        let mut logical = Vec::new();
        for (physical_index, frame) in self.frames.iter().enumerate() {
            let current_location = frame.last_logical_location();
            let location = frame
                .inline_frames
                .last()
                .map(|inline| LogicalFrameLocation::Assembly(inline.call_site.clone()))
                .or_else(|| current_location.clone());
            logical.push(LogicalStackFrame {
                name: frame.procedure(strip_prefix).unwrap_or_else(|| Arc::from("<unknown>")),
                kind: LogicalFrameKind::Physical,
                location,
                physical_index: Some(physical_index),
                origin: None,
                invocation: None,
                source: None,
            });

            for inline_index in (0..frame.inline_frames.len()).rev() {
                let inline = &frame.inline_frames[inline_index];
                let location = if inline_index == 0 {
                    current_location.clone()
                } else {
                    Some(LogicalFrameLocation::Assembly(
                        frame.inline_frames[inline_index - 1].call_site.clone(),
                    ))
                };
                logical.push(LogicalStackFrame {
                    name: Arc::from(inline.display_name().into_boxed_str()),
                    kind: LogicalFrameKind::Inline,
                    location,
                    physical_index: Some(physical_index),
                    origin: None,
                    invocation: None,
                    source: None,
                });
            }
        }
        logical
    }

    /// Takes the frame event handled by the most recent [`Self::next`], clearing it so a later
    /// cycle does not read it as its own.
    pub fn take_frame_transition(&mut self) -> Option<FrameTransition> {
        self.frame_transition.take()
    }

    /// Updates the call stack from `info`
    ///
    /// Returns the call frame exited this cycle, if any
    pub fn next(&mut self, info: &StepInfo<'_>) -> Option<CallFrame> {
        let procedure = info.asmop.map(|op| self.cache_procedure_name(op.context_name()));

        let event = {
            let mut events = self.events.write();
            match events.first_key_value() {
                Some((clk, _)) if *clk <= info.clk => events.pop_first().map(|(_, event)| event),
                _ => None,
            }
        };
        log::trace!("handling {:?}/{:?} at cycle {}: {:?}", info.control, info.op, info.clk, event);
        let is_frame_start = event.as_ref().is_some_and(|event| event.is_frame_start());
        let is_frame_end = event.as_ref().is_some_and(|event| event.is_frame_end());
        self.frame_transition = match (is_frame_start, is_frame_end) {
            (true, _) => Some(FrameTransition::Entered),
            (_, true) => Some(FrameTransition::Exited),
            _ => None,
        };
        let popped_frame = self.handle_event(event, procedure.clone(), info.op, info.asmop);

        match info.control {
            Some(ControlFlowOp::Span) => {
                if let Some(asmop) = info.asmop {
                    log::debug!("{asmop:#?}");
                    self.block_stack.push(Some(SpanContext {
                        frame_index: self.frames.len().saturating_sub(1),
                        location: asmop.location().cloned(),
                    }));
                } else {
                    self.block_stack.push(None);
                }
            }
            Some(ControlFlowOp::Join | ControlFlowOp::Split) => {
                self.block_stack.push(None);
            }
            Some(ControlFlowOp::End) => {
                self.block_stack.pop();
            }
            Some(ControlFlowOp::Respan) | None => {}
        }

        if !is_frame_end {
            if self.frames.is_empty() {
                self.frames.push(CallFrame::new(procedure.clone()));
            }
            self.frames.last_mut().unwrap().inline_frames = info.inline_frames.to_vec();
            self.update_current_procedure(procedure.clone());
        }

        if is_frame_start || is_frame_end {
            return popped_frame;
        }

        let Some(op) = info.op else {
            return popped_frame;
        };

        // Attempt to supply procedure context from the current span context, if needed +
        // available
        let (procedure, asmop) = match procedure {
            proc @ Some(_) => (proc, info.asmop.map(Cow::Borrowed)),
            None => match self.block_stack.last() {
                Some(Some(span_ctx)) => {
                    let proc =
                        self.frames.get(span_ctx.frame_index).and_then(|f| f.procedure.clone());
                    let asmop_cow = info.asmop.map(Cow::Borrowed).or_else(|| {
                        let context_name = proc.as_deref().unwrap_or("<unknown>").to_string();
                        let raw_asmop = AssemblyOp::new(
                            span_ctx.location.clone(),
                            context_name,
                            1,
                            op.to_string(),
                        );
                        Some(Cow::Owned(raw_asmop))
                    });
                    (proc, asmop_cow)
                }
                _ => (None, info.asmop.map(Cow::Borrowed)),
            },
        };

        // Use the current frame's procedure context, if no other more precise context is
        // available
        let procedure = procedure.or_else(|| self.frames.last().and_then(|f| f.procedure.clone()));

        // `exec` changes procedure context without creating a physical frame. Keep the physical
        // frame synchronized with the best context available for the current operation.
        self.update_current_procedure(procedure);
        let current_frame = self.frames.last_mut().unwrap();

        // Push op into call frame if this is any op other than `nop` or frame setup
        if !matches!(op, Operation::Noop) {
            let cycle_idx = info.asmop.map(|a| a.num_cycles()).unwrap_or(1);
            current_frame.push(op, cycle_idx, asmop.as_deref());
        }

        popped_frame
    }

    fn update_current_procedure(&mut self, procedure: Option<Arc<str>>) {
        let context_initialized = self
            .frames
            .last_mut()
            .is_some_and(|frame| frame.update_procedure(procedure.clone()));
        let num_frames = self.frames.len();
        if context_initialized && num_frames > 1 {
            let caller_frame = &mut self.frames[num_frames - 2];
            if let Some(OpDetail::Exec { callee }) = caller_frame.context.back_mut()
                && callee.is_none()
            {
                *callee = procedure;
            }
        }
    }

    // Get or cache procedure name/context as `Arc<str>`
    fn cache_procedure_name(&mut self, context_name: &str) -> Arc<str> {
        match self.contexts.get(context_name) {
            Some(name) => Arc::clone(name),
            None => {
                let name = Arc::from(context_name.to_string().into_boxed_str());
                self.contexts.insert(Arc::clone(&name));
                name
            }
        }
    }

    fn handle_event(
        &mut self,
        event: Option<Event>,
        procedure: Option<Arc<str>>,
        op: Option<Operation>,
        asmop: Option<&AssemblyOp>,
    ) -> Option<CallFrame> {
        // Do we need to handle any frame events?
        match event? {
            Event::FrameStart => {
                // Record the fact that we exec'd a new procedure in the op context
                if let Some(current_frame) = self.frames.last_mut() {
                    current_frame.push_exec(procedure.clone());
                }
                // The event is emitted at the start of the callee.
                let mut frame = CallFrame::new(procedure);
                if let Some(op) = op {
                    frame.push(op, 0, asmop);
                }
                self.frames.push(frame);
            }
            Event::Unknown(code) => log::debug!("unknown trace event: {code}"),
            Event::FrameEnd => {
                return self.frames.pop();
            }
            _ => (),
        }
        None
    }
}

pub struct CallFrame {
    procedure: Option<Arc<str>>,
    context: VecDeque<OpDetail>,
    display_name: OnceCell<Arc<str>>,
    finishing: bool,
    inline_frames: Vec<InlineCallFrame>,
}
impl CallFrame {
    pub fn new(procedure: Option<Arc<str>>) -> Self {
        Self {
            procedure,
            context: Default::default(),
            display_name: Default::default(),
            finishing: false,
            inline_frames: Vec::new(),
        }
    }

    /// Build a frame from remote (DAP) data — used in DAP client mode.
    ///
    /// The frame stores the procedure name and an optional [ResolvedLocation]
    /// as a pre-resolved `OpDetail::Full` entry so that `last_resolved()` and
    /// `recent()` work correctly for pane rendering.
    #[cfg(feature = "dap")]
    pub fn from_remote(procedure: Option<Arc<str>>, resolved: Option<ResolvedLocation>) -> Self {
        let mut context = VecDeque::new();
        if let Some(loc) = resolved {
            let cell = OnceCell::new();
            cell.set(Some(loc)).ok();
            context.push_back(OpDetail::Full {
                op: miden_processor::operation::Operation::Noop,
                location: None,
                resolved: cell,
            });
        }
        Self {
            procedure,
            context,
            display_name: Default::default(),
            finishing: false,
            inline_frames: Vec::new(),
        }
    }

    pub fn procedure(&self, strip_prefix: &str) -> Option<Arc<str>> {
        self.procedure.as_ref()?;
        let name = self.display_name.get_or_init(|| {
            let name = self.procedure.as_deref().unwrap();
            let name = match name.split_once("::") {
                Some((module, rest)) if module == strip_prefix => demangle(rest),
                _ => demangle(name),
            };
            Arc::<str>::from(name.into_boxed_str())
        });
        Some(Arc::clone(name))
    }

    /// Update this physical frame's procedure, returning true only when the context was first
    /// initialized. Later changes arise from `exec` and must invalidate the cached display name,
    /// but must not rewrite the caller's recorded callee.
    fn update_procedure(&mut self, procedure: Option<Arc<str>>) -> bool {
        let Some(procedure) = procedure else {
            return false;
        };
        if self.procedure.as_ref() == Some(&procedure) {
            return false;
        }

        let initialized = self.procedure.is_none();
        self.procedure = Some(procedure);
        self.display_name.take();
        initialized
    }

    pub fn push_exec(&mut self, callee: Option<Arc<str>>) {
        if self.context.len() == 5 {
            self.context.pop_front();
        }

        self.context.push_back(OpDetail::Exec { callee });
    }

    pub fn push(&mut self, opcode: Operation, cycle_idx: u8, op: Option<&AssemblyOp>) {
        if cycle_idx > 1 {
            // Should we ignore this op?
            let skip = self.context.back().map(|detail| matches!(detail, OpDetail::Full { op, .. } | OpDetail::Basic { op } if op == &opcode)).unwrap_or(false);
            if skip {
                return;
            }
        }

        if self.context.len() == 5 {
            self.context.pop_front();
        }

        match op {
            Some(op) => {
                let location = op.location().cloned();
                self.context.push_back(OpDetail::Full {
                    op: opcode,
                    location,
                    resolved: Default::default(),
                });
            }
            None => {
                // If this instruction does not have a location, inherit the location
                // of the previous op in the frame, if one is present
                if let Some(loc) = self.context.back().map(|op| op.location().cloned()) {
                    self.context.push_back(OpDetail::Full {
                        op: opcode,
                        location: loc,
                        resolved: Default::default(),
                    });
                } else {
                    self.context.push_back(OpDetail::Basic { op: opcode });
                }
            }
        }
    }

    pub fn last_location(&self) -> Option<&Location> {
        self.context.iter().rev().find_map(OpDetail::location)
    }

    fn last_logical_location(&self) -> Option<LogicalFrameLocation> {
        self.context.iter().rev().find_map(|detail| {
            detail
                .location()
                .cloned()
                .map(LogicalFrameLocation::Assembly)
                .or_else(|| detail.cached_resolved().cloned().map(LogicalFrameLocation::Resolved))
        })
    }

    pub fn last_resolved(&self, source_manager: &dyn SourceManager) -> Option<&ResolvedLocation> {
        // Search through context in reverse order to find the most recent op with a resolvable
        // location.
        for op in self.context.iter().rev() {
            if let Some(resolved) = op.resolve(source_manager) {
                return Some(resolved);
            }
        }
        None
    }

    pub fn recent(&self) -> &VecDeque<OpDetail> {
        &self.context
    }

    #[inline(always)]
    pub fn should_break_on_exit(&self) -> bool {
        self.finishing
    }

    #[inline(always)]
    pub fn break_on_exit(&mut self) {
        self.finishing = true;
    }
}

#[derive(Debug, Clone)]
pub enum OpDetail {
    Full {
        op: Operation,
        location: Option<Location>,
        resolved: OnceCell<Option<ResolvedLocation>>,
    },
    Exec {
        callee: Option<Arc<str>>,
    },
    Basic {
        op: Operation,
    },
}
impl OpDetail {
    pub fn callee(&self, strip_prefix: &str) -> Option<Box<str>> {
        match self {
            Self::Exec { callee: None } => Some(Box::from("<unknown>")),
            Self::Exec {
                callee: Some(callee),
            } => {
                let name = match callee.split_once("::") {
                    Some((module, rest)) if module == strip_prefix => demangle(rest),
                    _ => demangle(callee),
                };
                Some(name.into_boxed_str())
            }
            _ => None,
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Full { op, .. } | Self::Basic { op } => format!("{op}"),
            Self::Exec {
                callee: Some(callee),
            } => format!("exec.{callee}"),
            Self::Exec { callee: None } => "exec.<unavailable>".to_string(),
        }
    }

    pub fn opcode(&self) -> Operation {
        match self {
            Self::Full { op, .. } | Self::Basic { op } => *op,
            Self::Exec { .. } => panic!("no opcode associated with execs"),
        }
    }

    pub fn location(&self) -> Option<&Location> {
        match self {
            Self::Full { location, .. } => location.as_ref(),
            Self::Basic { .. } | Self::Exec { .. } => None,
        }
    }

    pub fn resolve(&self, source_manager: &dyn SourceManager) -> Option<&ResolvedLocation> {
        match self {
            Self::Full {
                location, resolved, ..
            } => {
                if let Some(cached) = resolved.get() {
                    return cached.as_ref();
                }
                let loc = location.as_ref()?;
                resolved
                    .get_or_init(|| {
                        let source_file = resolve_source_file_for_location(source_manager, loc)?;
                        let span = SourceSpan::new(source_file.id(), loc.start..loc.end);
                        let file_line_col = source_file.location(span);
                        Some(ResolvedLocation {
                            source_file,
                            line: file_line_col.line.to_u32(),
                            col: file_line_col.column.to_u32(),
                            span,
                        })
                    })
                    .as_ref()
            }
            _ => None,
        }
    }

    fn cached_resolved(&self) -> Option<&ResolvedLocation> {
        match self {
            Self::Full { resolved, .. } => resolved.get().and_then(Option::as_ref),
            Self::Exec { .. } | Self::Basic { .. } => None,
        }
    }
}

/// Resolve a source file for `location`.
///
/// Compiled packages may contain remapped paths such as `src/lib.rs`, while sources loaded by the
/// VM host may be keyed by an absolute path, or may not be loaded yet at all. Prefer the source
/// manager's existing URI table, then fall back to loading the file from disk.
#[cfg(feature = "std")]
pub fn resolve_source_file_for_location(
    source_manager: &dyn SourceManager,
    location: &Location,
) -> Option<Arc<SourceFile>> {
    use miden_assembly_syntax::debuginfo::SourceManagerExt;
    source_manager.get_by_uri(location.uri()).or_else(|| {
        resolve_source_path(location.uri()).and_then(|path| source_manager.load_file(&path).ok())
    })
}

#[cfg(not(feature = "std"))]
pub fn resolve_source_file_for_location(
    source_manager: &dyn SourceManager,
    location: &Location,
) -> Option<Arc<SourceFile>> {
    source_manager.get_by_uri(location.uri())
}

/// Resolve a source URI to an existing local filesystem path.
///
/// Non-file URI schemes are left to the source manager. Relative paths are resolved against the
/// debugger process' current directory, which DAP clients set to the launch `cwd`.
#[cfg(feature = "std")]
pub fn resolve_source_path(uri: &Uri) -> Option<PathBuf> {
    let path = match uri.scheme() {
        None | Some("file") => uri.to_path()?,
        Some(_) => return None,
    };

    fn existing_path(path: &Path) -> Option<PathBuf> {
        path.exists()
            .then(|| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
    }

    existing_path(&path).or_else(|| {
        if path.is_relative() {
            std::env::current_dir().ok().and_then(|cwd| existing_path(&cwd.join(path)))
        } else {
            None
        }
    })
}

/// Resolve a source location directly from the filesystem, returning the resolved path and line.
#[cfg(feature = "std")]
pub fn resolve_location_from_filesystem(location: &Location) -> Option<(PathBuf, u32)> {
    let path = resolve_source_path(location.uri())?;
    let bytes = std::fs::read(&path).ok()?;
    let start = location.start.to_usize().min(bytes.len());
    let line = bytes[..start].iter().filter(|byte| **byte == b'\n').count() as u32 + 1;
    Some((path, line))
}

/// Returns true for source paths emitted by compiler/runtime internals rather than user code.
pub fn is_internal_source_uri(uri: &Uri) -> bool {
    let path = uri.as_str().replace('\\', "/");
    path.contains("/codegen/masm/intrinsics/") || path.contains("/rustlib/src/rust/library/")
}

#[derive(Debug, Clone)]
pub struct ResolvedLocation {
    pub source_file: Arc<SourceFile>,
    // TODO(fabrio): Use LineNumber and ColumnNumber instead of raw `u32`.
    pub line: u32,
    pub col: u32,
    pub span: SourceSpan,
}
impl fmt::Display for ResolvedLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.source_file.uri().as_str(), self.line, self.col)
    }
}

pub struct CurrentFrame {
    pub procedure: Option<Arc<str>>,
    pub location: Option<ResolvedLocation>,
}

pub struct StackTrace<'a> {
    callstack: &'a CallStack,
    recent: &'a VecDeque<Operation>,
    source_manager: &'a dyn SourceManager,
    current_frame: Option<CurrentFrame>,
}

impl<'a> StackTrace<'a> {
    pub fn new(
        callstack: &'a CallStack,
        recent: &'a VecDeque<Operation>,
        source_manager: &'a dyn SourceManager,
    ) -> Self {
        let current_frame = callstack.logical_frames("").last().map(|frame| {
            let location = frame.resolved(source_manager);
            let procedure = Some(Arc::from(frame.display_name().into_boxed_str()));
            CurrentFrame {
                procedure,
                location,
            }
        });
        Self {
            callstack,
            recent,
            source_manager,
            current_frame,
        }
    }

    pub fn current_frame(&self) -> Option<&CurrentFrame> {
        self.current_frame.as_ref()
    }
}

impl fmt::Display for StackTrace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::Write;

        let frames = self.callstack.logical_frames("");
        let num_frames = frames.len();

        writeln!(f, "\nStack Trace:")?;

        for (i, frame) in frames.iter().enumerate() {
            let is_top = i + 1 == num_frames;
            let name = frame.display_name();
            if is_top {
                write!(f, " `-> {name}")?;
            } else {
                write!(f, " |-> {name}")?;
            }
            if let Some(resolved) = frame.resolved(self.source_manager) {
                write!(f, " in {resolved}")?;
            } else {
                write!(f, " in <unavailable>")?;
            }
            if is_top {
                let context = self.callstack.current_frame().map(CallFrame::recent);
                // A failure can have recovered source frames before any physical frame exists.
                let context_size = context.map_or(0, VecDeque::len);
                writeln!(f, ":\n\nLast {context_size} Instructions (of current frame):")?;
                for (i, op) in context.into_iter().flatten().enumerate() {
                    let is_last = i + 1 == context_size;
                    if let Some(callee) = op.callee("") {
                        write!(f, " |   exec.{callee}")?;
                    } else {
                        write!(f, " |   {}", op.opcode())?;
                    }
                    if is_last {
                        writeln!(f, "\n `-> <error occurred here>")?;
                    } else {
                        f.write_char('\n')?;
                    }
                }

                let context_size = self.recent.len();
                writeln!(f, "\n\nLast {context_size} Instructions (any frame):")?;
                for (i, op) in self.recent.iter().enumerate() {
                    let is_last = i + 1 == context_size;
                    if is_last {
                        writeln!(f, " |   {}", op)?;
                        writeln!(f, " `-> <error occurred here>")?;
                    } else {
                        writeln!(f, " |   {}", op)?;
                    }
                }
            } else {
                f.write_char('\n')?;
            }
        }

        Ok(())
    }
}

fn resolve_assembly_location(
    source_manager: &dyn SourceManager,
    location: &Location,
) -> Option<ResolvedLocation> {
    let source_file = resolve_source_file_for_location(source_manager, location)?;
    let span = SourceSpan::new(source_file.id(), location.start..location.end);
    let file_line_col = source_file.location(span);
    Some(ResolvedLocation {
        source_file,
        line: file_line_col.line.to_u32(),
        col: file_line_col.column.to_u32(),
        span,
    })
}

#[cfg(feature = "std")]
pub(super) fn demangle(name: &str) -> String {
    let mut input = name.as_bytes();
    let mut demangled = Vec::with_capacity(input.len() * 2);
    rustc_demangle::demangle_stream(&mut input, &mut demangled, /* include_hash= */ false)
        .expect("failed to write demangled identifier");
    String::from_utf8(demangled).expect("demangled identifier contains invalid utf-8")
}

#[cfg(not(feature = "std"))]
pub(super) fn demangle(name: &str) -> String {
    // Assembly contexts qualify the linkage symbol with a package/module path.
    match name.rsplit_once("::") {
        Some((prefix, symbol)) => format!("{prefix}::{:#}", rustc_demangle::demangle(symbol)),
        None => format!("{:#}", rustc_demangle::demangle(name)),
    }
}

#[cfg(test)]
mod tests;
