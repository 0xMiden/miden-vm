use miden_processor::{DebugCallFrame, DebugCallFrameResolver, ResumeContext};

use super::*;

/// Session-owned source-frame recovery, independent of the event stack used for execution control.
#[derive(Default)]
pub struct RecoveredCallStack {
    resolver: DebugCallFrameResolver,
    frames: Vec<RecoveredFrame>,
    current_frame_recovered: bool,
    next_invocation: u64,
}

/// Session-local identity of a recovered invocation, independent of stack position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvocationId(pub(crate) u64);

struct RecoveredFrame {
    invocation: InvocationId,
    identity: DebugCallFrame,
    location: Option<Location>,
    inline_frames: Vec<RecoveredInlineFrame>,
}

struct RecoveredInlineFrame {
    display: InlineCallFrame,
    info: Arc<PackageDebugInfo>,
    function_idx: DebugFunctionIdx,
}

/// An invocation to finish, captured before execution resumes.
///
/// Source identity distinguishes recursive invocations. Event depth is used only when no
/// invocation can be recovered at the point where the target is captured.
#[derive(Clone)]
pub struct ReturnTarget {
    invocation: Option<DebugCallFrame>,
    event_depth: usize,
}

impl ReturnTarget {
    pub fn is_recovered(&self) -> bool {
        self.invocation.is_some()
    }

    pub fn has_returned(&self, stack: &RecoveredCallStack, event_depth: usize) -> bool {
        match self.invocation.as_ref() {
            Some(invocation) => {
                !stack.frames.iter().any(|frame| frame.identity.is_same_frame(invocation))
            }
            None => event_depth < self.event_depth,
        }
    }
}

impl RecoveredCallStack {
    pub fn current_invocation(&self) -> Option<InvocationId> {
        self.frames
            .last()
            .filter(|_| self.current_frame_recovered)
            .map(|frame| frame.invocation)
    }

    pub fn invocation_ids(&self) -> impl Iterator<Item = InvocationId> + '_ {
        self.frames.iter().map(|frame| frame.invocation)
    }

    pub fn return_target(&self, event_depth: usize) -> ReturnTarget {
        ReturnTarget {
            invocation: self
                .frames
                .last()
                .filter(|_| self.current_frame_recovered)
                .map(|frame| frame.identity.clone()),
            event_depth,
        }
    }

    /// Whether the innermost recovered frame belongs to the active package. A stripped callee
    /// may leave recovered ancestors visible without providing a frame for the current invocation.
    pub fn has_current_frame(&self) -> bool {
        self.current_frame_recovered
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Observe the operation about to execute. Suspended callers retain their last source location.
    pub fn update(
        &mut self,
        context: &ResumeContext,
        current: Option<(DebugSourceNodeId, u32)>,
        asmop: Option<&AssemblyOp>,
    ) {
        let identities = self.resolver.resolve(context);
        let common = self
            .frames
            .iter()
            .zip(&identities)
            .take_while(|(old, new)| old.identity.is_same_frame(new))
            .count();
        self.frames.truncate(common);
        for (index, identity) in identities.into_iter().enumerate() {
            if let Some(frame) = self.frames.get_mut(index) {
                frame.identity = identity;
                continue;
            }
            let invocation = InvocationId(self.next_invocation);
            self.next_invocation =
                self.next_invocation.checked_add(1).expect("invocation identity exhausted");
            self.frames.push(RecoveredFrame {
                invocation,
                identity,
                location: None,
                inline_frames: Vec::new(),
            });
        }

        let debug_info = context.debug_info();
        self.current_frame_recovered = self
            .frames
            .last()
            .zip(debug_info.as_deref())
            .is_some_and(|(frame, info)| core::ptr::eq(frame.identity.debug_info(), info));
        let mut rows = Vec::new();
        if let Some((info, (source, operation))) = debug_info.as_ref().zip(current) {
            rows.extend(info.inline_calls_for_operation(source, operation).map(|row| (info, row)));
        }
        for inherited in context.inherited_inline_call_contexts() {
            rows.extend(inherited.inline_calls().map(|row| (inherited.debug_info(), row)));
        }
        rows.reverse();

        for index in 0..self.frames.len() {
            let start = self.frames[index].identity.inherited_inline_calls().min(rows.len());
            let next = self.frames.get(index + 1);
            let end = next
                .map_or(rows.len(), |next| next.identity.inherited_inline_calls().min(rows.len()));
            // An exec boundary is represented both by an inline row and a recovered invocation.
            // Compare package/function identities: names cannot distinguish aliases or recursion.
            // Across packages, the imported declaration and loaded definition share a MAST root,
            // but their function indices belong to different tables.
            let boundary = next.and_then(|next| {
                let (info, row) = *rows.get(end.checked_sub(1)?)?;
                let same_function = if core::ptr::eq(info.as_ref(), next.identity.debug_info()) {
                    row.callee_idx == next.identity.function_idx()
                } else {
                    info.get_function(row.callee_idx)?.mast_root
                        == next.identity.function().mast_root
                };
                (end > start && same_function).then_some((info, row))
            });
            let top = index + 1 == self.frames.len();
            let frame = &mut self.frames[index];
            if top || end > start {
                let own_end = end - usize::from(boundary.is_some());
                frame.inline_frames.clear();
                for (info, row) in rows[start..own_end.max(start)].iter().rev() {
                    let Some(function) = info.get_function(row.callee_idx) else {
                        continue;
                    };
                    let Some(name) = info.get_string(function.name_idx) else {
                        continue;
                    };
                    let Some(call_site) = info.get_location(row.loc_idx) else {
                        continue;
                    };
                    frame.inline_frames.push(RecoveredInlineFrame {
                        display: InlineCallFrame { name, call_site },
                        info: Arc::clone(info),
                        function_idx: row.callee_idx,
                    });
                }
            }
            if let Some((info, row)) = boundary {
                frame.location = info.get_location(row.loc_idx);
            } else if top && let Some(location) = asmop.and_then(AssemblyOp::location) {
                frame.location = Some(location.clone());
            }
        }
    }

    pub fn logical_frames(&self, strip_prefix: &str) -> Vec<LogicalStackFrame> {
        let mut logical = Vec::new();
        for frame in &self.frames {
            let name = &frame.identity.debug_info()[frame.identity.function().name_idx];
            let name = name.trim_start_matches("::");
            let name = match name.split_once("::") {
                Some((module, rest)) if module == strip_prefix => rest,
                _ => name,
            };
            let location = frame
                .inline_frames
                .last()
                .map(|inline| &inline.display.call_site)
                .or(frame.location.as_ref())
                .cloned()
                .map(LogicalFrameLocation::Assembly);
            logical.push(LogicalStackFrame {
                name: Arc::from(demangle(name)),
                kind: LogicalFrameKind::Physical,
                location,
                physical_index: None,
                origin: Some(frame.identity.origin()),
                invocation: Some(frame.invocation),
                source: Some(LogicalFrameSource::Physical(frame.identity.clone())),
            });
            for index in (0..frame.inline_frames.len()).rev() {
                let inline = &frame.inline_frames[index];
                let location = if index == 0 {
                    frame.location.clone()
                } else {
                    Some(frame.inline_frames[index - 1].display.call_site.clone())
                };
                logical.push(LogicalStackFrame {
                    name: Arc::from(inline.display.display_name()),
                    kind: LogicalFrameKind::Inline,
                    location: location.map(LogicalFrameLocation::Assembly),
                    physical_index: None,
                    origin: None,
                    invocation: None,
                    source: Some(LogicalFrameSource::Inline {
                        owner: frame.invocation,
                        info: Arc::clone(&inline.info),
                        function_idx: inline.function_idx,
                        call_site: inline.display.call_site.clone(),
                    }),
                });
            }
        }
        logical
    }
}

#[cfg(test)]
mod tests;
