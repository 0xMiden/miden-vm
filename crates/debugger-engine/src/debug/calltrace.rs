use alloc::{string::String, vec::Vec};

use super::{InvocationId, LogicalStackFrame};

/// The hierarchy of calls made during an execution.
#[derive(Debug, Default)]
pub struct CallTrace {
    pub roots: Vec<CallFrameRecord>,
}

/// A single call, with the calls it made nested underneath.
#[derive(Debug)]
pub struct CallFrameRecord {
    pub callee: Option<String>,
    pub enter_clk: usize,
    pub exit_clk: Option<usize>,
    pub args: Vec<TracedArg>,
    /// Returned values, top of the stack first, or `None` when they could not be worked out.
    pub results: Option<Vec<u64>>,
    pub children: Vec<CallFrameRecord>,
}

/// A single argument of a traced call.
#[derive(Debug)]
pub struct TracedArg {
    pub index: u32,
    pub name: String,
    /// How many stack elements the argument takes, or `None` if its type is not known.
    pub felt_count: Option<usize>,
    /// The argument's felts, or `None` if its width is not known or they could not be read.
    pub values: Option<Vec<u64>>,
}

impl CallFrameRecord {
    /// Number of cycles spent in this frame, including its children.
    pub fn cycles(&self) -> Option<usize> {
        self.exit_clk.map(|exit| exit.saturating_sub(self.enter_clk))
    }
}

/// Builds a [`CallTrace`] from frame entries and exits reported in execution order.
#[derive(Default)]
pub struct CallTraceRecorder {
    /// Frames that started and did not end yet. The last one is the current frame.
    open: Vec<OpenFrame>,
    /// Frames that ended when no parent frame was open.
    roots: Vec<CallFrameRecord>,
}

struct OpenFrame {
    record: CallFrameRecord,
    /// Source context while selecting the callee; cleared once selected or unrecoverable.
    caller: Option<Vec<LogicalStackFrame>>,
    /// Felts the callee returns; `None` means unknown.
    output_felt_count: Option<usize>,
    argument_owner: Option<InvocationId>,
    /// Set once this frame makes a call, after which arguments are no longer recorded.
    args_sealed: bool,
}

impl CallTraceRecorder {
    /// Open a frame entered at `clk`.
    pub fn enter(&mut self, clk: usize, caller: Vec<LogicalStackFrame>) {
        if let Some(parent) = self.open.last_mut() {
            parent.args_sealed = true;
        }
        self.open.push(OpenFrame {
            record: CallFrameRecord {
                callee: None,
                enter_clk: clk,
                exit_clk: None,
                args: Vec::new(),
                results: None,
                children: Vec::new(),
            },
            caller: (!caller.is_empty()).then_some(caller),
            output_felt_count: None,
            argument_owner: None,
            args_sealed: false,
        });
    }

    /// Whether source context is still needed to select the innermost callee.
    pub fn needs_callee(&self) -> bool {
        self.open.last().is_some_and(|frame| frame.caller.is_some())
    }

    /// Stop selecting a callee after entering code whose source invocation is unknown.
    /// Later recovered descendants cannot identify the missing invocation.
    pub fn stop_callee_search(&mut self) {
        if let Some(frame) = self.open.last_mut() {
            frame.caller = None;
        }
    }

    /// The first new logical callee beneath the caller observed at the start marker.
    /// Source identities distinguish recursion and aliases even when their names or code match.
    pub fn pending_callee<'a>(
        &self,
        frames: &'a [LogicalStackFrame],
    ) -> Option<&'a LogicalStackFrame> {
        let caller = self.open.last()?.caller.as_ref()?;
        if !caller
            .iter()
            .zip(frames)
            .all(|(caller, current)| caller.is_same_source_frame(current))
        {
            return None;
        }
        frames.get(caller.len())
    }

    /// Freeze the selected callee's name, result width, and argument ownership together.
    pub fn observe_callee(
        &mut self,
        name: &str,
        output_felt_count: Option<usize>,
        argument_owner: Option<InvocationId>,
    ) {
        if let Some(frame) = self.open.last_mut()
            && frame.record.callee.is_none()
        {
            frame.caller = None;
            frame.record.callee = Some(String::from(name));
            frame.output_felt_count = output_felt_count;
            frame.argument_owner = argument_owner;
        }
    }

    pub fn argument_owner(&self) -> Option<InvocationId> {
        self.open.last()?.argument_owner
    }

    /// The cycle the innermost open frame was entered at, while it still takes arguments.
    ///
    /// `None` once that frame has made a call of its own, which seals its arguments.
    pub fn accepting_args(&self) -> Option<usize> {
        self.open
            .last()
            .filter(|frame| !frame.args_sealed)
            .map(|frame| frame.record.enter_clk)
    }

    /// Whether the innermost open frame already holds the argument at `index`.
    ///
    /// Lets the caller skip re-reading the argument from VM memory on every cycle, since
    /// [`Self::observe_arg`] keeps the first value observed.
    pub fn has_arg(&self, index: u32) -> bool {
        self.open
            .last()
            .is_some_and(|frame| frame.record.args.iter().any(|arg| arg.index == index))
    }

    /// Records an argument of the innermost frame. Only the first value is kept, because the body
    /// can overwrite a parameter.
    ///
    /// ```text
    /// fn function_1(mut op: Felt) { op = 99; .. }
    ///
    /// op = 3    value at the call   -> kept
    /// op = 99   written by the body -> skipped
    /// ```
    pub fn observe_arg(
        &mut self,
        index: u32,
        name: &str,
        felt_count: Option<usize>,
        values: Option<Vec<u64>>,
    ) {
        let Some(frame) = self.open.last_mut() else {
            return;
        };
        if frame.args_sealed || frame.record.args.iter().any(|arg| arg.index == index) {
            return;
        }
        frame.record.args.push(TracedArg {
            index,
            name: String::from(name),
            felt_count,
            values,
        });
    }

    /// Closes the innermost frame at `clk`; its results are the top
    /// [`Self::observe_callee`] felts of `stack`.
    ///
    /// ```text
    /// -> Felt          width 1     -> results = [top felt]
    /// returns nothing  width 0     -> results = []
    /// no signature     width None  -> results = None (unknown)
    /// ```
    pub fn exit(&mut self, clk: usize, stack: &[u64]) {
        let Some(frame) = self.open.pop() else {
            return;
        };
        let mut record = frame.record;
        record.exit_clk = Some(clk);

        // If the stack is shorter than the width, the width is wrong, so the result is unknown.
        record.results = frame
            .output_felt_count
            .and_then(|count| (stack.len() >= count).then(|| stack[..count].to_vec()));

        self.attach(record);
    }

    /// Return the trace, leaving frames that are still open without an exit cycle.
    pub fn finish(mut self) -> CallTrace {
        while let Some(frame) = self.open.pop() {
            self.attach(frame.record);
        }
        CallTrace { roots: self.roots }
    }

    /// Put a closed frame in its place in the tree, with its arguments in signature order.
    fn attach(&mut self, mut frame: CallFrameRecord) {
        frame.args.sort_by_key(|arg| arg.index);
        match self.open.last_mut() {
            Some(parent) => parent.record.children.push(frame),
            None => self.roots.push(frame),
        }
    }
}

#[cfg(test)]
mod tests;
