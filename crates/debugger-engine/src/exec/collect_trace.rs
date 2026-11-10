use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use miden_core::FMP_ADDR;
use miden_debug_types::DefaultSourceManager;
use miden_processor::{ExecutionError, Felt, event::EventId};

use super::{
    DebugQuery, Event, ExecutionConfig, Executor, ReplaySnapshot,
    source::SourceContext,
    state::{DebugExecutor, Observation},
};
use crate::debug::{
    CallTrace, CallTraceRecorder, DebugVarSnapshot, FrameTransition, resolve_typed_variable_values,
    return_felt_count, value_felt_count,
};

/// The result of replaying a recorded execution with [`replay_call_trace`].
pub struct CallTraceReplay {
    pub trace: CallTrace,
    pub cycles: usize,
    pub error: Option<ExecutionError>,
}

/// Replay `recording` and collect its call trace.
///
/// Calls with insufficient source metadata retain their timing and children, but may have no
/// callee name, arguments, or result values. Callee recovery conservatively stops at metadata gaps.
pub fn replay_call_trace(recording: ReplaySnapshot) -> CallTraceReplay {
    let ReplaySnapshot {
        package,
        stack_inputs,
        advice_inputs,
        options,
        event_log,
        mast_forests,
    } = recording;

    let executor = Executor::from_config(ExecutionConfig {
        inputs: stack_inputs,
        advice_inputs,
        options,
    });
    let mut executor = executor.into_debug_with_replay(
        package,
        Arc::new(DefaultSourceManager::default()),
        mast_forests,
        VecDeque::from(event_log),
    );

    let (trace, error) = collect_call_trace(&mut executor);

    CallTraceReplay {
        trace,
        cycles: executor.cycle,
        error,
    }
}

/// Run `executor` to completion and collect its call trace.
///
/// If execution fails, the trace collected up to the failure is returned alongside the error.
fn collect_call_trace(executor: &mut DebugExecutor) -> (CallTrace, Option<ExecutionError>) {
    let mut recorder = CallTraceRecorder::default();
    let mut error = None;

    while !executor.stopped {
        if let Err(err) = executor.step_with_observer(|observed| {
            observe_callee(&mut recorder, observed);
            observe_arguments(&mut recorder, observed);
        }) {
            error = Some(err);
            break;
        }
        // The last step runs no cycle, so the executor state is stale and must not be read.
        if executor.stopped {
            break;
        }

        let clk = executor.cycle;
        // Frame events open and close frames, even when the call stack has nothing to pop.
        let transition = executor.callstack.take_frame_transition();

        // Only `exit` uses the stack.
        let stack = match transition {
            Some(FrameTransition::Exited) => stack_without_frame_marker(&executor.current_stack),
            _ => Vec::new(),
        };

        match transition {
            Some(FrameTransition::Exited) => recorder.exit(clk, &stack),
            // On the entry cycle execution is still in the caller, so the callee is named later.
            Some(FrameTransition::Entered) => {
                recorder.enter(clk, executor.callstack.logical_frames(""));
            }
            None => {}
        }
    }

    (recorder.finish(), error)
}

fn observe_callee(recorder: &mut CallTraceRecorder, observed: &Observation<'_>) {
    if !recorder.needs_callee() {
        return;
    }
    if !observed.callstack.has_recovered_current_frame() || has_metadata_gap(observed.source) {
        recorder.stop_callee_search();
        return;
    }
    let frames = observed.callstack.logical_frames("");
    if let Some(callee) = recorder.pending_callee(&frames)
        && let Some((info, function)) = callee.debug_info().zip(callee.function())
    {
        recorder.observe_callee(
            &info[function.name_idx],
            return_felt_count(info, function),
            callee.invocation_id(),
        );
    }
}

/// A stripped static import can retain a source node and recovered ancestors without attribution
/// for its own code. Do not let a later unmarked descendant supply its name or result signature.
///
/// This is deliberately a call-trace heuristic: an empty source occurrence may also be generated
/// code, while inherited inline rows or merged operations can hide a gap. On a detected gap we
/// prefer an unnamed frame, preserving its timing and independently marked children.
///
/// TODO: Remove this heuristic when the processor resolver exposes active-invocation recovery
/// evidence that distinguishes the current invocation from retained ancestors.
fn has_metadata_gap(source: &SourceContext) -> bool {
    source
        .source_node()
        .is_none_or(|node| node.asm_ops.is_empty() && node.inline_calls.is_empty())
}

fn observe_arguments(recorder: &mut CallTraceRecorder, observed: &Observation<'_>) {
    // Only inspect the selected physical invocation. Inline-local ownership is not
    // available, so an exec-only wrapper must not borrow an unmarked leaf's arguments.
    if let Some(enter_clk) = recorder.accepting_args()
        && let Some(owner) = recorder.argument_owner()
        && observed.debug_vars.current_invocation() == Some(owner)
    {
        for snapshot in observed.debug_vars.current_variables() {
            let Some(index) = snapshot.info.arg_index() else {
                continue;
            };
            // Up to and including `enter_clk`, variables belong to the caller.
            if usize::from(snapshot.clk) <= enter_clk {
                continue;
            }
            // Already recorded, so skip reading VM memory again.
            if recorder.has_arg(index.get()) {
                continue;
            }
            // An untyped argument has no width, so it is recorded by name only.
            let ty = snapshot.info.ty();
            let felt_count = ty.and_then(value_felt_count);
            let values = felt_count
                .zip(ty)
                .and_then(|(count, ty)| resolve_arg_values(observed, snapshot, ty, count));
            recorder.observe_arg(index.get(), snapshot.info.name(), felt_count, values);
        }
    }
}

/// Read `count` consecutive felts of a typed argument out of the VM state.
fn resolve_arg_values(
    observed: &Observation<'_>,
    snapshot: &DebugVarSnapshot,
    ty: &miden_assembly_syntax::ast::types::Type,
    count: usize,
) -> Option<Vec<u64>> {
    let to_u64 = |values: Vec<Felt>| values.iter().map(Felt::as_canonical_u64).collect();

    // `Stack` locations are resolved at the debug decorator and rewritten to a `Const`, which
    // holds a single felt (see `snapshot_transient_debug_values`). Anything wider than one felt
    // survives only in the capture.
    if let Some(captured) = observed.debug_vars.captured_values(snapshot.info.name())
        && captured.len() == count
    {
        return Some(to_u64(captured.to_vec()));
    }

    let read_memory = |addr: u32| observed.read_memory_element(addr);
    let read_local = |offset: i16| {
        let fmp = read_memory(FMP_ADDR.as_canonical_u64() as u32)?;
        let fmp = u32::try_from(fmp.as_canonical_u64()).ok()?;
        read_memory(fmp.checked_add_signed(i32::from(offset))?)
    };

    resolve_typed_variable_values(
        snapshot.info.value_location(),
        ty,
        count,
        observed.current_stack,
        read_memory,
        read_local,
    )
    .map(to_u64)
}

fn stack_without_frame_marker(stack: &[Felt]) -> Vec<u64> {
    // `emit.event(...)` pushes the event id, so drop the top element when it is a frame event id.
    let is_marker = |value: &Felt| {
        let id = EventId::from_felt(*value);
        id == Event::FrameStart.as_event_id() || id == Event::FrameEnd.as_event_id()
    };

    let rest = match stack.split_first() {
        Some((top, rest)) if is_marker(top) => rest,
        _ => stack,
    };

    rest.iter().map(Felt::as_canonical_u64).collect()
}

#[cfg(test)]
mod tests;
