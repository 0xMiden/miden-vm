use core::ops::ControlFlow;

use miden_core::events::{EventId, SystemEvent};
use miden_event_handler::{AdviceBatch, InvocationKind};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, Host, SyncHost,
    advice::AdviceError,
    errors::{
        MapExecErrWithOpIdx, PackageSourceDebugContext, advice_error_with_context,
        advice_error_with_package_source_context, event_error_with_context,
        event_error_with_package_source_context,
    },
    event::EventError,
    fast::{BreakReason, FastProcessor},
    host::{
        LegacyHostFallback,
        handlers::{event_context, record_mutations},
    },
};

mod deferred_handlers;
mod sys_event_handlers;
pub use sys_event_handlers::SystemEventError;
use sys_event_handlers::handle_system_event;

impl FastProcessor {
    #[inline(always)]
    fn handle_system_event<F>(
        &mut self,
        system_event: SystemEvent,
        host: &impl BaseHost,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let context = package_source_context(package_debug_info, source_node_id);
        match handle_system_event(self, system_event)
            .map_exec_err_with_package_source_op_idx(context, host, op_idx)
        {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(err)),
        }
    }

    #[inline(always)]
    fn complete_host_event<F>(
        &mut self,
        host: &impl BaseHost,
        op_idx: usize,
        event_id: EventId,
        kind: InvocationKind,
        result: Result<(), EventError>,
        batch: AdviceBatch,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        match result {
            Ok(()) => (),
            Err(err) => {
                let event_name = match kind {
                    InvocationKind::Event => host.resolve_event(event_id),
                    InvocationKind::Trace => host.resolve_trace(event_id),
                }
                .cloned();
                let context = package_source_context(package_debug_info, source_node_id);
                if let Some(context) = context {
                    return ControlFlow::Break(BreakReason::Err(
                        event_error_with_package_source_context(
                            err,
                            context,
                            host,
                            Some(op_idx),
                            event_id,
                            event_name,
                        ),
                    ));
                }
                return ControlFlow::Break(BreakReason::Err(event_error_with_context(
                    err, event_id, event_name,
                )));
            },
        };

        let applied = match kind {
            InvocationKind::Trace if !batch.is_empty() => Err(AdviceError::TraceAdvice),
            InvocationKind::Trace => Ok(()),
            InvocationKind::Event => self.advice.apply_batch(batch),
        };
        match applied {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => {
                let context = package_source_context(package_debug_info, source_node_id);
                let err = if let Some(context) = context {
                    advice_error_with_package_source_context(err, context, host, Some(op_idx))
                } else {
                    advice_error_with_context(err)
                };
                ControlFlow::Break(BreakReason::Err(err))
            },
        }
    }

    #[inline(always)]
    pub(super) fn op_emit_sync<F>(
        &mut self,
        host: &mut impl SyncHost,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let raw_id = EventId::from_felt(self.stack_get(0));
        let kind = match SystemEvent::from_event_id(raw_id) {
            Some(SystemEvent::TraceEvent) if !self.options.trace_delivery() => {
                return ControlFlow::Continue(());
            },
            Some(SystemEvent::TraceEvent) => InvocationKind::Trace,
            Some(system_event) => {
                return self.handle_system_event(
                    system_event,
                    host,
                    op_idx,
                    package_debug_info,
                    source_node_id,
                );
            },
            None => InvocationKind::Event,
        };
        let state = self.state();
        let context = event_context(&state, kind);
        let event_id = context.id();
        let mut batch = AdviceBatch::new();
        let mut result = host.handle_event(context, &mut batch.recorder());
        // Only the engine can bridge a portable callback to full legacy state. Never retain
        // advice staged by a callback that requested fallback after recording output.
        if batch.is_empty() && result.as_ref().is_err_and(|error| error.is::<LegacyHostFallback>())
        {
            result = match kind {
                InvocationKind::Event => host
                    .on_event(&state)
                    .map(|mutations| record_mutations(&mut batch.recorder(), mutations)),
                InvocationKind::Trace => host.on_trace(&state),
            };
        }
        self.complete_host_event(
            host,
            op_idx,
            event_id,
            kind,
            result,
            batch,
            package_debug_info,
            source_node_id,
        )
    }

    #[inline(always)]
    pub(super) async fn op_emit<F>(
        &mut self,
        host: &mut impl Host,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let raw_id = EventId::from_felt(self.stack_get(0));
        let kind = match SystemEvent::from_event_id(raw_id) {
            Some(SystemEvent::TraceEvent) if !self.options.trace_delivery() => {
                return ControlFlow::Continue(());
            },
            Some(SystemEvent::TraceEvent) => InvocationKind::Trace,
            Some(system_event) => {
                return self.handle_system_event(
                    system_event,
                    host,
                    op_idx,
                    package_debug_info,
                    source_node_id,
                );
            },
            None => InvocationKind::Event,
        };
        let state = self.state();
        let context = event_context(&state, kind);
        let event_id = context.id();
        let mut batch = AdviceBatch::new();
        let mut result = host.handle_event(context, &mut batch.recorder()).await;
        // Only the engine can bridge a portable callback to full legacy state. Never retain
        // advice staged by a callback that requested fallback after recording output.
        if batch.is_empty() && result.as_ref().is_err_and(|error| error.is::<LegacyHostFallback>())
        {
            result = match kind {
                InvocationKind::Event => host
                    .on_event(&state)
                    .await
                    .map(|mutations| record_mutations(&mut batch.recorder(), mutations)),
                InvocationKind::Trace => host.on_trace(&state).await,
            };
        }
        self.complete_host_event(
            host,
            op_idx,
            event_id,
            kind,
            result,
            batch,
            package_debug_info,
            source_node_id,
        )
    }
}

fn package_source_context(
    package_debug_info: Option<&PackageDebugInfo>,
    source_node_id: Option<DebugSourceNodeId>,
) -> Option<PackageSourceDebugContext<'_>> {
    Some(PackageSourceDebugContext::new_optional(package_debug_info?, source_node_id))
}
