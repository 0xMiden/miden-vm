use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::events::{EventId, EventName};
use miden_event_handler::{AdviceBatch, AdviceRecorder, EventContext, Invocation, InvocationKind};

use super::{EventError, EventHandler, registration, validate_event_name};
use crate::{ExecutionError, ProcessorState, advice::AdviceMutation};

/// One portable handler binding per identity, shared by regular events and traces.
#[derive(Default)]
pub struct HandlerRegistry {
    handlers: BTreeMap<EventId, (EventName, registration::EventHandler)>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a handler for either invocation kind. Duplicate identities, empty names, and
    /// reserved namespaces are rejected without changing the registry.
    pub fn register(
        &mut self,
        name: EventName,
        handler: impl Into<registration::EventHandler>,
    ) -> Result<(), ExecutionError> {
        validate_event_name(&name)?;
        let id = name.to_event_id();
        if self.handlers.contains_key(&id) {
            return Err(crate::errors::HostError::DuplicateEventHandler { event: name }.into());
        }
        self.handlers.insert(id, (name, handler.into()));
        Ok(())
    }

    pub fn unregister(&mut self, id: EventId) -> bool {
        self.handlers.remove(&id).is_some()
    }

    pub fn resolve(&self, id: EventId) -> Option<&EventName> {
        self.handlers.get(&id).map(|(name, _)| name)
    }

    /// Dispatches by routing key, preserving the actual invocation metadata in `context`.
    /// Returns false for an unknown key. Writes share the caller's recorder even on error; use a
    /// child batch when a caught helper failure must discard that helper's pending output.
    pub fn handle_event(
        &self,
        id: EventId,
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> Result<bool, EventError> {
        let Some((_, handler)) = self.handlers.get(&id) else {
            return Ok(false);
        };
        handler.as_ref().handle(context, advice)?;
        Ok(true)
    }
}

impl core::fmt::Debug for HandlerRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.handlers.values().map(|(name, _)| name)).finish()
    }
}

/// Adapts a portable handler to an existing legacy event registration or library list.
///
/// This retains legacy event-only delivery. Migrate registrations to [`HandlerRegistry`] for
/// unified event/trace delivery. A child batch isolates failure before conversion to legacy output.
pub fn legacy_handler(handler: impl Into<registration::EventHandler>) -> Arc<dyn EventHandler> {
    let handler = handler.into();
    Arc::new(move |process: &ProcessorState<'_>| invoke_legacy_handler(handler.as_ref(), process))
}

/// Invokes a borrowed portable handler for a legacy event callback, isolating its output until
/// success. This supports concrete types retaining their old trait implementation during migration.
pub fn invoke_legacy_handler(
    handler: &dyn miden_event_handler::EventHandler,
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let mut batch = AdviceBatch::new();
    handler.handle(event_context(process, InvocationKind::Event), &mut batch.recorder())?;
    Ok(batch_into_mutations(batch))
}

pub(crate) fn event_context<'a>(
    process: &ProcessorState<'a>,
    kind: InvocationKind,
) -> EventContext<'a> {
    let clock = process.clock().as_u32();
    let in_root_context = process.ctx() == crate::ContextId::root();
    let invocation = match kind {
        InvocationKind::Event => {
            Invocation::event(EventId::from_felt(process.get_stack_item(0)), clock, in_root_context)
        },
        InvocationKind::Trace => {
            Invocation::trace(EventId::from_felt(process.get_stack_item(1)), clock, in_root_context)
        },
    };
    EventContext::new(process.processor, invocation)
}

pub(crate) fn record_mutations(advice: &mut AdviceRecorder<'_>, mutations: Vec<AdviceMutation>) {
    for mutation in mutations {
        match mutation {
            AdviceMutation::ExtendStack { stack } => advice.prepend_stack(stack.into_elements()),
            AdviceMutation::ExtendMap { map } => {
                for (key, values) in map {
                    advice.insert_map_entry(key, values);
                }
            },
            AdviceMutation::ExtendMerkleStore { inner_nodes } => {
                advice.extend_merkle_store(inner_nodes)
            },
        }
    }
}

fn batch_into_mutations(batch: AdviceBatch) -> Vec<AdviceMutation> {
    let (stack, entries, nodes) = batch.into_parts();
    let mut mutations = Vec::with_capacity(entries.len() + 2);
    if !stack.is_empty() {
        mutations.push(AdviceMutation::extend_advice_stack(stack));
    }
    for entry in entries {
        mutations.push(AdviceMutation::extend_map([entry].into_iter().collect()));
    }
    if !nodes.is_empty() {
        mutations.push(AdviceMutation::extend_merkle_store(nodes));
    }
    mutations
}
