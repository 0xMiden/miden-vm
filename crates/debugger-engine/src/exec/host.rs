use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::num::NonZeroU32;

use miden_assembly_syntax::debuginfo::SourceManager;
use miden_core::{
    Word,
    events::{EventId, EventName},
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_mast_package::Package;
use miden_processor::{
    BaseHost, ExecutionError, LoadedMastForest, MastForestStore, MemMastForestStore,
    ProcessorState, SyncHost,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventHandlerRegistry},
};

use super::advice::clone_advice_mutations;
use crate::Event;

/// This is an implementation of [Host] which is essentially [miden_processor::DefaultHost],
/// but extended with additional functionality for debugging, in particular it manages trace
/// events that record the entry or exit of a procedure call frame.
pub struct DebuggerHost<S: SourceManager + ?Sized> {
    store: MemMastForestStore,
    event_handlers: EventHandlerRegistry,
    #[allow(clippy::type_complexity)]
    on_assert_failed: Option<Box<dyn FnMut(&ProcessorState<'_>, u32)>>,
    source_manager: Arc<S>,
    event_replay: VecDeque<Vec<AdviceMutation>>,
    event_recording: Option<Vec<Vec<AdviceMutation>>>,
}
impl<S> DebuggerHost<S>
where
    S: SourceManager + ?Sized,
{
    /// Construct a new instance of [DebuggerHost] with the given source manager.
    pub fn new(source_manager: Arc<S>) -> Self {
        Self {
            store: Default::default(),
            event_handlers: EventHandlerRegistry::default(),
            on_assert_failed: None,
            source_manager,
            event_replay: VecDeque::new(),
            event_recording: None,
        }
    }

    /// Set the event replay queue.
    ///
    /// When non-empty, `on_event()` will pop mutations from this queue instead of
    /// returning empty results. This is used for transaction debugging where events
    /// were recorded during a prior execution.
    pub fn set_event_replay(&mut self, events: VecDeque<Vec<AdviceMutation>>) {
        self.event_replay = events;
    }

    /// Record the advice mutations produced by each event handler invocation.
    ///
    /// One entry is recorded per `on_event` invocation, in execution order, **including empty
    /// mutation sets**, so the recorded log can be fed directly back into
    /// [DebuggerHost::set_event_replay] to replay this execution later. Take the log with
    /// [DebuggerHost::take_recorded_event_mutations] once execution completes.
    ///
    /// Mutations are only recorded for live event handling; nothing is recorded while an event
    /// replay queue is being consumed.
    pub fn with_event_advice_mutations_recording(mut self) -> Self {
        self.event_recording = Some(Vec::new());
        self
    }

    /// Returns the advice mutations recorded so far, leaving the recording empty.
    ///
    /// Returns an empty log when recording was not enabled via
    /// [DebuggerHost::with_event_advice_mutations_recording].
    pub fn take_recorded_event_mutations(&mut self) -> Vec<Vec<AdviceMutation>> {
        self.event_recording.as_mut().map(core::mem::take).unwrap_or_default()
    }

    /// Register a handler to be called when an assertion in the VM fails
    pub fn register_assert_failed_tracer<F>(&mut self, callback: F)
    where
        F: FnMut(&ProcessorState<'_>, u32) + 'static,
    {
        self.on_assert_failed = Some(Box::new(callback));
    }

    /// Invoke the assert-failed handler, if registered.
    ///
    /// This is called externally when `step()` returns an assertion error, since
    /// `on_assert_failed` no longer exists on the Host trait in 0.21.
    pub fn handle_assert_failed(
        &mut self,
        process: &ProcessorState<'_>,
        err_code: Option<NonZeroU32>,
    ) {
        if let Some(handler) = self.on_assert_failed.as_mut() {
            handler(process, err_code.map(|nz| nz.get()).unwrap_or_default());
        }
    }

    /// Load `package` into the MAST store for this host
    pub fn load_package(&mut self, package: Arc<Package>) {
        let mast = package.mast_forest().clone();
        let debug_info = package.debug_info();
        self.store
            .insert_loaded(LoadedMastForest::with_package_debug_info(mast, debug_info));
    }

    /// Load `forest` into the MAST store for this host
    pub fn load_mast_forest(&mut self, forest: LoadedMastForest) {
        self.store.insert_loaded(forest);
    }

    /// Registers an event handler for use during program execution.
    pub fn register_event_handler(
        &mut self,
        event: EventName,
        handler: Arc<dyn EventHandler>,
    ) -> Result<(), ExecutionError> {
        self.event_handlers.register(event, handler)
    }
}

impl<S> BaseHost for DebuggerHost<S>
where
    S: SourceManager + ?Sized,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.event_handlers.resolve_event(event_id)
    }
}

impl<S> SyncHost for DebuggerHost<S>
where
    S: SourceManager + ?Sized,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest> {
        self.store.get(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        let is_builtin_event = Event::from(event_id).has_builtin_handler();
        let replay_mutations = self.event_replay.pop_front();
        let is_replaying = replay_mutations.is_some();

        if let Some(mutations) = replay_mutations {
            if !is_builtin_event {
                // Non-debug events without builtin handler: return mutations from replay.
                return Ok(mutations);
            }

            // Even in replay mode we want to forward builtin events to the builtin handlers.
            // Debugger functionality relies on the side effects of the handlers.
            if is_builtin_event {
                assert!(
                    mutations.is_empty(),
                    "debug events must not be associated with mutations from replay"
                );
            }
        }

        let result = match self.event_handlers.handle_event(event_id, process) {
            Ok(Some(mutations)) => Ok(mutations),
            Ok(None) => {
                #[derive(Debug, thiserror::Error)]
                #[error("no event handler registered")]
                struct UnhandledEvent;

                Err(UnhandledEvent.into())
            }
            Err(err) => Err(err),
        };

        if !is_replaying
            && let (Some(log), Ok(mutations)) = (self.event_recording.as_mut(), &result)
        {
            log.push(clone_advice_mutations(mutations));
        }
        result
    }
}
