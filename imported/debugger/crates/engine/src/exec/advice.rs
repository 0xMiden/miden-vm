//! Support utilities for working with [AdviceMutation]s, in particular cloning, recording, and
//! (de)serializing the mutations produced by event handlers so they can be replayed later.

use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Felt, Word,
    crypto::merkle::InnerNodeInfo,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_processor::advice::{AdviceMap, AdviceMutation, AdviceStack};
use miden_utils_sync::RwLock;

/// Clone a single [AdviceMutation].
///
/// [AdviceMutation] does not implement [Clone] upstream, so recording and replaying event
/// mutations requires reconstructing each variant by hand.
pub fn clone_advice_mutation(mutation: &AdviceMutation) -> AdviceMutation {
    match mutation {
        AdviceMutation::ExtendStack { stack } => AdviceMutation::ExtendStack {
            stack: stack.clone(),
        },
        AdviceMutation::ExtendMap { map: other } => {
            AdviceMutation::ExtendMap { map: other.clone() }
        }
        AdviceMutation::ExtendMerkleStore { inner_nodes } => AdviceMutation::ExtendMerkleStore {
            inner_nodes: inner_nodes.clone(),
        },
    }
}

/// Clone a batch of [AdviceMutation]s. See [clone_advice_mutation].
pub fn clone_advice_mutations(mutations: &[AdviceMutation]) -> Vec<AdviceMutation> {
    mutations.iter().map(clone_advice_mutation).collect()
}

// SERIALIZATION
// ================================================================================================

// Variant tags for the manual [AdviceMutation] encoding. [AdviceMutation] does not implement the
// serialization traits upstream, so — as with cloning — each variant is (de)serialized by hand.
const TAG_EXTEND_STACK: u8 = 0;
const TAG_EXTEND_MAP: u8 = 1;
const TAG_EXTEND_MERKLE_STORE: u8 = 2;

/// Serialize a single [AdviceMutation] into `target`.
pub fn write_advice_mutation<W: ByteWriter>(mutation: &AdviceMutation, target: &mut W) {
    match mutation {
        AdviceMutation::ExtendStack { stack } => {
            target.write_u8(TAG_EXTEND_STACK);
            stack.iter().copied().collect::<Vec<_>>().write_into(target);
        }
        AdviceMutation::ExtendMap { map } => {
            target.write_u8(TAG_EXTEND_MAP);
            map.write_into(target);
        }
        AdviceMutation::ExtendMerkleStore { inner_nodes } => {
            target.write_u8(TAG_EXTEND_MERKLE_STORE);
            target.write_usize(inner_nodes.len());
            for info in inner_nodes {
                info.value.write_into(target);
                info.left.write_into(target);
                info.right.write_into(target);
            }
        }
    }
}

/// Deserialize a single [AdviceMutation] from `source`.
pub fn read_advice_mutation<R: ByteReader>(
    source: &mut R,
) -> Result<AdviceMutation, DeserializationError> {
    match source.read_u8()? {
        TAG_EXTEND_STACK => Ok(AdviceMutation::ExtendStack {
            stack: AdviceStack::from(Vec::<Felt>::read_from(source)?),
        }),
        TAG_EXTEND_MAP => Ok(AdviceMutation::ExtendMap {
            map: AdviceMap::read_from(source)?,
        }),
        TAG_EXTEND_MERKLE_STORE => {
            let len = source.read_usize()?;
            let mut inner_nodes = Vec::with_capacity(len);
            for _ in 0..len {
                let value = Word::read_from(source)?;
                let left = Word::read_from(source)?;
                let right = Word::read_from(source)?;
                inner_nodes.push(InnerNodeInfo { value, left, right });
            }
            Ok(AdviceMutation::ExtendMerkleStore { inner_nodes })
        }
        other => Err(DeserializationError::InvalidValue(format!(
            "unknown AdviceMutation variant tag: {other}"
        ))),
    }
}

/// Serialize a recorded event log (one entry per `on_event` invocation) into `target`.
///
/// This raw encoding is not independently versioned. Use [`super::ReplaySnapshot`] for persistent
/// storage with an explicit compatibility boundary.
pub fn write_event_log<W: ByteWriter>(log: &[Vec<AdviceMutation>], target: &mut W) {
    target.write_usize(log.len());
    for batch in log {
        target.write_usize(batch.len());
        for mutation in batch {
            write_advice_mutation(mutation, target);
        }
    }
}

/// Deserialize a recorded event log from `source`.
///
/// Legacy logs containing the removed precompile-request mutation tag are rejected. Use
/// [`super::ReplaySnapshot`] for versioned persistent storage.
pub fn read_event_log<R: ByteReader>(
    source: &mut R,
) -> Result<Vec<Vec<AdviceMutation>>, DeserializationError> {
    let batches = source.read_usize()?;
    let mut log = Vec::with_capacity(batches);
    for _ in 0..batches {
        let len = source.read_usize()?;
        let mut batch = Vec::with_capacity(len);
        for _ in 0..len {
            batch.push(read_advice_mutation(source)?);
        }
        log.push(batch);
    }
    Ok(log)
}

/// A shared, cloneable log of the advice mutations produced by event handlers.
///
/// One entry is recorded per `on_event` invocation, in execution order, **including empty
/// mutation sets**: event replay pops exactly one entry per event, so the log must stay aligned
/// with the event stream of the recorded execution.
///
/// This handle exists for executors that are consumed by execution and whose return type cannot
/// carry the log (see `DapExecutor::record_event_mutations`): obtain it before running, read it
/// once execution completes, and feed the recorded log into `DebuggerHost::set_event_replay`
/// (or `Executor::into_debug_with_replay`) to debug the same execution later without access to
/// the original host's event handlers. Hosts owned by the caller record internally instead; see
/// `DebuggerHost::with_event_advice_mutations_recording`.
#[derive(Clone, Default)]
pub struct EventMutationRecorder {
    log: Arc<RwLock<Vec<Vec<AdviceMutation>>>>,
}

impl core::fmt::Debug for EventMutationRecorder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventMutationRecorder").field("events", &self.len()).finish()
    }
}

impl EventMutationRecorder {
    /// Create a new, empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the recorded mutation batches, leaving the recorder empty.
    pub fn take(&self) -> Vec<Vec<AdviceMutation>> {
        core::mem::take(&mut *self.log.write())
    }

    /// Returns a copy of the recorded mutation batches, leaving the recorder intact.
    pub fn snapshot(&self) -> Vec<Vec<AdviceMutation>> {
        self.log.read().iter().map(|batch| clone_advice_mutations(batch)).collect()
    }

    /// The number of `on_event` invocations recorded so far.
    pub fn len(&self) -> usize {
        self.log.read().len()
    }

    /// Returns true if no `on_event` invocations have been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record the mutations produced by one `on_event` invocation.
    pub(crate) fn record(&self, mutations: Vec<AdviceMutation>) {
        self.log.write().push(mutations);
    }

    /// Discard everything recorded so far, e.g. when execution restarts from the beginning.
    #[cfg(feature = "dap")]
    pub(crate) fn clear(&self) {
        self.log.write().clear();
    }
}
