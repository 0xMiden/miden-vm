//! System-event glue for the deferred-DAG subsystem.
//!
//! Reads the `(payload, tag)` operand-stack layout used by `DeferredRegister` /
//! `DeferredEvaluate` (see [`miden_core::events::sys_events`]) and dispatches into the installed
//! [`miden_core::deferred::Schema`].

use miden_core::{
    Word,
    deferred::{Node, NodeType, Payload, Tag},
};

use super::SystemEventError;
use crate::fast::FastProcessor;

/// Stack offset of the payload's low half — the topmost word below the event ID.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half (next word below the low half).
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag — the third word below the event ID.
const DEFERRED_TAG_OFFSET: usize = 9;

/// Reads a node off the operand stack: 8-felt payload (two words) followed by a 4-felt tag.
///
/// This layout mirrors the Poseidon2 sponge state used by [`Node::digest`] (`payload || tag`),
/// letting MASM callers feed the stack directly into `hperm` to recover the digest.
fn read_deferred_node(processor: &FastProcessor) -> Node {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag_word = processor.stack_get_word(DEFERRED_TAG_OFFSET);
    let tag: Tag = [tag_word[0], tag_word[1], tag_word[2], tag_word[3]];
    let payload = Payload::new([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    Node::new(tag, payload)
}

/// Handles `SystemEvent::DeferredRegister`. Reads the node off the operand stack and hands it
/// to the installed schema, which classifies it as either an expression (inserted into the DAG)
/// or an assertion (recorded + verified). A schema-reported mismatch surfaces as
/// `SchemaError::AssertionFailed`.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let node = read_deferred_node(processor);
    let (state, schema) = processor.deferred_view_mut();
    let _ = state.register(schema, node)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredEvaluate`. Reads the node off the operand stack and asks the
/// schema to evaluate it.
///
/// - For expression nodes, the 12 felts of the canonical `(payload, tag)` are pushed onto the
///   advice stack in `[PAYLOAD_LO, PAYLOAD_HI, TAG]` order (top-down), matching the operand-stack
///   input layout — MASM can recover each word with `adv_pushw`.
/// - For assertion nodes, evaluation is a pure verify: a mismatch surfaces as
///   `SchemaError::AssertionFailed`, and nothing is pushed onto the advice stack on success.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let node = read_deferred_node(processor);
    let (state, schema) = processor.deferred_view_mut();
    let canonical = state.evaluate(schema, node)?;

    // Assertion-evaluate is pure verify — no canonical value to surface to MASM.
    if !matches!(schema.is_valid(&canonical), Some(NodeType::Expression)) {
        return Ok(());
    }

    let payload_hi = Word::new([
        canonical.payload.0[4],
        canonical.payload.0[5],
        canonical.payload.0[6],
        canonical.payload.0[7],
    ]);
    let payload_lo = Word::new([
        canonical.payload.0[0],
        canonical.payload.0[1],
        canonical.payload.0[2],
        canonical.payload.0[3],
    ]);
    // Push deepest first so `payload_lo` ends up on top. `push_stack_word` reverses element
    // order so an `adv_pushw` on the MASM side recovers each word in structural order.
    processor.advice.push_stack_word(&Word::new(canonical.tag))?;
    processor.advice.push_stack_word(&payload_hi)?;
    processor.advice.push_stack_word(&payload_lo)?;
    Ok(())
}
