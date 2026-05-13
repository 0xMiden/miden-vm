//! Repeat-loop slot simulation used by lifting.

use std::collections::{HashMap, HashSet};

use log::trace;
use miden_assembly_syntax::{ast::Instruction, debuginfo::SourceSpan};

use super::{LiftingError, LiftingResult, inst, stack::SlotId};
use crate::{
    semantics::{StackFamily, stack_family},
    signature::{SignatureMap, StackEffect},
    symbol::resolution::SymbolResolver,
};

/// Lightweight slot-only stack used for repeat-loop simulation.
#[derive(Debug, Clone)]
pub(super) struct SlotStack {
    slots: Vec<SlotId>,
    next_slot: u64,
}

impl SlotStack {
    /// Create a slot stack initialized with the given entries.
    pub(super) fn new(entry_slots: &[SlotId]) -> Self {
        let next_slot = entry_slots
            .iter()
            .map(|slot| slot.as_u64())
            .max()
            .map(|value| value + 1)
            .unwrap_or(0);
        Self { slots: entry_slots.to_vec(), next_slot }
    }

    /// Return the current slot order.
    pub(super) fn slots(&self) -> &[SlotId] {
        &self.slots
    }

    /// Require the stack to have at least the given depth without synthesizing slots.
    fn require_depth(
        &self,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        let actual_depth = self.slots.len();
        if actual_depth < required_depth {
            return Err(LiftingError::InsufficientStackDepth {
                span,
                operation: operation.into(),
                required_depth,
                actual_depth,
            });
        }
        Ok(())
    }

    /// Allocate a fresh slot identifier.
    fn alloc_slot(&mut self) -> SlotId {
        let id = self.next_slot;
        self.next_slot += 1;
        SlotId::new(id)
    }

    /// Pop a slot identifier from the top of the stack.
    fn pop(&mut self) -> SlotId {
        self.slots.pop().expect("slot stack underflow")
    }

    /// Swap the top slot with the slot at the given depth.
    fn swap(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let top_idx = len - 1;
            let other_idx = len - 1 - depth;
            self.slots.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Swap the top word with the word below it.
    fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        if word_index == 0 {
            return Ok(());
        }
        self.require_depth((word_index + 1) * 4, span, operation)?;
        let len = self.slots.len();
        let offset = word_index.saturating_mul(4);
        if offset + 4 > len {
            return Ok(());
        }
        for i in 0..4 {
            let top_idx = len - 1 - i;
            let other_idx = len - 1 - offset - i;
            self.slots.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Reverse the order of the top word.
    fn reversew(&mut self, span: SourceSpan, operation: impl Into<String>) -> LiftingResult<()> {
        self.require_depth(4, span, operation)?;
        let len = self.slots.len();
        if len < 4 {
            return Ok(());
        }
        self.slots.swap(len - 4, len - 1);
        self.slots.swap(len - 3, len - 2);
        Ok(())
    }

    /// Move the slot at the given depth to the top.
    fn movup(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let idx = len - 1 - depth;
            let slot = self.slots.remove(idx);
            self.slots.push(slot);
        }
        Ok(())
    }

    /// Move the top slot down to the given depth.
    fn movdn(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let slot = self.slots.pop().expect("slot stack underflow");
            let idx = len - 1 - depth;
            self.slots.insert(idx, slot);
        }
        Ok(())
    }

    /// Apply a stack effect to the slot stack, reusing slots where possible.
    fn apply_effect(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(required_depth, span, operation)?;
        let mut popped = Vec::with_capacity(pops);
        for _ in 0..pops {
            popped.push(self.pop());
        }
        let mut reuse = popped.into_iter().rev().collect::<Vec<_>>();
        let reuse_count = reuse.len().min(pushes);
        for slot in reuse.drain(0..reuse_count) {
            self.slots.push(slot);
        }
        for _ in reuse_count..pushes {
            let slot = self.alloc_slot();
            self.slots.push(slot);
        }
        Ok(())
    }

    /// Return the stack contents from bottom to top.
    pub(super) fn into_slots(self) -> Vec<SlotId> {
        self.slots
    }
}

/// Slot stack with loop-carried tag tracking for repeat loops.
#[derive(Debug, Clone)]
pub(super) struct TaggedSlotStack {
    slots: Vec<SlotId>,
    next_slot: u64,
    tags: HashMap<SlotId, HashSet<SlotId>>,
}

impl TaggedSlotStack {
    /// Create a tagged slot stack initialized with the given slots.
    pub(super) fn new(entry_slots: &[SlotId], loop_carried: &HashSet<SlotId>) -> Self {
        let next_slot = entry_slots
            .iter()
            .map(|slot| slot.as_u64())
            .max()
            .map(|value| value + 1)
            .unwrap_or(0);
        let mut tags = HashMap::new();
        for slot in entry_slots {
            let mut set = HashSet::new();
            if loop_carried.contains(slot) {
                set.insert(*slot);
            }
            tags.insert(*slot, set);
        }
        Self {
            slots: entry_slots.to_vec(),
            next_slot,
            tags,
        }
    }

    /// Return the current slot order.
    pub(super) fn slots(&self) -> &[SlotId] {
        &self.slots
    }

    /// Check whether another tagged stack has the same slot order and tags.
    pub(super) fn same_state_as(&self, other: &Self) -> bool {
        self.slots == other.slots && self.tags == other.tags
    }

    /// Render the slot stack and tags for trace logging.
    pub(super) fn state_snapshot(&self) -> String {
        let mut parts = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let mut tags = self
                .tags
                .get(slot)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(SlotId::as_u64)
                .collect::<Vec<_>>();
            tags.sort_unstable();
            parts.push(format!("{}:{:?}", slot.as_u64(), tags));
        }
        format!("[{}]", parts.join(", "))
    }

    /// Return tags for a slot identifier.
    pub(super) fn tags_for(&self, slot_id: SlotId) -> HashSet<SlotId> {
        self.tags.get(&slot_id).cloned().unwrap_or_default()
    }

    /// Require the stack to have at least the given depth without synthesizing slots.
    fn require_depth(
        &self,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        let actual_depth = self.slots.len();
        if actual_depth < required_depth {
            return Err(LiftingError::InsufficientStackDepth {
                span,
                operation: operation.into(),
                required_depth,
                actual_depth,
            });
        }
        Ok(())
    }

    /// Allocate a fresh slot identifier.
    fn alloc_slot(&mut self) -> SlotId {
        let id = self.next_slot;
        self.next_slot += 1;
        SlotId::new(id)
    }

    /// Pop a slot identifier from the top of the stack.
    fn pop(&mut self) -> SlotId {
        self.slots.pop().expect("slot stack underflow")
    }

    /// Swap the top slot with the slot at the given depth.
    fn swap(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let top_idx = len - 1;
            let other_idx = len - 1 - depth;
            self.slots.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Swap the top word with the word below it.
    fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        if word_index == 0 {
            return Ok(());
        }
        self.require_depth((word_index + 1) * 4, span, operation)?;
        let len = self.slots.len();
        let offset = word_index.saturating_mul(4);
        if offset + 4 > len {
            return Ok(());
        }
        for i in 0..4 {
            let top_idx = len - 1 - i;
            let other_idx = len - 1 - offset - i;
            self.slots.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Reverse the order of the top word.
    fn reversew(&mut self, span: SourceSpan, operation: impl Into<String>) -> LiftingResult<()> {
        self.require_depth(4, span, operation)?;
        let len = self.slots.len();
        if len < 4 {
            return Ok(());
        }
        self.slots.swap(len - 4, len - 1);
        self.slots.swap(len - 3, len - 2);
        Ok(())
    }

    /// Move the slot at the given depth to the top.
    fn movup(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let idx = len - 1 - depth;
            let slot = self.slots.remove(idx);
            self.slots.push(slot);
        }
        Ok(())
    }

    /// Move the top slot down to the given depth.
    fn movdn(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.slots.len();
        if depth > 0 && depth < len {
            let slot = self.slots.pop().expect("slot stack underflow");
            let idx = len - 1 - depth;
            self.slots.insert(idx, slot);
        }
        Ok(())
    }

    /// Apply a stack effect to the tagged slot stack.
    fn apply_effect(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        let before = self.state_snapshot();
        self.require_depth(required_depth, span, operation)?;
        let mut popped = Vec::with_capacity(pops);
        let mut popped_tags = Vec::with_capacity(pops);
        for _ in 0..pops {
            let slot = self.pop();
            let tags = self.tags.remove(&slot).unwrap_or_default();
            popped.push(slot);
            popped_tags.push(tags);
        }
        let mut merged_tags = HashSet::new();
        for tags in popped_tags {
            merged_tags.extend(tags);
        }
        let mut reuse = popped.into_iter().rev().collect::<Vec<_>>();
        let reuse_count = reuse.len().min(pushes);
        for slot in reuse.drain(0..reuse_count) {
            self.tags.insert(slot, merged_tags.clone());
            self.slots.push(slot);
        }
        for _ in reuse_count..pushes {
            let slot = self.alloc_slot();
            self.tags.entry(slot).or_default();
            self.slots.push(slot);
        }
        trace!(
            "repeat tag simulation effect: pops={}, pushes={}, requred_depth={}, before={}, after={}",
            pops,
            pushes,
            required_depth,
            before,
            self.state_snapshot()
        );
        Ok(())
    }
}

/// Common instruction simulation surface for repeat slot stacks.
pub(super) trait RepeatSlotSimulator {
    /// Swap the top slot with the slot at the given depth.
    fn swap(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()>;

    /// Swap the top word with a lower word.
    fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()>;

    /// Reverse the order of the top word.
    fn reversew(&mut self, span: SourceSpan, operation: String) -> LiftingResult<()>;

    /// Move the slot at the given depth to the top.
    fn movup(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()>;

    /// Move the top slot down to the given depth.
    fn movdn(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()>;

    /// Apply a generic stack effect.
    fn apply_effect(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()>;
}

impl RepeatSlotSimulator for SlotStack {
    fn swap(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        SlotStack::swap(self, depth, span, operation)
    }

    fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()> {
        SlotStack::swapw(self, word_index, span, operation)
    }

    fn reversew(&mut self, span: SourceSpan, operation: String) -> LiftingResult<()> {
        SlotStack::reversew(self, span, operation)
    }

    fn movup(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        SlotStack::movup(self, depth, span, operation)
    }

    fn movdn(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        SlotStack::movdn(self, depth, span, operation)
    }

    fn apply_effect(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()> {
        SlotStack::apply_effect(self, pops, pushes, required_depth, span, operation)
    }
}

impl RepeatSlotSimulator for TaggedSlotStack {
    fn swap(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        TaggedSlotStack::swap(self, depth, span, operation)
    }

    fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()> {
        TaggedSlotStack::swapw(self, word_index, span, operation)
    }

    fn reversew(&mut self, span: SourceSpan, operation: String) -> LiftingResult<()> {
        TaggedSlotStack::reversew(self, span, operation)
    }

    fn movup(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        TaggedSlotStack::movup(self, depth, span, operation)
    }

    fn movdn(&mut self, depth: usize, span: SourceSpan, operation: String) -> LiftingResult<()> {
        TaggedSlotStack::movdn(self, depth, span, operation)
    }

    fn apply_effect(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: String,
    ) -> LiftingResult<()> {
        TaggedSlotStack::apply_effect(self, pops, pushes, required_depth, span, operation)
    }
}

/// Simulate one instruction against a repeat slot stack.
pub(super) fn simulate_inst_on_repeat_stack<S: RepeatSlotSimulator>(
    inst: &Instruction,
    op_span: SourceSpan,
    stack: &mut S,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<()> {
    let operation = inst.to_string();
    match stack_family(inst) {
        Some(StackFamily::Swap(depth)) => stack.swap(depth, op_span, operation)?,
        Some(StackFamily::SwapWord(index)) => stack.swapw(index, op_span, operation)?,
        Some(StackFamily::MovUp(depth)) => stack.movup(depth, op_span, operation)?,
        Some(StackFamily::MovDown(depth)) => stack.movdn(depth, op_span, operation)?,
        _ if matches!(inst, Instruction::Reversew) => stack.reversew(op_span, operation)?,
        _ => {
            let effect = inst::effect_for_inst(inst, op_span, resolver, sigs)?;
            let (pops, pushes, required_depth) = match effect {
                StackEffect::Known { pops, pushes, required_depth } => {
                    (pops, pushes, required_depth)
                },
                StackEffect::Unknown => (0, 0, 0),
            };
            stack.apply_effect(pops, pushes, required_depth, op_span, operation)?;
        },
    }
    Ok(())
}
