//! Symbolic stack for lifting.
//!
//! This module provides a symbolic stack that tracks variables during lifting,
//! modeled after the provenance stack used in signature inference.

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    rc::Rc,
};

use miden_assembly_syntax::debuginfo::SourceSpan;

use super::{LiftingError, LiftingResult};
use crate::ir::{ValueId, Var, VarBase};

/// Generator for unique SSA value identifiers.
#[derive(Debug, Clone)]
pub struct ValueIdGen {
    next: Rc<Cell<u64>>,
}

impl ValueIdGen {
    /// Create a new value identifier generator.
    pub fn new() -> Self {
        Self { next: Rc::new(Cell::new(0)) }
    }

    /// Allocate the next unique value identifier.
    pub fn next(&self) -> ValueId {
        let current = self.next.get();
        self.next.set(current + 1);
        ValueId::new(current)
    }

    /// Ensure the next value identifier is at least the provided value.
    pub fn ensure_next_at_least(&self, next: u64) {
        let current = self.next.get();
        if current < next {
            self.next.set(next);
        }
    }
}

impl Default for ValueIdGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotId(u64);

impl SlotId {
    /// Create a new slot identifier from a raw integer.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw integer value of this slot identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Generator for unique stack slot identifiers.
#[derive(Debug, Clone)]
pub struct SlotIdGen {
    next: Rc<Cell<u64>>,
}

impl SlotIdGen {
    /// Create a new slot identifier generator.
    pub fn new() -> Self {
        Self { next: Rc::new(Cell::new(0)) }
    }

    /// Allocate the next unique slot identifier.
    pub fn next(&self) -> SlotId {
        let current = self.next.get();
        self.next.set(current + 1);
        SlotId::new(current)
    }

    /// Ensure the next slot identifier is at least the provided value.
    pub fn ensure_next_at_least(&self, next: u64) {
        let current = self.next.get();
        if current < next {
            self.next.set(next);
        }
    }
}

impl Default for SlotIdGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Stack entry pairing a variable with its slot identity.
#[derive(Debug, Clone)]
pub struct StackEntry {
    /// Variable stored at this stack position.
    pub var: Var,
    /// Slot identifier tracking the position across iterations.
    pub slot_id: SlotId,
}

impl StackEntry {
    /// Create a new stack entry.
    pub const fn new(var: Var, slot_id: SlotId) -> Self {
        Self { var, slot_id }
    }
}

/// Symbolic stack tracking variables during lifting.
///
/// The stack grows to the right (back). Variables are created with their
/// birth depth set to the stack depth at the time of creation.
#[derive(Debug, Clone, Default)]
pub struct SymbolicStack {
    /// Stack contents, bottom to top.
    stack: VecDeque<StackEntry>,
    /// Shared generator for unique SSA value identifiers.
    ids: ValueIdGen,
    /// Shared generator for unique slot identifiers.
    slots: SlotIdGen,
    /// Mapping from value identifiers to their slot identifiers.
    value_slots: Rc<RefCell<HashMap<ValueId, SlotId>>>,
}

impl SymbolicStack {
    /// Create a new empty stack.
    pub fn new() -> Self {
        Self {
            stack: VecDeque::new(),
            ids: ValueIdGen::new(),
            slots: SlotIdGen::new(),
            value_slots: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Return the current stack depth.
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Check if the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Push a new variable onto the stack.
    ///
    /// The variable's stack_depth should be set to the current stack depth
    /// before pushing (i.e., the depth at which it is born).
    pub fn push(&mut self, var: Var) {
        let slot_id = self.slots.next();
        self.push_with_slot(var, slot_id);
    }

    /// Create a fresh variable at the given depth.
    pub fn fresh_var(&mut self, stack_depth: usize) -> Var {
        Var::new(self.ids.next(), stack_depth)
    }

    /// Create and push a fresh variable at the current stack depth.
    pub fn push_fresh(&mut self) -> Var {
        let depth = self.stack.len();
        let var = self.fresh_var(depth);
        let slot_id = self.slots.next();
        self.register_value_slot(&var, slot_id);
        self.stack.push_back(StackEntry::new(var.clone(), slot_id));
        var
    }

    /// Create and push a fresh variable with an explicit value identifier and
    /// display depth.
    ///
    /// This is used when lifting needs hidden stack scaffolding below the
    /// public procedure inputs. The rendered variable name follows
    /// `display_depth`, while `value_id` preserves any invariants expected by
    /// later analyses.
    pub fn push_fresh_with_value_id(&mut self, value_id: ValueId, display_depth: usize) -> Var {
        self.ids.ensure_next_at_least(value_id.as_u64() + 1);
        let var = Var::new(value_id, display_depth);
        let slot_id = self.slots.next();
        self.register_value_slot(&var, slot_id);
        self.stack.push_back(StackEntry::new(var.clone(), slot_id));
        var
    }

    /// Create and push a fresh variable reusing the provided slot identifier.
    ///
    /// The new variable inherits the template's subscript to preserve slot identity.
    pub fn push_fresh_with_slot_like(&mut self, slot_id: SlotId, template: &Var) -> Var {
        let var = Var {
            base: VarBase::Value(self.ids.next()),
            stack_depth: template.stack_depth,
            subscript: template.subscript.clone(),
        };
        self.register_value_slot(&var, slot_id);
        self.stack.push_back(StackEntry::new(var.clone(), slot_id));
        var
    }

    /// Create a fresh variable using the template's depth and subscript.
    pub fn fresh_like(&mut self, template: &Var) -> Var {
        Var {
            base: VarBase::Value(self.ids.next()),
            stack_depth: template.stack_depth,
            subscript: template.subscript.clone(),
        }
    }

    /// Push an existing variable using an explicit slot identifier.
    pub fn push_with_slot(&mut self, var: Var, slot_id: SlotId) {
        self.register_value_slot(&var, slot_id);
        self.stack.push_back(StackEntry::new(var, slot_id));
    }

    /// Replace the entire stack with the provided variables.
    pub fn set_stack(&mut self, vars: Vec<Var>) {
        let mut new_stack = VecDeque::with_capacity(vars.len());
        for (idx, var) in vars.into_iter().enumerate() {
            let slot_id = self
                .stack
                .get(idx)
                .map(|entry| entry.slot_id)
                .unwrap_or_else(|| self.slots.next());
            self.register_value_slot(&var, slot_id);
            new_stack.push_back(StackEntry::new(var, slot_id));
        }
        self.stack = new_stack;
    }

    /// Replace the entire stack with the provided entries (including slot ids).
    pub fn set_entries(&mut self, entries: VecDeque<StackEntry>) {
        let mut max_slot: Option<u64> = None;
        for entry in &entries {
            self.register_value_slot(&entry.var, entry.slot_id);
            let slot_value = entry.slot_id.as_u64();
            max_slot = Some(max_slot.map_or(slot_value, |current| current.max(slot_value)));
        }
        if let Some(max_slot) = max_slot {
            self.slots.ensure_next_at_least(max_slot + 1);
        }
        self.stack = entries;
    }

    /// Return a snapshot of the current stack as a vector from bottom to top.
    pub fn to_vec(&self) -> Vec<Var> {
        self.stack.iter().map(|entry| entry.var.clone()).collect()
    }

    /// Return a snapshot of the current stack entries from bottom to top.
    pub fn to_entries(&self) -> Vec<StackEntry> {
        self.stack.iter().cloned().collect()
    }

    /// Pop a variable from the top of the stack.
    ///
    /// # Panics
    ///
    /// Panics if the stack is empty.
    pub fn pop(&mut self) -> Var {
        self.pop_entry().var
    }

    /// Pop a stack entry from the top of the stack.
    ///
    /// # Panics
    ///
    /// Panics if the stack is empty.
    pub fn pop_entry(&mut self) -> StackEntry {
        self.stack.pop_back().expect("stack underflow")
    }

    /// Pop multiple variables from the stack, returning them in pop order
    /// (top of stack first).
    pub fn pop_n(&mut self, n: usize) -> Vec<Var> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            result.push(self.pop());
        }
        result
    }

    /// Pop multiple entries from the stack, returning them in pop order
    /// (top of stack first).
    pub fn pop_n_entries(&mut self, n: usize) -> Vec<StackEntry> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            result.push(self.pop_entry());
        }
        result
    }

    /// Peek at the variable at the given depth from the top (0 = top).
    pub fn peek(&self, depth: usize) -> Option<&Var> {
        if depth >= self.stack.len() {
            return None;
        }
        self.stack.get(self.stack.len() - 1 - depth).map(|entry| &entry.var)
    }

    /// Peek at the stack entry at the given depth from the top (0 = top).
    pub fn peek_entry(&self, depth: usize) -> Option<&StackEntry> {
        if depth >= self.stack.len() {
            return None;
        }
        self.stack.get(self.stack.len() - 1 - depth)
    }

    /// Get the top n variables without removing them (top of stack first).
    pub fn top_n(&self, n: usize) -> Vec<Var> {
        let len = self.stack.len();
        if n > len {
            return self.stack.iter().rev().map(|e| e.var.clone()).collect();
        }
        self.stack.iter().skip(len - n).rev().map(|entry| entry.var.clone()).collect()
    }

    /// Return a copy of the value-to-slot map.
    pub fn value_slots(&self) -> HashMap<ValueId, SlotId> {
        self.value_slots.borrow().clone()
    }

    /// Ensure the stack has at least the given depth by pushing input variables.
    ///
    /// Returns the variables that were created to satisfy the depth requirement.
    /// Variables are numbered from bottom to top: v_0 is the first input (deepest),
    /// v_n is the last input (at the top).
    pub fn ensure_depth(&mut self, required_depth: usize) -> Vec<Var> {
        let mut inputs = Vec::new();
        while self.stack.len() < required_depth {
            // Input variables are numbered by their stack depth from the bottom.
            // v_0 is at the bottom (first input), v_n is at the top (last input).
            let depth = self.stack.len();
            let var = self.fresh_var(depth);
            let slot_id = self.slots.next();
            self.register_value_slot(&var, slot_id);
            self.stack.push_back(StackEntry::new(var.clone(), slot_id));
            inputs.push(var);
        }
        inputs
    }

    /// Require the stack to have at least the given depth without synthesizing inputs.
    pub fn require_depth(
        &self,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        let actual_depth = self.stack.len();
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

    /// Apply a stack effect: pop `pops` values, push `pushes` new variables.
    ///
    /// The `required_depth` is ensured before popping. Returns the popped
    /// variables and the newly pushed variables.
    pub fn apply(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
    ) -> (Vec<Var>, Vec<Var>) {
        self.ensure_depth(required_depth);

        // Pop values (top of stack first).
        let popped_entries = self.pop_n_entries(pops);
        let popped = popped_entries.iter().map(|entry| entry.var.clone()).collect::<Vec<_>>();

        // Push new variables with their birth depth.
        let mut pushed = Vec::with_capacity(pushes);
        let mut slot_iter = popped_entries.iter().rev().map(|entry| entry.slot_id);
        for _ in 0..pushes {
            let depth = self.stack.len();
            let var = self.fresh_var(depth);
            let slot_id = slot_iter.next().unwrap_or_else(|| self.slots.next());
            self.register_value_slot(&var, slot_id);
            self.stack.push_back(StackEntry::new(var.clone(), slot_id));
            pushed.push(var);
        }

        (popped, pushed)
    }

    /// Apply a stack effect without synthesizing inputs.
    pub fn apply_checked(
        &mut self,
        pops: usize,
        pushes: usize,
        required_depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<(Vec<Var>, Vec<Var>)> {
        self.require_depth(required_depth, span, operation)?;

        let popped_entries = self.pop_n_entries(pops);
        let popped = popped_entries.iter().map(|entry| entry.var.clone()).collect::<Vec<_>>();

        let mut pushed = Vec::with_capacity(pushes);
        let mut slot_iter = popped_entries.iter().rev().map(|entry| entry.slot_id);
        for _ in 0..pushes {
            let depth = self.stack.len();
            let var = self.fresh_var(depth);
            let slot_id = slot_iter.next().unwrap_or_else(|| self.slots.next());
            self.register_value_slot(&var, slot_id);
            self.stack.push_back(StackEntry::new(var.clone(), slot_id));
            pushed.push(var);
        }

        Ok((popped, pushed))
    }

    /// Get the top n variables without removing them, failing on underflow.
    pub fn top_n_checked(
        &self,
        n: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<Vec<Var>> {
        self.require_depth(n, span, operation)?;
        Ok(self.top_n(n))
    }

    /// Swap the top element with the element at the given depth.
    pub fn swap(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.stack.len();
        if depth > 0 && depth < len {
            let top_idx = len - 1;
            let other_idx = len - 1 - depth;
            self.stack.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Swap the top word (4 elements) with the nth word below it.
    ///
    /// The word index is 1-based: swapw(1) swaps the top word with the next word.
    pub fn swapw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        if word_index == 0 {
            return Ok(());
        }
        self.require_depth((word_index + 1) * 4, span, operation)?;
        let len = self.stack.len();
        let offset = word_index.saturating_mul(4);
        if offset + 4 > len {
            return Ok(());
        }
        for i in 0..4 {
            let top_idx = len - 1 - i;
            let other_idx = len - 1 - offset - i;
            self.stack.swap(top_idx, other_idx);
        }
        Ok(())
    }

    /// Reverse the order of the top 4 stack elements (word).
    pub fn reversew(
        &mut self,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(4, span, operation)?;
        let len = self.stack.len();
        if len < 4 {
            return Ok(());
        }
        self.stack.swap(len - 4, len - 1);
        self.stack.swap(len - 3, len - 2);
        Ok(())
    }

    /// Swap the first two words with the next two words.
    ///
    /// This models `swapdw`, which transforms `[D, C, B, A, ...]` into
    /// `[B, A, D, C, ...]`.
    pub fn swapdw(&mut self, span: SourceSpan, operation: impl Into<String>) -> LiftingResult<()> {
        self.require_depth(16, span, operation)?;
        let len = self.stack.len();
        if len < 16 {
            return Ok(());
        }
        for i in 0..8 {
            self.stack.swap(len - 16 + i, len - 8 + i);
        }
        Ok(())
    }

    /// Move the element at the given depth to the top.
    pub fn movup(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.stack.len();
        if depth > 0 && depth < len {
            let idx = len - 1 - depth;
            if let Some(entry) = self.stack.remove(idx) {
                self.stack.push_back(entry);
            }
        }
        Ok(())
    }

    /// Move the word at the given 1-based word depth to the top word.
    ///
    /// Valid indices in MASM are 2 and 3 (matching `movupw.2`/`movupw.3`).
    pub fn movupw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        if word_index < 1 {
            return Ok(());
        }
        self.require_depth((word_index + 1) * 4, span, operation)?;
        let len = self.stack.len();
        let offset = word_index.saturating_mul(4);
        if offset + 4 > len {
            return Ok(());
        }
        let start = len - offset - 4;
        let mut moved = Vec::with_capacity(4);
        for _ in 0..4 {
            if let Some(entry) = self.stack.remove(start) {
                moved.push(entry);
            }
        }
        for entry in moved {
            self.stack.push_back(entry);
        }
        Ok(())
    }

    /// Move the top element down to the given depth.
    pub fn movdn(
        &mut self,
        depth: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth(depth + 1, span, operation)?;
        let len = self.stack.len();
        if depth > 0
            && depth < len
            && let Some(entry) = self.stack.pop_back()
        {
            let idx = len - 1 - depth;
            self.stack.insert(idx, entry);
        }
        Ok(())
    }

    /// Move the top word down to the given 2-indexed word position.
    ///
    /// Valid indices in MASM are 2 and 3 (matching `movdnw.2`/`movdnw.3`).
    pub fn movdnw(
        &mut self,
        word_index: usize,
        span: SourceSpan,
        operation: impl Into<String>,
    ) -> LiftingResult<()> {
        self.require_depth((word_index + 1) * 4, span, operation)?;
        match word_index {
            2 => {
                self.swapw(2, span, "movdnw.2")?;
                self.swapw(1, span, "movdnw.2")?;
            },
            3 => {
                self.swapw(3, span, "movdnw.3")?;
                self.swapw(2, span, "movdnw.3")?;
                self.swapw(1, span, "movdnw.3")?;
            },
            _ => {},
        }
        Ok(())
    }

    /// Get an iterator over the stack from bottom to top.
    pub fn iter(&self) -> impl Iterator<Item = &Var> {
        self.stack.iter().map(|entry| &entry.var)
    }

    /// Record the slot identifier for a newly created value.
    fn register_value_slot(&mut self, var: &Var, slot_id: SlotId) {
        if let VarBase::Value(id) = var.base {
            self.value_slots.borrow_mut().insert(id, slot_id);
        }
    }

    /// Associate an existing variable with a slot identifier.
    pub fn register_value_slot_for_var(&mut self, var: &Var, slot_id: SlotId) {
        self.register_value_slot(var, slot_id);
    }
}
