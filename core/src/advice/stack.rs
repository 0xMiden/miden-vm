use alloc::{collections::VecDeque, vec::Vec};

use super::{AdviceInputs, AdviceMap};
use crate::{Felt, Word, crypto::merkle::MerkleStore, field::PrimeField64};

// ADVICE STACK BUILDER
// ================================================================================================

/// A builder for constructing advice stack inputs with intuitive ordering.
///
/// The builder maintains a conceptual advice stack where index 0 is the "top" - i.e., the element
/// that will be consumed first. Method names indicate which MASM instruction pattern they target,
/// abstracting away the internal transformations needed for correct element ordering.
///
/// # Building Direction
///
/// Building happens "top-first": the first method call adds elements that will be consumed first
/// by the MASM code. Each subsequent method call adds elements "below" the previous ones.
///
/// # Example
///
/// ```ignore
/// let advice = AdviceStackBuilder::new()
///     .push_for_adv_push(&[a, b, c])  // Consumed first by adv_push.3
///     .push_for_adv_loadw(word)       // Consumed second by adv_loadw
///     .build();
/// ```
#[derive(Clone, Debug, Default)]
pub struct AdviceStackBuilder {
    /// Conceptual stack where front (index 0) is "top" (consumed first).
    stack: VecDeque<Felt>,
}

impl AdviceStackBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a single element onto the advice stack.
    ///
    /// Elements are consumed in FIFO order: first pushed = first consumed by advice operations.
    pub fn push_element(&mut self, value: Felt) -> &mut Self {
        self.stack.push_back(value);
        self
    }

    /// Extends the advice stack with raw elements (already ordered top-to-bottom).
    ///
    /// Elements are consumed in FIFO order: first element in iter = first consumed.
    pub fn push_elements<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.extend(values);
        self
    }

    /// Adds elements for consumption by `adv_push.n` instructions.
    ///
    /// After `adv_push.n`, the operand stack will have `slice[0]` on top.
    /// The slice length determines n (e.g., 4-element slice → `adv_push.4`).
    ///
    /// # How it works
    ///
    /// `adv_push.n` pops elements one-by-one from the advice stack and pushes each to the operand
    /// stack. Since each push goes to the top, the first-popped element ends up at the bottom
    /// of the n elements, and the last-popped element ends up on top.
    ///
    /// Therefore, this method reverses the slice internally so that `slice[0]` is popped last
    /// and ends up on top of the operand stack.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.push_for_adv_push(&[a, b, c]);
    /// // MASM: adv_push.3
    /// // Result: operand stack = [a, b, c, ...] with a on top
    /// ```
    pub fn push_for_adv_push(&mut self, slice: &[Felt]) -> &mut Self {
        // Reverse the slice: we want slice[0] to be popped last (ending up on top of operand stack)
        // So we add elements in reverse order to the back of our stack
        for elem in slice.iter().rev() {
            self.stack.push_back(*elem);
        }
        self
    }

    /// Adds a word for consumption by `padw adv_loadw`.
    ///
    /// After `adv_loadw`, the operand stack will have the structural word loaded directly.
    /// Use `reversew` afterward to convert to canonical (little-endian) order.
    ///
    /// # How it works
    ///
    /// The `adv_loadw` instruction:
    /// 1. Calls `pop_stack_word()` which pops 4 elements from front and creates
    ///    `Word::new(\[e0,e1,e2,e3\])`
    /// 2. Places the word on the operand stack with `word\[0\]` on top, `word\[1\]` at position 1,
    ///    etc.
    ///
    /// Elements are pushed without reversal since `adv_loadw` loads the structural word directly.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.push_for_adv_loadw([w0, w1, w2, w3].into());
    /// // MASM: padw adv_loadw
    /// // Result: operand stack = [w0, w1, w2, w3, ...] with w0 on top
    /// ```
    pub fn push_for_adv_loadw(&mut self, word: Word) -> &mut Self {
        // Push elements without reversal. adv_loadw loads the structural word directly,
        // so a `reversew` is needed afterward to get canonical order on the operand stack.
        for elem in word.iter() {
            self.stack.push_back(*elem);
        }
        self
    }

    /// Adds elements for sequential consumption by `adv_pipe` operations.
    ///
    /// Elements are consumed in order: `slice[0..8]` first, then `slice[8..16]`, etc.
    /// No reversal is applied.
    ///
    /// # Panics
    ///
    /// Panics if the slice length is not a multiple of 8 (double-word aligned).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.push_for_adv_pipe(&elements); // elements.len() must be multiple of 8
    /// // MASM: multiple adv_pipe calls
    /// // Result: elements consumed in order [elements[0], elements[1], ...]
    /// ```
    pub fn push_for_adv_pipe(&mut self, slice: &[Felt]) -> &mut Self {
        assert!(
            slice.len().is_multiple_of(8),
            "push_for_adv_pipe requires slice length to be a multiple of 8, got {}",
            slice.len()
        );

        for elem in slice.iter() {
            self.stack.push_back(*elem);
        }
        self
    }

    /// Extends the advice stack with u64 values converted to Felt.
    ///
    /// This is a convenience method for test data that is typically specified as u64.
    /// Elements are consumed in FIFO order: first element = first consumed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.push_u64_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    /// // Elements consumed in order: 1, 2, 3, 4, 5, 6, 7, 8
    /// ```
    pub fn push_u64_slice(&mut self, values: &[u64]) -> &mut Self {
        self.stack.extend(values.iter().map(|&v| Felt::new(v)));
        self
    }

    // INPUT BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Builds the `AdviceInputs` from the accumulated stack.
    ///
    /// The builder's conceptual stack (with index 0 as top) is converted to the format
    /// expected by `AdviceInputs`, which will be reversed when creating an `AdviceProvider`.
    pub fn build(self) -> AdviceInputs {
        AdviceInputs {
            stack: self.stack.into(),
            map: AdviceMap::default(),
            store: MerkleStore::default(),
        }
    }

    /// Builds the `AdviceInputs` with additional map and store data.
    pub fn build_with(self, map: AdviceMap, store: MerkleStore) -> AdviceInputs {
        AdviceInputs { stack: self.stack.into(), map, store }
    }

    /// Builds just the advice stack as `Vec<u64>` for use with `build_test!` macro.
    ///
    /// This is a convenience method that avoids needing to modify the test infrastructure.
    pub fn build_vec_u64(self) -> Vec<u64> {
        self.stack.into_iter().map(|f| f.as_canonical_u64()).collect()
    }

    /// Consumes the builder and returns the accumulated elements as `Vec<Felt>`.
    pub fn into_elements(self) -> Vec<Felt> {
        self.stack.into_iter().collect()
    }
}
