use alloc::{collections::VecDeque, vec::Vec};

use super::{AdviceInputs, AdviceMap};
use crate::{Felt, Word, crypto::merkle::MerkleStore};

// ADVICE STACK
// ================================================================================================

/// Advice stack values ordered from top to bottom.
///
/// The front of the stack is the next element consumed by `adv_push`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdviceStack {
    stack: VecDeque<Felt>,
}

impl AdviceStack {
    /// Creates a new empty advice stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of elements on this advice stack.
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Returns true if this advice stack has no elements.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Returns an iterator over elements from top to bottom.
    pub fn iter(&self) -> impl Iterator<Item = &Felt> {
        self.stack.iter()
    }

    /// Pushes a single element onto the advice stack.
    ///
    /// Elements are consumed in FIFO order: first pushed = first consumed by advice operations.
    pub fn push_element(&mut self, value: Felt) -> &mut Self {
        self.stack.push_back(value);
        self
    }

    /// Extends the advice stack with raw elements ordered from top to bottom.
    ///
    /// Elements are consumed in FIFO order: first element in iter = first consumed.
    pub fn push_elements<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.extend(values);
        self
    }

    /// Adds elements for consumption by multiple sequential `adv_push` instructions.
    ///
    /// After `repeat.n adv_push end`, the operand stack will have `slice[0]` on top.
    pub fn push_for_adv_push(&mut self, slice: &[Felt]) -> &mut Self {
        for elem in slice.iter().rev() {
            self.stack.push_back(*elem);
        }
        self
    }

    /// Adds a word for consumption by `adv_loadw` or `adv_pushw`.
    pub fn push_word(&mut self, word: Word) -> &mut Self {
        self.stack.extend(word.iter().copied());
        self
    }

    /// Adds two words for consumption by `adv_pipe`.
    pub fn push_dword(&mut self, words: [Word; 2]) -> &mut Self {
        for word in words {
            self.push_word(word);
        }
        self
    }

    /// Adds elements for sequential consumption by `adv_pipe` operations.
    ///
    /// # Panics
    ///
    /// Panics if the slice length is not a multiple of 8 (double-word aligned).
    pub fn push_for_adv_pipe(&mut self, slice: &[Felt]) -> &mut Self {
        assert!(
            slice.len().is_multiple_of(8),
            "push_for_adv_pipe requires slice length to be a multiple of 8, got {}",
            slice.len()
        );

        self.stack.extend(slice.iter().copied());
        self
    }

    /// Consumes a single element from the top of the advice stack.
    pub fn consume_element(&mut self) -> Option<Felt> {
        self.stack.pop_front()
    }

    /// Consumes a word from the top of the advice stack.
    pub fn consume_word(&mut self) -> Option<Word> {
        if self.stack.len() < 4 {
            return None;
        }

        Some(Word::new([
            self.consume_element().expect("checked len"),
            self.consume_element().expect("checked len"),
            self.consume_element().expect("checked len"),
            self.consume_element().expect("checked len"),
        ]))
    }

    /// Consumes two words from the top of the advice stack.
    pub fn consume_dword(&mut self) -> Option<[Word; 2]> {
        if self.stack.len() < 8 {
            return None;
        }

        Some([self.consume_word()?, self.consume_word()?])
    }

    /// Consumes `self` and returns elements ordered from top to bottom.
    pub fn into_elements(self) -> Vec<Felt> {
        self.stack.into_iter().collect()
    }
}

impl From<Vec<Felt>> for AdviceStack {
    fn from(stack: Vec<Felt>) -> Self {
        Self { stack: stack.into() }
    }
}

impl From<VecDeque<Felt>> for AdviceStack {
    fn from(stack: VecDeque<Felt>) -> Self {
        Self { stack }
    }
}

impl From<AdviceStack> for Vec<Felt> {
    fn from(stack: AdviceStack) -> Self {
        stack.into_elements()
    }
}

impl FromIterator<Felt> for AdviceStack {
    fn from_iter<T: IntoIterator<Item = Felt>>(iter: T) -> Self {
        Self { stack: iter.into_iter().collect() }
    }
}

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
///     .push_for_adv_push(&[a, b, c])  // Consumed first by adv_push adv_push adv_push
///     .push_word(word)                // Consumed second by adv_loadw (or adv_pushw)
///     .build();
/// ```
#[derive(Clone, Debug, Default)]
pub struct AdviceStackBuilder {
    stack: AdviceStack,
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
        self.stack.push_element(value);
        self
    }

    /// Extends the advice stack with raw elements (already ordered top-to-bottom).
    ///
    /// Elements are consumed in FIFO order: first element in iter = first consumed.
    pub fn push_elements<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.push_elements(values);
        self
    }

    /// Adds elements for consumption by multiple sequential `adv_push` instructions.
    ///
    /// After `repeat.n adv_push end`, the operand stack will have `slice[0]` on top.
    ///
    /// # How it works
    ///
    /// Each `adv_push` pops one element from the advice stack and pushes it to the operand
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
    /// // MASM: adv_push adv_push adv_push
    /// // Result: operand stack = [a, b, c, ...] with a on top
    /// ```
    pub fn push_for_adv_push(&mut self, slice: &[Felt]) -> &mut Self {
        self.stack.push_for_adv_push(slice);
        self
    }

    /// Adds a word for consumption by `adv_loadw` or `adv_pushw`.
    ///
    /// Both instructions consume the same 4 elements from the advice stack and place them on
    /// the operand stack with `word[0]` on top; they differ only in whether the top operand
    /// word is overwritten (`adv_loadw`) or the stack grows by 4 (`adv_pushw`).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.push_word([w0, w1, w2, w3].into());
    /// // MASM: adv_loadw (or adv_pushw)
    /// // Result: operand stack = [w0, w1, w2, w3, ...] with w0 on top
    /// ```
    pub fn push_word(&mut self, word: Word) -> &mut Self {
        self.stack.push_word(word);
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
        self.stack.push_for_adv_pipe(slice);
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
        self.stack.push_elements(values.iter().map(|&v| Felt::new_unchecked(v)));
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
            stack: self.stack.into_elements(),
            map: AdviceMap::default(),
            store: MerkleStore::default(),
        }
    }

    /// Builds the `AdviceInputs` with additional map and store data.
    pub fn build_with(self, map: AdviceMap, store: MerkleStore) -> AdviceInputs {
        AdviceInputs {
            stack: self.stack.into_elements(),
            map,
            store,
        }
    }

    /// Builds just the advice stack as `Vec<u64>` for use with `build_test!` macro.
    ///
    /// This is a convenience method that avoids needing to modify the test infrastructure.
    pub fn build_vec_u64(self) -> Vec<u64> {
        self.stack.into_elements().into_iter().map(|f| f.as_canonical_u64()).collect()
    }

    /// Consumes the builder and returns the accumulated elements as `Vec<Felt>`.
    pub fn into_elements(self) -> Vec<Felt> {
        self.stack.into_elements()
    }
}
