use alloc::{collections::VecDeque, vec::Vec};

use crate::{Felt, Word, field::QuotientMap, program::InputError};

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

    /// Creates an advice stack from integer values ordered from top to bottom.
    ///
    /// # Errors
    ///
    /// Returns an error if any value is not a valid field element.
    pub fn try_from_values<I>(values: I) -> Result<Self, InputError>
    where
        I: IntoIterator<Item = u64>,
    {
        values
            .into_iter()
            .map(|value| {
                Felt::from_canonical_checked(value).ok_or(InputError::InvalidStackElement(value))
            })
            .collect()
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

    /// Appends a single element to the bottom of the advice stack.
    ///
    /// The appended element is consumed after all existing advice stack elements.
    pub fn append_element(&mut self, value: Felt) -> &mut Self {
        self.stack.push_back(value);
        self
    }

    /// Appends raw elements to the bottom of the advice stack.
    ///
    /// Values are ordered from top to bottom within the appended block.
    pub fn append_elements<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.extend(values);
        self
    }

    /// Prepends raw elements ordered from top to bottom.
    ///
    /// The first element in `values` becomes the next element consumed by advice operations.
    pub fn prepend_elements<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator<Item = Felt>,
    {
        let values: Vec<Felt> = values.into_iter().collect();
        for value in values.into_iter().rev() {
            self.stack.push_front(value);
        }
        self
    }

    /// Pushes a single element onto the top of the advice stack.
    pub fn push_element(&mut self, value: Felt) -> &mut Self {
        self.stack.push_front(value);
        self
    }

    /// Prepends a word to the top of the advice stack.
    pub fn prepend_word(&mut self, word: Word) -> &mut Self {
        self.prepend_elements(word.iter().copied())
    }

    /// Prepends another advice stack to the top of this stack.
    pub fn prepend_stack(&mut self, stack: AdviceStack) -> &mut Self {
        self.prepend_elements(stack.into_elements())
    }

    /// Appends elements for consumption by multiple sequential `adv_push` instructions.
    ///
    /// After `repeat.n adv_push end`, the operand stack will have `slice[0]` on top.
    pub fn append_for_adv_push(&mut self, slice: &[Felt]) -> &mut Self {
        for elem in slice.iter().rev() {
            self.stack.push_back(*elem);
        }
        self
    }

    /// Appends a word for consumption by `adv_loadw` or `adv_pushw`.
    pub fn append_word(&mut self, word: Word) -> &mut Self {
        self.stack.extend(word.iter().copied());
        self
    }

    /// Appends two words for consumption by `adv_pipe`.
    pub fn append_dword(&mut self, words: [Word; 2]) -> &mut Self {
        for word in words {
            self.append_word(word);
        }
        self
    }

    /// Appends elements for sequential consumption by `adv_pipe` operations.
    ///
    /// # Panics
    ///
    /// Panics if the slice length is not a multiple of 8 (double-word aligned).
    pub fn append_for_adv_pipe(&mut self, slice: &[Felt]) -> &mut Self {
        assert!(
            slice.len().is_multiple_of(8),
            "append_for_adv_pipe requires slice length to be a multiple of 8, got {}",
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
