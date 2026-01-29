use alloc::{collections::VecDeque, vec::Vec};

use miden_core::{
    AdviceMap, Felt, Word,
    crypto::merkle::MerkleStore,
    errors::InputError,
    field::{PrimeField64, QuotientMap},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// ADVICE INPUTS
// ================================================================================================

/// Inputs container to initialize advice provider for the execution of Miden VM programs.
///
/// The program may request nondeterministic advice inputs from the prover. These inputs are secret
/// inputs. This means that the prover does not need to share them with the verifier.
///
/// There are three types of advice inputs:
///
/// 1. Single advice stack which can contain any number of elements.
/// 2. Key-mapped element lists which can be pushed onto the advice stack.
/// 3. Merkle store, which is used to provide nondeterministic inputs for instructions that operates
///    with Merkle trees.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdviceInputs {
    pub stack: Vec<Felt>,
    pub map: AdviceMap,
    pub store: MerkleStore,
}

impl AdviceInputs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Attempts to extend the stack values with the given sequence of integers, returning an error
    /// if any of the numbers fails while converting to an element `[Felt]`.
    pub fn with_stack_values<I>(mut self, iter: I) -> Result<Self, InputError>
    where
        I: IntoIterator<Item = u64>,
    {
        let stack = iter
            .into_iter()
            .map(|v| Felt::from_canonical_checked(v).ok_or(InputError::InvalidStackElement(v)))
            .collect::<Result<Vec<_>, _>>()?;

        self.stack.extend(stack.iter());
        Ok(self)
    }

    /// Extends the stack with the given elements.
    pub fn with_stack<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.extend(iter);
        self
    }

    /// Extends the map of values with the given argument, replacing previously inserted items.
    pub fn with_map<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (Word, Vec<Felt>)>,
    {
        self.map.extend(iter);
        self
    }

    /// Replaces the [MerkleStore] with the provided argument.
    pub fn with_merkle_store(mut self, store: MerkleStore) -> Self {
        self.store = store;
        self
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Extends the contents of this instance with the contents of the other instance.
    pub fn extend(&mut self, other: Self) {
        self.stack.extend(other.stack);
        self.map.extend(other.map);
        self.store.extend(other.store.inner_nodes());
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

    /// Alias for `build_vec_u64` for compatibility with existing tests.
    pub fn into_u64_vec(self) -> Vec<u64> {
        self.build_vec_u64()
    }

    /// Consumes the builder and returns the accumulated elements as `Vec<Felt>`.
    pub fn into_elements(self) -> Vec<Felt> {
        self.stack.into_iter().collect()
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
}

impl Serializable for AdviceInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { stack, map, store } = self;
        stack.write_into(target);
        map.write_into(target);
        store.write_into(target);
    }
}

impl Deserializable for AdviceInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let stack = Vec::<Felt>::read_from(source)?;
        let map = AdviceMap::read_from(source)?;
        let store = MerkleStore::read_from(source)?;
        Ok(Self { stack, map, store })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, Word,
        utils::{Deserializable, Serializable},
    };

    use super::AdviceStackBuilder;
    use crate::AdviceInputs;

    #[test]
    fn test_advice_inputs_eq() {
        let advice1 = AdviceInputs::default();
        let advice2 = AdviceInputs::default();

        assert_eq!(advice1, advice2);

        let advice1 = AdviceInputs::default().with_stack_values([1, 2, 3].iter().copied()).unwrap();
        let advice2 = AdviceInputs::default().with_stack_values([1, 2, 3].iter().copied()).unwrap();

        assert_eq!(advice1, advice2);
    }

    #[test]
    fn test_advice_inputs_serialization() {
        let advice1 = AdviceInputs::default().with_stack_values([1, 2, 3].iter().copied()).unwrap();
        let bytes = advice1.to_bytes();
        let advice2 = AdviceInputs::read_from_bytes(&bytes).unwrap();

        assert_eq!(advice1, advice2);
    }

    // ADVICE STACK BUILDER TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn test_builder_push_for_adv_push() {
        // push_for_adv_push reverses the slice
        // Input: [a, b, c] -> Builder stack: [c, b, a] (c on top)
        let a = Felt::new(1);
        let b = Felt::new(2);
        let c = Felt::new(3);

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_push(&[a, b, c]);
        let advice = builder.build();

        // Builder stack is [c, b, a] with c on top (index 0)
        // This becomes AdviceInputs.stack = [c, b, a]
        assert_eq!(advice.stack, vec![c, b, a]);
    }

    #[test]
    fn test_builder_push_for_adv_loadw() {
        let word: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_loadw(word);
        let advice = builder.build();

        // Builder stack is [w0, w1, w2, w3] with w0 on top
        assert_eq!(advice.stack, vec![Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    }

    #[test]
    fn test_builder_push_for_adv_pipe() {
        let slice: Vec<Felt> = (1..=8).map(Felt::new).collect();

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_pipe(&slice);
        let advice = builder.build();

        assert_eq!(advice.stack, slice);
    }

    #[test]
    #[should_panic(expected = "push_for_adv_pipe requires slice length to be a multiple of 8")]
    fn test_builder_push_for_adv_pipe_panics_on_misalignment() {
        let slice: Vec<Felt> = (1..=7).map(Felt::new).collect();

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_pipe(&slice);
        builder.build();
    }

    #[test]
    fn test_builder_push_u64_slice() {
        // push_u64_slice converts u64 to Felt without reversal
        let mut builder = AdviceStackBuilder::new();
        builder.push_u64_slice(&[1, 2, 3, 4]);
        let advice = builder.build();

        assert_eq!(advice.stack, vec![Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    }

    #[test]
    fn test_builder_chaining_top_first() {
        // First call adds elements consumed first (on top)
        // Second call adds elements consumed second (below)
        let a = Felt::new(1);
        let b = Felt::new(2);
        let c = Felt::new(3);
        let word: Word = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)].into();

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_push(&[a, b, c]); // Consumed first
        builder.push_for_adv_loadw(word); // Consumed second
        let advice = builder.build();

        // Builder stack: [c, b, a, w0, w1, w2, w3]
        // (c on top from reversed [a,b,c], then word below)
        assert_eq!(
            advice.stack,
            vec![c, b, a, Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]
        );
    }

    #[test]
    fn test_builder_multiple_push_for_adv_push() {
        // Multiple calls should maintain top-first ordering
        let first = [Felt::new(1), Felt::new(2)];
        let second = [Felt::new(3), Felt::new(4)];

        let mut builder = AdviceStackBuilder::new();
        builder.push_for_adv_push(&first); // Consumed first
        builder.push_for_adv_push(&second); // Consumed second
        let advice = builder.build();

        // First call: [2, 1] (reversed)
        // Second call prepends: [4, 3, 2, 1] -> but wait, second is consumed AFTER first
        // So second should go BELOW first in the stack
        // Builder stack after first: [2, 1]
        // Builder stack after second: [2, 1, 4, 3]
        assert_eq!(advice.stack, vec![Felt::new(2), Felt::new(1), Felt::new(4), Felt::new(3)]);
    }
}
