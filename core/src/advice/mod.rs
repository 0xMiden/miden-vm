use alloc::vec::Vec;

use crate::{
    Felt, Word,
    crypto::merkle::MerkleStore,
    field::QuotientMap,
    stack::InputError,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod map;
pub use map::AdviceMap;

mod stack;
pub use stack::AdviceStackBuilder;

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

    use super::{AdviceInputs, AdviceStackBuilder};
    use crate::{
        Felt, Word,
        utils::{Deserializable, Serializable},
    };

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
