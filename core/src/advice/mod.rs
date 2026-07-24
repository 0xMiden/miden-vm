use alloc::vec::Vec;

use crate::{
    Felt, Word,
    crypto::merkle::MerkleStore,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod map;
pub use map::AdviceMap;

mod stack;
pub use stack::AdviceStack;

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
    advice_stack: AdviceStack,
    pub map: AdviceMap,
    pub store: MerkleStore,
}

impl AdviceInputs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the advice stack with the provided typed stack.
    pub fn with_advice_stack(mut self, stack: AdviceStack) -> Self {
        self.advice_stack = stack;
        self
    }

    /// Returns the advice stack as a typed stack.
    pub fn advice_stack(&self) -> AdviceStack {
        self.advice_stack.clone()
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
        self.advice_stack.push_elements(other.advice_stack.into_elements());
        self.map.extend(other.map);
        self.store.extend(other.store.inner_nodes());
    }

    /// Consumes this instance and returns its parts.
    pub fn into_parts(self) -> (AdviceStack, AdviceMap, MerkleStore) {
        (self.advice_stack, self.map, self.store)
    }
}

impl Serializable for AdviceInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { advice_stack, map, store } = self;
        let stack: Vec<Felt> = advice_stack.iter().copied().collect();
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
        Ok(Self { advice_stack: stack.into(), map, store })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{AdviceInputs, AdviceStack};
    use crate::{
        Felt, Word,
        serde::{Deserializable, Serializable},
    };

    #[test]
    fn test_advice_inputs_eq() {
        let advice1 = AdviceInputs::default();
        let advice2 = AdviceInputs::default();

        assert_eq!(advice1, advice2);

        let advice1 = AdviceInputs::default()
            .with_advice_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());
        let advice2 = AdviceInputs::default()
            .with_advice_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());

        assert_eq!(advice1, advice2);
    }

    #[test]
    fn test_advice_inputs_serialization() {
        let advice1 = AdviceInputs::default()
            .with_advice_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());
        let bytes = advice1.to_bytes();
        let advice2 = AdviceInputs::read_from_bytes(&bytes).unwrap();

        assert_eq!(advice1, advice2);
    }

    #[test]
    fn advice_inputs_accept_typed_advice_stack() {
        let mut stack = AdviceStack::new();
        stack.push_element(Felt::new_unchecked(1));
        stack.push_word(
            [
                Felt::new_unchecked(2),
                Felt::new_unchecked(3),
                Felt::new_unchecked(4),
                Felt::new_unchecked(5),
            ]
            .into(),
        );

        let advice = AdviceInputs::default().with_advice_stack(stack.clone());

        assert_eq!(advice.advice_stack(), stack);
    }

    #[test]
    fn advice_stack_consumes_word_sized_groups_top_first() {
        let word0: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let word1: Word = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]
        .into();
        let mut stack = AdviceStack::new();

        stack.push_element(Felt::new_unchecked(0));
        stack.push_word(word0);
        stack.push_dword([word1, word0]);

        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(0)));
        assert_eq!(stack.consume_word(), Some(word0));
        assert_eq!(stack.consume_dword(), Some([word1, word0]));
        assert!(stack.is_empty());
    }

    #[test]
    fn advice_stack_rejects_partial_dword_without_consuming() {
        let word: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let mut stack = AdviceStack::new();
        stack.push_word(word);

        assert_eq!(stack.consume_dword(), None);
        assert_eq!(stack.consume_word(), Some(word));
    }

    #[test]
    fn advice_stack_push_for_adv_push_matches_repeated_consumption() {
        let values = [Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];
        let mut stack = AdviceStack::new();
        stack.push_for_adv_push(&values);

        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(3)));
        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(2)));
        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(1)));
        assert!(stack.is_empty());
    }

    #[test]
    fn advice_stack_push_for_adv_pipe_requires_dword_alignment() {
        let values: Vec<Felt> = (1..=16).map(Felt::new_unchecked).collect();
        let mut stack = AdviceStack::new();
        stack.push_for_adv_pipe(&values);

        assert_eq!(stack.into_elements(), values);
    }

    #[test]
    #[should_panic(expected = "push_for_adv_pipe requires slice length to be a multiple of 8")]
    fn advice_stack_push_for_adv_pipe_panics_on_misalignment() {
        let values: Vec<Felt> = (1..=7).map(Felt::new_unchecked).collect();
        let mut stack = AdviceStack::new();
        stack.push_for_adv_pipe(&values);
    }

    #[test]
    fn advice_stack_prepends_new_top_elements() {
        let mut stack = AdviceStack::from(vec![Felt::new_unchecked(3), Felt::new_unchecked(4)]);

        stack.prepend_element(Felt::new_unchecked(2));
        stack.prepend_elements([Felt::new_unchecked(0), Felt::new_unchecked(1)]);

        assert_eq!(
            stack.into_elements(),
            vec![
                Felt::new_unchecked(0),
                Felt::new_unchecked(1),
                Felt::new_unchecked(2),
                Felt::new_unchecked(3),
                Felt::new_unchecked(4),
            ]
        );
    }

    // INTEGER INPUT TESTS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn advice_stack_try_from_values_keeps_top_first_order() {
        let stack = AdviceStack::try_from_values([1, 2, 3, 4]).unwrap();

        assert_eq!(
            stack.into_elements(),
            vec![
                Felt::new_unchecked(1),
                Felt::new_unchecked(2),
                Felt::new_unchecked(3),
                Felt::new_unchecked(4)
            ]
        );
    }
}
