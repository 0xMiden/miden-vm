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
    stack: AdviceStack,
    map: AdviceMap,
    store: MerkleStore,
}

impl AdviceInputs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new advice inputs container from the provided stack, map, and Merkle store.
    pub fn new(stack: AdviceStack, map: AdviceMap, store: MerkleStore) -> Self {
        Self { stack, map, store }
    }

    /// Replaces the stack with the provided typed stack.
    pub fn with_stack(mut self, stack: AdviceStack) -> Self {
        self.stack = stack;
        self
    }

    /// Returns the advice stack.
    pub fn stack(&self) -> AdviceStack {
        self.stack.clone()
    }

    /// Returns the advice map.
    pub fn map(&self) -> &AdviceMap {
        &self.map
    }

    /// Returns the Merkle store.
    pub fn store(&self) -> &MerkleStore {
        &self.store
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
        self.stack.append_elements(other.stack.into_elements());
        self.map.extend(other.map);
        self.store.extend(other.store.inner_nodes());
    }

    /// Consumes this instance and returns its parts.
    pub fn into_parts(self) -> (AdviceStack, AdviceMap, MerkleStore) {
        (self.stack, self.map, self.store)
    }
}

impl From<AdviceMap> for AdviceInputs {
    fn from(map: AdviceMap) -> Self {
        Self {
            stack: AdviceStack::default(),
            map,
            store: MerkleStore::default(),
        }
    }
}

impl Serializable for AdviceInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { stack, map, store } = self;
        let stack: Vec<Felt> = stack.iter().copied().collect();
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
        Ok(Self { stack: stack.into(), map, store })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{AdviceInputs, AdviceMap, AdviceStack};
    use crate::{
        Felt, Word,
        crypto::merkle::MerkleStore,
        serde::{Deserializable, Serializable},
    };

    #[test]
    fn test_advice_inputs_eq() {
        let advice1 = AdviceInputs::default();
        let advice2 = AdviceInputs::default();

        assert_eq!(advice1, advice2);

        let advice1 =
            AdviceInputs::default().with_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());
        let advice2 =
            AdviceInputs::default().with_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());

        assert_eq!(advice1, advice2);
    }

    #[test]
    fn test_advice_inputs_serialization() {
        let advice1 =
            AdviceInputs::default().with_stack(AdviceStack::try_from_values([1, 2, 3]).unwrap());
        let bytes = advice1.to_bytes();
        let advice2 = AdviceInputs::read_from_bytes(&bytes).unwrap();

        assert_eq!(advice1, advice2);
    }

    #[test]
    fn advice_inputs_new_assembles_parts() {
        let stack = AdviceStack::try_from_values([1, 2, 3]).unwrap();
        let map = AdviceMap::from_iter([(Word::default(), vec![Felt::new_unchecked(7)])]);
        let store = MerkleStore::default();

        let advice = AdviceInputs::new(stack.clone(), map.clone(), store.clone());

        assert_eq!(advice.stack(), stack);
        assert_eq!(advice.map, map);
        assert_eq!(advice.store, store);
    }

    #[test]
    fn advice_inputs_from_advice_map_defaults_other_parts() {
        let map = AdviceMap::from_iter([(Word::default(), vec![Felt::new_unchecked(7)])]);

        let advice = AdviceInputs::from(map.clone());

        assert_eq!(advice.stack(), AdviceStack::default());
        assert_eq!(advice.map, map);
        assert_eq!(advice.store, MerkleStore::default());
    }

    #[test]
    fn advice_inputs_accept_typed_advice_stack() {
        let mut stack = AdviceStack::new();
        stack.append_element(Felt::new_unchecked(1));
        stack.append_word(
            [
                Felt::new_unchecked(2),
                Felt::new_unchecked(3),
                Felt::new_unchecked(4),
                Felt::new_unchecked(5),
            ]
            .into(),
        );

        let advice = AdviceInputs::default().with_stack(stack.clone());

        assert_eq!(advice.stack(), stack);
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

        stack.append_element(Felt::new_unchecked(0));
        stack.append_word(word0);
        stack.append_dword([word1, word0]);

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
        stack.append_word(word);

        assert_eq!(stack.consume_dword(), None);
        assert_eq!(stack.consume_word(), Some(word));
    }

    #[test]
    fn advice_stack_append_for_adv_push_matches_repeated_consumption() {
        let values = [Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];
        let mut stack = AdviceStack::new();
        stack.append_for_adv_push(&values);

        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(3)));
        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(2)));
        assert_eq!(stack.consume_element(), Some(Felt::new_unchecked(1)));
        assert!(stack.is_empty());
    }

    #[test]
    fn advice_stack_append_for_adv_pipe_requires_dword_alignment() {
        let values: Vec<Felt> = (1..=16).map(Felt::new_unchecked).collect();
        let mut stack = AdviceStack::new();
        stack.append_for_adv_pipe(&values);

        assert_eq!(stack.into_elements(), values);
    }

    #[test]
    #[should_panic(expected = "append_for_adv_pipe requires slice length to be a multiple of 8")]
    fn advice_stack_append_for_adv_pipe_panics_on_misalignment() {
        let values: Vec<Felt> = (1..=7).map(Felt::new_unchecked).collect();
        let mut stack = AdviceStack::new();
        stack.append_for_adv_pipe(&values);
    }

    #[test]
    fn advice_stack_prepends_new_top_elements() {
        let mut stack = AdviceStack::from(vec![Felt::new_unchecked(3), Felt::new_unchecked(4)]);

        stack.push_element(Felt::new_unchecked(2));
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
