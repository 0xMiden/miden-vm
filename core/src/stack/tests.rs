use alloc::vec::Vec;

use crate::{
    StackInputs, StackOutputs,
    utils::{Deserializable, Serializable},
};

// SERDE INPUTS TESTS
// ================================================================================================

#[test]
fn test_inputs_simple() {
    let source = Vec::<u64>::from([5, 4, 3, 2, 1]);
    let mut serialized = Vec::new();
    let inputs = StackInputs::try_from_ints(source.clone()).unwrap();

    inputs.write_into(&mut serialized);

    let mut expected_serialized = Vec::new();
    expected_serialized.push(source.len() as u8);
    source
        .iter()
        .rev()
        .for_each(|v| expected_serialized.append(&mut v.to_le_bytes().to_vec()));

    assert_eq!(serialized, expected_serialized);

    let result = StackInputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

#[test]
fn test_inputs_full() {
    let source = Vec::<u64>::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    let mut serialized = Vec::new();
    let inputs = StackInputs::try_from_ints(source.clone()).unwrap();

    inputs.write_into(&mut serialized);

    let mut expected_serialized = Vec::new();
    expected_serialized.push(source.len() as u8);
    source
        .iter()
        .rev()
        .for_each(|v| expected_serialized.append(&mut v.to_le_bytes().to_vec()));

    assert_eq!(serialized, expected_serialized);

    let result = StackInputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

#[test]
fn test_inputs_empty() {
    let mut serialized = Vec::new();
    let inputs = StackInputs::try_from_ints([]).unwrap();

    inputs.write_into(&mut serialized);

    let expected_serialized = vec![0];

    assert_eq!(serialized, expected_serialized);

    let result = StackInputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

// SERDE OUTPUTS TESTS
// ================================================================================================

#[test]
fn test_outputs_simple() {
    let source = Vec::<u64>::from([1, 2, 3, 4, 5]);
    let mut serialized = Vec::new();
    let inputs = StackOutputs::try_from_ints(source.clone()).unwrap();

    inputs.write_into(&mut serialized);

    let mut expected_serialized = Vec::new();
    expected_serialized.push(source.len() as u8);
    source
        .iter()
        .for_each(|v| expected_serialized.append(&mut v.to_le_bytes().to_vec()));

    assert_eq!(serialized, expected_serialized);

    let result = StackOutputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

#[test]
fn test_outputs_full() {
    let source = Vec::<u64>::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let mut serialized = Vec::new();
    let inputs = StackOutputs::try_from_ints(source.clone()).unwrap();

    inputs.write_into(&mut serialized);

    let mut expected_serialized = Vec::new();
    expected_serialized.push(source.len() as u8);
    source
        .iter()
        .for_each(|v| expected_serialized.append(&mut v.to_le_bytes().to_vec()));

    assert_eq!(serialized, expected_serialized);

    let result = StackOutputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

#[test]
fn test_outputs_empty() {
    let mut serialized = Vec::new();
    let inputs = StackOutputs::try_from_ints([]).unwrap();

    inputs.write_into(&mut serialized);

    let expected_serialized = vec![0];

    assert_eq!(serialized, expected_serialized);

    let result = StackOutputs::read_from_bytes(&serialized).unwrap();

    assert_eq!(*inputs, *result);
}

// GET_STACK_WORD ENDIANNESS TESTS
// ================================================================================================

#[test]
fn test_get_stack_word_be_and_le() {
    use crate::Felt;

    // Create stack outputs with known values: [1, 2, 3, 4, 5, 6, 7, 8, ...]
    let source = Vec::<u64>::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let outputs = StackOutputs::try_from_ints(source).unwrap();

    // Test big-endian (reversed) ordering
    // For idx=0, we expect [4, 3, 2, 1] (elements at positions 0-3, reversed)
    let word_be_0 = outputs.get_stack_word_be(0).unwrap();
    assert_eq!(word_be_0[0], Felt::new(4), "BE word[0] element 0");
    assert_eq!(word_be_0[1], Felt::new(3), "BE word[0] element 1");
    assert_eq!(word_be_0[2], Felt::new(2), "BE word[0] element 2");
    assert_eq!(word_be_0[3], Felt::new(1), "BE word[0] element 3");

    // For idx=4, we expect [8, 7, 6, 5]
    let word_be_4 = outputs.get_stack_word_be(4).unwrap();
    assert_eq!(word_be_4[0], Felt::new(8), "BE word[4] element 0");
    assert_eq!(word_be_4[1], Felt::new(7), "BE word[4] element 1");
    assert_eq!(word_be_4[2], Felt::new(6), "BE word[4] element 2");
    assert_eq!(word_be_4[3], Felt::new(5), "BE word[4] element 3");

    // Test little-endian (memory) ordering
    // For idx=0, we expect [1, 2, 3, 4] (elements at positions 0-3, in order)
    let word_le_0 = outputs.get_stack_word_le(0).unwrap();
    assert_eq!(word_le_0[0], Felt::new(1), "LE word[0] element 0");
    assert_eq!(word_le_0[1], Felt::new(2), "LE word[0] element 1");
    assert_eq!(word_le_0[2], Felt::new(3), "LE word[0] element 2");
    assert_eq!(word_le_0[3], Felt::new(4), "LE word[0] element 3");

    // For idx=4, we expect [5, 6, 7, 8]
    let word_le_4 = outputs.get_stack_word_le(4).unwrap();
    assert_eq!(word_le_4[0], Felt::new(5), "LE word[4] element 0");
    assert_eq!(word_le_4[1], Felt::new(6), "LE word[4] element 1");
    assert_eq!(word_le_4[2], Felt::new(7), "LE word[4] element 2");
    assert_eq!(word_le_4[3], Felt::new(8), "LE word[4] element 3");

    // Verify that get_stack_word() is an alias for get_stack_word_be()
    #[allow(deprecated)]
    let word_default = outputs.get_stack_word(0).unwrap();
    assert_eq!(word_default, word_be_0, "get_stack_word() should equal get_stack_word_be()");

    // Test bounds checking - should return None for out of bounds access
    assert!(
        outputs.get_stack_word_be(13).is_none(),
        "Should return None for out of bounds BE"
    );
    assert!(
        outputs.get_stack_word_le(13).is_none(),
        "Should return None for out of bounds LE"
    );
}
