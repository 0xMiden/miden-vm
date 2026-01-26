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

// GET_STACK_WORD TESTS
// ================================================================================================

#[test]
fn test_get_stack_word() {
    use crate::Felt;

    // Create stack outputs with known values: [1, 2, 3, 4, 5, 6, 7, 8, ...]
    let source = Vec::<u64>::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let outputs = StackOutputs::try_from_ints(source).unwrap();

    // For idx=0, we expect [1, 2, 3, 4] (elements at positions 0-3, in order)
    let word_0 = outputs.get_word(0).unwrap();
    assert_eq!(word_0[0], Felt::new(1), "word[0] element 0");
    assert_eq!(word_0[1], Felt::new(2), "word[0] element 1");
    assert_eq!(word_0[2], Felt::new(3), "word[0] element 2");
    assert_eq!(word_0[3], Felt::new(4), "word[0] element 3");

    // For idx=4, we expect [5, 6, 7, 8]
    let word_4 = outputs.get_word(4).unwrap();
    assert_eq!(word_4[0], Felt::new(5), "word[4] element 0");
    assert_eq!(word_4[1], Felt::new(6), "word[4] element 1");
    assert_eq!(word_4[2], Felt::new(7), "word[4] element 2");
    assert_eq!(word_4[3], Felt::new(8), "word[4] element 3");

    // Test bounds checking - should return None for out of bounds access
    assert!(outputs.get_word(13).is_none(), "Should return None for out of bounds");
}
