/*
use alloc::vec::Vec;

use crate::{
    StackInputs, StackOutputs,
    utils::{Deserializable, Serializable},
};

// SERDE INPUTS TESTS
// ================================================================================================

// TODO(Al)

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
 */
