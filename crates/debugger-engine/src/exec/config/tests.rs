use miden_processor::Felt as RawFelt;
use toml::toml;

use super::{ExecutionConfig, *};

#[test]
fn execution_config_empty() {
    let text = toml::to_string_pretty(&toml! {
        [inputs]
        [options]
    })
    .unwrap();

    let file = toml::from_str::<ExecutionConfig>(&text).unwrap();
    let expected_inputs = StackInputs::new(&[]).unwrap();
    assert_eq!(file.inputs.as_ref(), expected_inputs.as_ref());
    assert!(file.advice_inputs.stack().is_empty());
    assert_eq!(file.options.max_cycles(), ExecutionOptions::MAX_CYCLES);
    assert_eq!(file.options.expected_cycles(), ExecutionOptions::default().expected_cycles());
}

#[test]
fn execution_config_with_options() {
    let text = toml::to_string_pretty(&toml! {
        [inputs]
        [options]
        max_cycles = 100000
    })
    .unwrap();

    let file = ExecutionConfig::parse_str(&text).unwrap();
    let expected_inputs = StackInputs::new(&[]).unwrap();
    assert_eq!(file.inputs.as_ref(), expected_inputs.as_ref());
    assert!(file.advice_inputs.stack().is_empty());
    assert_eq!(file.options.max_cycles(), 100000);
    assert_eq!(file.options.expected_cycles(), ExecutionOptions::default().expected_cycles());
}

#[test]
fn execution_config_with_operands() {
    let text = toml::to_string_pretty(&toml! {
        [inputs]
        stack = [1, 2, 3]

        [options]
        max_cycles = 100000
    })
    .unwrap();

    let file = ExecutionConfig::parse_str(&text).unwrap();
    let expected_inputs = StackInputs::new(&[
        RawFelt::new(1).expect("value exceeds field modulus"),
        RawFelt::new(2).expect("value exceeds field modulus"),
        RawFelt::new(3).expect("value exceeds field modulus"),
    ])
    .unwrap();
    assert_eq!(file.inputs.as_ref(), expected_inputs.as_ref());
    assert!(file.advice_inputs.stack().is_empty());
    assert_eq!(file.options.max_cycles(), 100000);
    assert_eq!(file.options.expected_cycles(), ExecutionOptions::default().expected_cycles());
}

#[test]
fn execution_config_with_advice() {
    let text = toml::to_string_pretty(&toml! {
        [inputs]
        stack = [1, 2, 0x3]

        [inputs.advice]
        stack = [1, 2, 3, 4]

        [[inputs.advice.map]]
        digest = "0x3cff5b58a573dc9d25fd3c57130cc57e5b1b381dc58b5ae3594b390c59835e63"
        values = [1, 2, 3, 4]

        [options]
        max_cycles = 100000
    })
    .unwrap();
    let digest = miden_core::Word::try_from(
        "0x3cff5b58a573dc9d25fd3c57130cc57e5b1b381dc58b5ae3594b390c59835e63",
    )
    .unwrap();
    let file = ExecutionConfig::parse_str(&text).unwrap_or_else(|err| panic!("{err}"));
    let expected_inputs = StackInputs::new(&[
        RawFelt::new(1).expect("value exceeds field modulus"),
        RawFelt::new(2).expect("value exceeds field modulus"),
        RawFelt::new(3).expect("value exceeds field modulus"),
    ])
    .unwrap();
    assert_eq!(file.inputs.as_ref(), expected_inputs.as_ref());
    assert_eq!(
        file.advice_inputs.stack().into_elements(),
        &[
            RawFelt::new(1).expect("value exceeds field modulus"),
            RawFelt::new(2).expect("value exceeds field modulus"),
            RawFelt::new(3).expect("value exceeds field modulus"),
            RawFelt::new(4).expect("value exceeds field modulus")
        ]
    );
    assert_eq!(
        file.advice_inputs.map().get(&digest).map(|value| value.as_ref()),
        Some(
            [
                RawFelt::new(1).expect("value exceeds field modulus"),
                RawFelt::new(2).expect("value exceeds field modulus"),
                RawFelt::new(3).expect("value exceeds field modulus"),
                RawFelt::new(4).expect("value exceeds field modulus")
            ]
            .as_slice()
        )
    );
    assert_eq!(file.options.max_cycles(), 100000);
    assert_eq!(file.options.expected_cycles(), ExecutionOptions::default().expected_cycles());
}
