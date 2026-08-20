use miden_processor::{
    ExecutionOptions, ZERO,
    advice::{AdviceError, AdviceInputs, AdviceProvider, AdviceStack},
};

const PROTOCOL_LOWER_BOUND_BYTES: usize = 8_445_856;
const DEFAULT_MAX_ADVICE_SIZE_BYTES: usize = 16 * 1024 * 1024;
const FELT_SIZE_BYTES: usize = 8;

fn stack_inputs(stack_bytes: usize) -> AdviceInputs {
    assert_eq!(stack_bytes % FELT_SIZE_BYTES, 0);
    AdviceInputs::default().with_stack(AdviceStack::from(vec![
        ZERO;
        stack_bytes / FELT_SIZE_BYTES
    ]))
}

#[test]
fn default_options_accept_advice_above_protocol_lower_bound() {
    let inputs = stack_inputs(PROTOCOL_LOWER_BOUND_BYTES + FELT_SIZE_BYTES);

    AdviceProvider::new(inputs, &ExecutionOptions::default())
        .expect("default advice budget should accept advice above the Protocol lower bound");
}

#[test]
fn default_options_reject_advice_above_16_mib() {
    let inputs = stack_inputs(DEFAULT_MAX_ADVICE_SIZE_BYTES + FELT_SIZE_BYTES);

    let err = AdviceProvider::new(inputs, &ExecutionOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        AdviceError::SizeBudgetExceeded { max, .. } if max == DEFAULT_MAX_ADVICE_SIZE_BYTES
    ));
}
