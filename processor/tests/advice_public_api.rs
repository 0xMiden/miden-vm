use miden_processor::{
    Felt,
    advice::{AdviceInputs, AdviceStack},
};

#[test]
fn advice_stack_is_available_through_processor_advice_facade() {
    let mut stack = AdviceStack::new();
    let value = Felt::new_unchecked(1);
    stack.push_element(value);

    let advice_inputs = AdviceInputs::default().with_advice_stack(stack);

    assert_eq!(advice_inputs.advice_stack().into_elements(), vec![value]);
}
