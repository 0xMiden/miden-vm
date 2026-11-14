use {
    miden_processor::Felt,
    miden_processor::advice::AdviceInputs,
    miden_processor::advice::AdviceStack,
};

#[test]
fn advice_stack_is_available_through_processor_advice_facade() {
    let mut stack = AdviceStack::new();
    let value = Felt::new_unchecked(1);
    stack.append_element(value);

    let advice_inputs = AdviceInputs::default().with_stack(stack);

    assert_eq!(advice_inputs.stack().into_elements(), vec![value]);
}

#[test]
fn precompile_witness_root_and_trace_paths_preserve_type_identity() {
    let witness: Option<miden_core::deferred::PrecompileWitness> = None;
    let witness: Option<miden_processor::PrecompileWitness> = witness;
    let _: Option<miden_processor::trace::PrecompileWitness> = witness;
}
