use super::*;

#[rstest]
#[case(false)]
#[case(true)]
#[tokio::test(flavor = "current_thread")]
async fn proving_with_debug_info_retains_advice(#[case] explicit_source_node: bool) {
    let fixture = same_digest_entrypoint_fixture(vec![Operation::Add], "add");
    let mut builder = PackageDebugInfoBuilder::default();
    let source_node = builder
        .add_node(debug_source_node(fixture.program.entrypoint(), Vec::new(), 1, Vec::new()))
        .unwrap();
    builder.add_root(source_node);
    let debug_info = builder.build();
    let stack_inputs = StackInputs::new(&[Felt::from_u32(3), Felt::from_u32(4)]).unwrap();
    let advice_inputs =
        AdviceInputs::default().with_map([(Word::empty(), vec![Felt::from_u32(42)])]);
    let mut sync_host = DefaultHost::default();
    let mut async_host = DefaultHost::default();

    let source_context = Some(crate::PackageSourceDebugContext::new_optional(
        &debug_info,
        explicit_source_node.then_some(source_node),
    ));
    let request = |advice| {
        Processor::new(&fixture.program)
            .with_stack_inputs(stack_inputs)
            .with_advice(advice)
            .with_source_context(source_context)
    };
    let sync_result = request(advice_inputs.clone())
        .record_witness()
        .run_sync(&mut sync_host)
        .unwrap();
    let async_result = request(advice_inputs).record_witness().run(&mut async_host).await.unwrap();

    assert_eq!(sync_result.claim, async_result.claim);
    assert_eq!(sync_result.advice, async_result.advice);
    for crate::WitnessOutput { witness, advice, .. } in [sync_result, async_result] {
        assert_eq!(witness.claim().stack_outputs().get_element(0), Some(Felt::from_u32(7)));
        assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::from_u32(42)].as_slice()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn proving_with_advice_preserves_explicit_source_errors() {
    let fixture =
        same_digest_entrypoint_fixture(vec![Operation::Assert(Felt::from_u32(9))], "assert");
    let mut sync_host = DefaultHost::default().with_source_manager(fixture.source_manager.clone());
    let mut async_host = DefaultHost::default().with_source_manager(fixture.source_manager);
    let sync_error = Processor::new(&fixture.program)
        .with_source_context(Some(crate::PackageSourceDebugContext::new_optional(
            &fixture.debug_info,
            Some(fixture.entrypoint_source_node_id),
        )))
        .record_witness()
        .run_sync(&mut sync_host)
        .unwrap_err();
    let async_error = Processor::new(&fixture.program)
        .with_source_context(Some(crate::PackageSourceDebugContext::new_optional(
            &fixture.debug_info,
            Some(fixture.entrypoint_source_node_id),
        )))
        .record_witness()
        .run(&mut async_host)
        .await
        .unwrap_err();

    for error in [sync_error, async_error] {
        assert_matches!(
            error,
            ExecutionError::OperationError {
                label,
                source_file: Some(actual_source_file),
                err: OperationError::FailedAssertion { err_code, .. },
            } if label == SourceSpan::new(fixture.source_file.id(), 9u32..17)
                && actual_source_file.id() == fixture.source_file.id()
                && err_code == Felt::from_u32(9)
        );
    }
}
