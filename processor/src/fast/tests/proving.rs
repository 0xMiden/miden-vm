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
    let sync_processor =
        FastProcessor::new(stack_inputs).with_advice(advice_inputs.clone()).unwrap();
    let async_processor = FastProcessor::new(stack_inputs).with_advice(advice_inputs).unwrap();
    let mut sync_host = DefaultHost::default();
    let mut async_host = DefaultHost::default();

    let sync_result = if explicit_source_node {
        sync_processor.execute_for_proving_with_package_debug_info_at_source_node_and_advice_sync(
            &fixture.program,
            &debug_info,
            source_node,
            &mut sync_host,
        )
    } else {
        sync_processor.execute_for_proving_with_package_debug_info_and_advice_sync(
            &fixture.program,
            &debug_info,
            &mut sync_host,
        )
    }
    .unwrap();
    let async_result = if explicit_source_node {
        async_processor
            .execute_for_proving_with_package_debug_info_at_source_node_and_advice(
                &fixture.program,
                &debug_info,
                source_node,
                &mut async_host,
            )
            .await
    } else {
        async_processor
            .execute_for_proving_with_package_debug_info_and_advice(
                &fixture.program,
                &debug_info,
                &mut async_host,
            )
            .await
    }
    .unwrap();

    assert_eq!(sync_result.0.claim(), async_result.0.claim());
    assert_eq!(sync_result.1, async_result.1);
    for (witness, advice) in [sync_result, async_result] {
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
    let sync_error = FastProcessor::new(StackInputs::default())
        .execute_for_proving_with_package_debug_info_at_source_node_and_advice_sync(
            &fixture.program,
            &fixture.debug_info,
            fixture.entrypoint_source_node_id,
            &mut sync_host,
        )
        .unwrap_err();
    let async_error = FastProcessor::new(StackInputs::default())
        .execute_for_proving_with_package_debug_info_at_source_node_and_advice(
            &fixture.program,
            &fixture.debug_info,
            fixture.entrypoint_source_node_id,
            &mut async_host,
        )
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
