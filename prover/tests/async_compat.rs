use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, ExecutionOptions, FastProcessor, Felt, FutureMaybeSend, Host,
    LoadedMastForest, ProcessorState, Word,
    advice::AdviceMutation,
    event::{EventError, EventName},
};
use miden_prover::{AdviceInputs, ExecutionProof, Prover, StackInputs};

struct YieldingAsyncHost {
    event_calls: usize,
}

impl YieldingAsyncHost {
    fn new() -> Self {
        Self { event_calls: 0 }
    }
}

impl BaseHost for YieldingAsyncHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for YieldingAsyncHost {
    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        async { None }
    }

    fn on_event(
        &mut self,
        _process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        self.event_calls += 1;
        async {
            tokio::task::yield_now().await;
            Ok(Vec::new())
        }
    }
}

fn simple_program() -> miden_processor::Program {
    Assembler::default()
        .assemble_program(
            "program",
            r#"
            begin
                repeat.64
                    swap dup.1 add
                end
            end
            "#,
        )
        .expect("program should compile")
        .unwrap_program()
}

#[tokio::test(flavor = "current_thread")]
async fn async_and_sync_execution_witnesses_prove_equivalently() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(0), Felt::new_unchecked(1)]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let execution_options = ExecutionOptions::default();

    let mut sync_host = DefaultHost::default();
    let sync_witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs.clone(), execution_options)
            .unwrap()
            .execute_for_proving_sync(&program, &mut sync_host)
            .unwrap();
    let sync_outputs = *sync_witness.claim().stack_outputs();
    let sync_proof = Prover::new().prove_full(sync_witness).unwrap();

    let mut async_host = DefaultHost::default();
    let async_witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
            .unwrap()
            .execute_for_proving(&program, &mut async_host)
            .await
            .unwrap();
    let async_outputs = *async_witness.claim().stack_outputs();
    let async_proof = Prover::new().prove_full(async_witness).unwrap();

    assert_eq!(sync_outputs, async_outputs);
    assert!(matches!(sync_proof, ExecutionProof::Complete { precompile: None, .. }));
    assert!(matches!(async_proof, ExecutionProof::Complete { precompile: None, .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn proving_supports_witnesses_from_async_only_host_events() {
    let event_name = EventName::new("test::async::prove");
    let event_id = event_name.to_event_id().as_u64();
    let program = Assembler::default()
        .assemble_program("program", format!("begin push.{event_id} emit drop end"))
        .expect("program should compile")
        .unwrap_program();

    let mut host = YieldingAsyncHost::new();
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_for_proving(&program, &mut host)
    .await
    .expect("async execution should succeed");
    let proof = Prover::new().prove_full(witness).expect("proving should succeed");

    assert_eq!(host.event_calls, 1);
    assert!(matches!(proof, ExecutionProof::Complete { precompile: None, .. }));
}
