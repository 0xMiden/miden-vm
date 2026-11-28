use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, DefaultHost, Felt, FutureMaybeSend, Host, LoadedMastForest, MastForestLoadError,
    Processor, ProcessorState, WitnessOutput, Word,
    advice::AdviceMutation,
    event::{EventError, EventName},
};
use miden_prover::{ExecutionClaim, ExecutionProof, Prover, StackInputs};
use miden_verifier::Verifier;

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
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
        async { Ok(None) }
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

fn verify_generated_proof(claim: &ExecutionClaim, proof: &ExecutionProof) {
    let outcome = Verifier::new()
        .verify(claim, proof)
        .expect("generated proof should verify against its execution claim");
    assert!(outcome.is_complete());
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
    let request = || Processor::new(&program).with_stack_inputs(stack_inputs);

    let mut sync_host = DefaultHost::default();
    let WitnessOutput { claim: sync_claim, witness, .. } =
        request().record_witness().run_sync(&mut sync_host).unwrap();
    let sync_proof = Prover::new().prove_full(witness).unwrap();

    let mut async_host = DefaultHost::default();
    let WitnessOutput { claim: async_claim, witness, .. } =
        request().record_witness().run(&mut async_host).await.unwrap();
    let async_proof = Prover::new().prove_full(witness).unwrap();

    assert_eq!(sync_claim.stack_outputs(), async_claim.stack_outputs());
    verify_generated_proof(&sync_claim, &sync_proof);
    verify_generated_proof(&async_claim, &async_proof);
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
    let WitnessOutput { claim, witness, .. } = Processor::new(&program)
        .record_witness()
        .run(&mut host)
        .await
        .expect("async execution should succeed");
    let proof = Prover::new().prove_full(witness).expect("proving should succeed");

    assert_eq!(host.event_calls, 1);
    verify_generated_proof(&claim, &proof);
}
