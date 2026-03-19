use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    DefaultHost, Felt, FutureMaybeSend, Host, ProcessorState, Word,
    advice::AdviceMutation,
    event::{EventError, EventName},
    mast::MastForest,
};
use miden_prover::{AdviceInputs, ProvingOptions, StackInputs, prove, prove_sync};

struct YieldingAsyncHost {
    event_calls: usize,
}

impl YieldingAsyncHost {
    fn new() -> Self {
        Self { event_calls: 0 }
    }
}

impl Host for YieldingAsyncHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }

    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
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
            r#"
            begin
                repeat.64
                    swap dup.1 add
                end
            end
            "#,
        )
        .expect("program should compile")
}

#[tokio::test(flavor = "current_thread")]
async fn prove_async_matches_prove() {
    let program = simple_program();
    let stack_inputs = StackInputs::new(&[Felt::new(0), Felt::new(1)]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let options = ProvingOptions::default();

    let mut sync_host = DefaultHost::default();
    let (sync_outputs, sync_proof) =
        prove_sync(&program, stack_inputs, advice_inputs.clone(), &mut sync_host, options.clone())
            .unwrap();

    let mut async_host = DefaultHost::default();
    let (async_outputs, async_proof) =
        prove(&program, stack_inputs, advice_inputs, &mut async_host, options)
            .await
            .unwrap();

    assert_eq!(sync_outputs, async_outputs);
    assert_eq!(sync_proof.hash_fn(), async_proof.hash_fn());
    assert!(!sync_proof.stark_proof().is_empty());
    assert!(!async_proof.stark_proof().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn prove_async_supports_async_only_host_events() {
    let event_name = EventName::new("test::async::prove");
    let event_id = event_name.to_event_id().as_u64();
    let program = Assembler::default()
        .assemble_program(format!("begin push.{event_id} emit drop end"))
        .expect("program should compile");

    let mut host = YieldingAsyncHost::new();
    let (_outputs, proof) = prove(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ProvingOptions::default(),
    )
    .await
    .expect("async proving should succeed");

    assert_eq!(host.event_calls, 1);
    assert!(!proof.stark_proof().is_empty());
}
