use miden_assembly::Assembler;
use miden_processor::{DefaultHost, Felt};
use miden_prover::{AdviceInputs, ProvingOptions, StackInputs, prove, prove_async};

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
        prove(&program, stack_inputs, advice_inputs.clone(), &mut sync_host, options.clone())
            .unwrap();

    let mut async_host = DefaultHost::default();
    let (async_outputs, async_proof) =
        prove_async(&program, stack_inputs, advice_inputs, &mut async_host, options)
            .await
            .unwrap();

    assert_eq!(sync_outputs, async_outputs);
    assert_eq!(sync_proof.hash_fn(), async_proof.hash_fn());
    assert!(!sync_proof.stark_proof().is_empty());
    assert!(!async_proof.stark_proof().is_empty());
}
