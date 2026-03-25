//! WASM prover tests. Run with: `wasm-pack test --chrome --headless --release`

use std::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::proof::HashFunction;
use miden_processor::{DefaultHost, StackInputs, advice::AdviceInputs};
use miden_prover::{ProvingOptions, prove};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const FIB_SOURCE: &str = "begin repeat.1000 swap dup.1 add end end";

fn setup() -> (miden_core::program::Program, StackInputs, AdviceInputs, DefaultHost) {
    let program = Assembler::default().assemble_program(FIB_SOURCE).unwrap();
    let stack_inputs =
        StackInputs::new(&[miden_core::Felt::new(0), miden_core::Felt::new(1)]).unwrap();
    let host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    (program, stack_inputs, AdviceInputs::default(), host)
}

#[wasm_bindgen_test]
async fn prove_blake3() {
    let (program, stack_inputs, advice_inputs, mut host) = setup();
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);
    prove(&program, stack_inputs, advice_inputs, &mut host, options)
        .await
        .expect("Blake3 prove failed");
}

#[wasm_bindgen_test]
async fn prove_rpo() {
    let (program, stack_inputs, advice_inputs, mut host) = setup();
    let options = ProvingOptions::with_96_bit_security(HashFunction::Rpo256);
    prove(&program, stack_inputs, advice_inputs, &mut host, options)
        .await
        .expect("RPO prove failed");
}
