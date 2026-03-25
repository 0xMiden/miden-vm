//! WASM prover integration tests.
//!
//! These tests verify that the Miden VM prover works correctly in a WASM environment.
//! Run with: `wasm-pack test --chrome --headless` from this crate's directory.

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn perf_now() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

/// Minimal prove test — a tiny program (push.1 push.2 add) to verify the prover
/// doesn't panic in WASM. This generates a small trace.
#[wasm_bindgen_test]
async fn prove_minimal_program() {
    use std::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::proof::HashFunction;
    use miden_processor::{DefaultHost, StackInputs, advice::AdviceInputs};
    use miden_prover::{ProvingOptions, prove};

    let source = "begin push.1 push.2 add drop end";

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    let t0 = perf_now();
    web_sys::console::log_1(&"[wasm-prove] Starting prove (minimal program)...".into());

    let result = prove(&program, stack_inputs, advice_inputs, &mut host, options).await;

    let t1 = perf_now();
    web_sys::console::log_1(
        &format!("[wasm-prove] prove completed in {:.0}ms", t1 - t0).into(),
    );

    let (stack_outputs, _proof) = result.expect("prove() panicked or failed in WASM");

    web_sys::console::log_1(
        &format!("[wasm-prove] Stack output: {:?}", stack_outputs).into(),
    );
}

/// Fibonacci prove test — matches the native integration test (1000 iterations).
/// This generates a larger trace (~2048+ rows) and exercises the full FRI pipeline
/// including multiple rounds of grinding.
#[wasm_bindgen_test]
async fn prove_fibonacci_blake3() {
    use std::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::proof::HashFunction;
    use miden_processor::{DefaultHost, StackInputs, advice::AdviceInputs};
    use miden_prover::{ProvingOptions, prove};

    let source = "
        begin
            repeat.1000
                swap dup.1 add
            end
        end
    ";

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::new(&[miden_core::Felt::new(0), miden_core::Felt::new(1)]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    let t0 = perf_now();
    web_sys::console::log_1(&"[wasm-prove] Starting prove (fibonacci, Blake3)...".into());

    let result = prove(&program, stack_inputs, advice_inputs, &mut host, options).await;

    let t1 = perf_now();
    web_sys::console::log_1(
        &format!("[wasm-prove] prove completed in {:.0}ms", t1 - t0).into(),
    );

    let (_stack_outputs, _proof) = result.expect("prove() panicked or failed in WASM (fibonacci)");
}

/// RPO prove test — uses the algebraic hash (DuplexChallenger) path which has the
/// SIMD-optimized grinding code.
#[wasm_bindgen_test]
async fn prove_fibonacci_rpo() {
    use std::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::proof::HashFunction;
    use miden_processor::{DefaultHost, StackInputs, advice::AdviceInputs};
    use miden_prover::{ProvingOptions, prove};

    let source = "
        begin
            repeat.1000
                swap dup.1 add
            end
        end
    ";

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::new(&[miden_core::Felt::new(0), miden_core::Felt::new(1)]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    let options = ProvingOptions::with_96_bit_security(HashFunction::Rpo256);

    let t0 = perf_now();
    web_sys::console::log_1(&"[wasm-prove] Starting prove (fibonacci, RPO)...".into());

    let result = prove(&program, stack_inputs, advice_inputs, &mut host, options).await;

    let t1 = perf_now();
    web_sys::console::log_1(
        &format!("[wasm-prove] prove completed in {:.0}ms", t1 - t0).into(),
    );

    let (_stack_outputs, _proof) =
        result.expect("prove() panicked or failed in WASM (fibonacci RPO)");
}
