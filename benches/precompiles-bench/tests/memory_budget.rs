use miden_vm_precompiles_bench::{PrecompileFixture, PrecompileWorkload, prove_once, verify_once};

/// The default precompile prover memory budget must accept the standard precompile benchmark
/// workload (`PrecompileWorkload::default()`, the fixture proven by `precompiles_bench`).
#[test]
fn default_precompile_prover_memory_budget_accepts_the_standard_benchmark() {
    let fixture = PrecompileFixture::generate(PrecompileWorkload::default());
    let (stack_outputs, proof) = prove_once(&fixture);
    verify_once(&fixture, stack_outputs, &proof);
}
