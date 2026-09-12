#[path = "../../../crates/precompiles/benches/precompiles_bench/support.rs"]
#[allow(
    unused_imports,
    reason = "shared with the precompiles_bench binary, which uses the full re-export surface"
)]
mod support;

use miden_vm::HashFunction;
use support::{PrecompileFixture, PrecompileWorkload, prove_once_with_hash, verify_once};

/// The default precompile prover memory budget must accept the standard precompile benchmark
/// workload (`PrecompileWorkload::default()`, the fixture proven by `precompiles_bench`).
#[test]
fn default_precompile_prover_memory_budget_accepts_the_standard_benchmark() {
    let fixture = PrecompileFixture::generate(PrecompileWorkload::default());
    let (stack_outputs, proof) = prove_once_with_hash(&fixture, HashFunction::Blake3_256);
    verify_once(&fixture, stack_outputs, proof);
}
