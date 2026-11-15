//! Generated kernel drift checks anchored to independently authored native source equations.
//! Scalar and actual packed inputs, assertion class/order/degree, metadata and arbitrary
//! polynomial assignments remain separate comparisons. The ignored timing case is manual only.

use miden_air::vm::AIRS;
use miden_constraint_compiler::ir::{Graph, capture_kernel_native_into, capture_native_into};
use miden_stark::air::native::DirectKernel;

const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

#[path = "common/native_registration.rs"]
mod native_registration;

#[test]
fn production_dispatch_preserves_each_authored_relation() {
    for air in AIRS {
        native_registration::assert_native_registration(&air.0, &air, &SEEDS);
    }
}

/// Preserve the production-specific routing guard: these optimized evaluators have structurally
/// distinct roots. Accidentally capturing their Source forwarding method would compare itself.
#[test]
fn authored_and_prepared_execution_are_distinct_captures() {
    for air in AIRS {
        let mut builder = Graph::builder();
        let (authored, _) = capture_native_into(&air.0, &mut builder).unwrap();
        let (generated, _) = capture_kernel_native_into(&air, &mut builder).unwrap();
        assert!(
            authored.base_roots != generated.base_roots
                || authored.ext_roots != generated.ext_roots,
            "{air:?}: authored and generated captures unexpectedly coincide"
        );
    }
}

/// Reusable arithmetic-only comparison; preparation and input generation precede each timer.
#[test]
#[ignore = "manual evaluator timing; use release mode"]
fn evaluator_timing() {
    let iterations = std::env::var("MIDEN_EVAL_ITERATIONS")
        .map(|value| value.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(256);
    assert!(iterations > 0);
    for air in AIRS {
        let source = DirectKernel::new(air.0).unwrap();
        let handwritten = miden_constraint_compiler::testing::time_evaluation(&source, iterations);
        let generated = miden_constraint_compiler::testing::time_evaluation(&air, iterations);
        std::eprintln!(
            "{}: {iterations} evaluations, handwritten scalar={:?} packed={:?}, generated scalar={:?} packed={:?}",
            air.name(),
            handwritten[0],
            handwritten[1],
            generated[0],
            generated[1]
        );
    }
}
