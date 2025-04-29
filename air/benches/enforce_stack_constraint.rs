use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_air::{
    Felt, FieldElement,
    stack::{
        NUM_GENERAL_CONSTRAINTS, enforce_constraints, field_ops, io_ops,
        op_flags::generate_evaluation_frame, overflow, stack_manipulation, system_ops, u32_ops,
    },
    trace::STACK_TRACE_OFFSET,
};
use vm_core::{Operation, PrimeCharacteristicRing, ZERO};

fn enforce_stack_constraint(c: &mut Criterion) {
    let mut group = c.benchmark_group("enforce_stack_constraint");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("enforce_stack", |bench| {
        const NUM_CONSTRAINTS: usize = overflow::NUM_CONSTRAINTS
            + system_ops::NUM_CONSTRAINTS
            + u32_ops::NUM_CONSTRAINTS
            + field_ops::NUM_CONSTRAINTS
            + stack_manipulation::NUM_CONSTRAINTS
            + io_ops::NUM_CONSTRAINTS
            + NUM_GENERAL_CONSTRAINTS;

        let mut frame = generate_evaluation_frame(Operation::Inv.op_code() as usize);
        frame.current_mut()[STACK_TRACE_OFFSET] = Felt::from_u64(89u64);
        frame.next_mut()[STACK_TRACE_OFFSET] = Felt::from_u64(89u64).inv();

        let mut result = [ZERO; NUM_CONSTRAINTS];

        let frame = generate_evaluation_frame(36);
        bench.iter(|| {
            enforce_constraints(&frame, &mut result);
        });
    });

    group.finish();
}

criterion_group!(enforce_stack_group, enforce_stack_constraint);
criterion_main!(enforce_stack_group);
