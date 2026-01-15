use miden_core::{
    Felt,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt, TwoAdicField},
};
use proptest::prelude::*;

use super::{
    super::stack_ops::op_push, DOMAIN_OFFSET, EIGHT, TAU_INV, TAU2_INV, TAU3_INV, TWO_INV,
    compute_evaluation_points, fold4 as fri_fold4, get_domain_segment_flags, get_tau_factor,
    op_fri_ext2fold4,
};
use crate::fast::{FastProcessor, NoopTracer, step::NeverStopper};

// FRI FOLDING TESTS
// --------------------------------------------------------------------------------------------

// NOTE: The `test_fold4` proptest that compared our fold4 implementation against Winterfell's
// FRI folding has been removed as we've migrated from Winterfell to Plonky3.
// The test_op_fri_ext2fold4 proptest below still validates the fold4 implementation.

/// Tests that the pre-computed FRI constants are correct.
#[test]
fn test_constants() {
    let tau = Felt::two_adic_generator(2);

    assert_eq!(TAU_INV, tau.inverse());
    assert_eq!(TAU2_INV, tau.square().inverse());
    assert_eq!(TAU3_INV, tau.cube().inverse());

    assert_eq!(Felt::new(2).inverse(), TWO_INV);
}

// FRI OPERATION TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    /// Tests the FRI ext2fold4 operation.
    ///
    /// This test sets up a stack with random values and verifies that the `op_fri_ext2fold4`
    /// operation correctly folds 4 query values into a single value.
    #[test]
    fn test_op_fri_ext2fold4(
        // Query values: 4 QuadFelt = 8 base field elements
        v0_0 in any::<u64>(),
        v0_1 in any::<u64>(),
        v1_0 in any::<u64>(),
        v1_1 in any::<u64>(),
        v2_0 in any::<u64>(),
        v2_1 in any::<u64>(),
        v3_0 in any::<u64>(),
        v3_1 in any::<u64>(),
        // Folded position
        f_pos in any::<u64>(),
        // Domain segment (0-3)
        d_seg in 0u64..4,
        // Power of domain generator (must be non-zero to avoid InvalidFriDomainGenerator)
        poe in 1u64..=u64::MAX,
        // Alpha challenge
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // Layer pointer
        layer_ptr in any::<u64>(),
        // End pointer (will be moved from overflow table)
        end_ptr in any::<u64>(),
    ) {
        // Query values
        let query_values = [
            QuadFelt::new([Felt::new(v0_0), Felt::new(v0_1)]),
            QuadFelt::new([Felt::new(v1_0), Felt::new(v1_1)]),
            QuadFelt::new([Felt::new(v2_0), Felt::new(v2_1)]),
            QuadFelt::new([Felt::new(v3_0), Felt::new(v3_1)]),
        ];

        // The previous value must match query_values[d_seg] for the operation to succeed
        let prev_value = query_values[d_seg as usize];
        let prev_value_base = prev_value.as_basis_coefficients_slice();

        let alpha = QuadFelt::new([Felt::new(alpha_0), Felt::new(alpha_1)]);
        let poe = Felt::new(poe);
        let f_pos = Felt::new(f_pos);
        let d_seg_felt = Felt::new(d_seg);
        let layer_ptr = Felt::new(layer_ptr);
        let end_ptr = Felt::new(end_ptr);

        // Build the stack inputs (only 16 elements for initial stack)
        // The operation expects the following layout after pushing v0 (17 elements):
        // [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, d_seg, poe, pe1, pe0, a1, a0, cptr, end_ptr]
        //  ^0   1   2   3   4   5   6   7    8      9    10   11   12  13  14   15     overflow
        let stack_inputs = [
            query_values[0].as_basis_coefficients_slice()[1], // position 0 -> 1 (v1) after push
            query_values[1].as_basis_coefficients_slice()[0], // position 1 -> 2 (v2)
            query_values[1].as_basis_coefficients_slice()[1], // position 2 -> 3 (v3)
            query_values[2].as_basis_coefficients_slice()[0], // position 3 -> 4 (v4)
            query_values[2].as_basis_coefficients_slice()[1], // position 4 -> 5 (v5)
            query_values[3].as_basis_coefficients_slice()[0], // position 5 -> 6 (v6)
            query_values[3].as_basis_coefficients_slice()[1], // position 6 -> 7 (v7)
            f_pos,                                // position 7 -> 8
            d_seg_felt,                           // position 8 -> 9
            poe,                                  // position 9 -> 10
            prev_value_base[1],                   // position 10 -> 11 (pe1)
            prev_value_base[0],                   // position 11 -> 12 (pe0)
            Felt::new(alpha_1),                   // position 12 -> 13 (a1)
            Felt::new(alpha_0),                   // position 13 -> 14 (a0)
            layer_ptr,                            // position 14 -> 15 after push (cptr)
            end_ptr,                              // position 15 (will be pushed to overflow)
        ];

        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Push v0 to the top of the stack
        // This shifts everything down by one position, moving end_ptr to overflow
        let v0 = query_values[0].as_basis_coefficients_slice()[0];
        op_push(&mut processor, v0, &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Execute the operation
        let result = op_fri_ext2fold4(&mut processor, &mut tracer);
        prop_assert!(result.is_ok(), "op_fri_ext2fold4 failed: {:?}", result.err());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Compute expected values
        let f_tau = get_tau_factor(d_seg as usize);
        let x = poe * f_tau * DOMAIN_OFFSET;
        let x_inv = x.inverse();

        let (ev, es) = compute_evaluation_points(alpha, x_inv);
        let (folded_value, tmp0, tmp1) = fri_fold4(query_values, ev, es);

        let tmp0_base = tmp0.as_basis_coefficients_slice();
        let tmp1_base = tmp1.as_basis_coefficients_slice();
        let ds = get_domain_segment_flags(d_seg as usize);
        let folded_value_base = folded_value.as_basis_coefficients_slice();
        let poe2 = poe.square();
        let poe4 = poe2.square();

        // Check the stack state
        let stack = processor.stack_top();

        // Check temp values (tmp0, tmp1)
        prop_assert_eq!(stack[15], tmp0_base[1], "tmp0[1] at position 0");
        prop_assert_eq!(stack[14], tmp0_base[0], "tmp0[0] at position 1");
        prop_assert_eq!(stack[13], tmp1_base[1], "tmp1[1] at position 2");
        prop_assert_eq!(stack[12], tmp1_base[0], "tmp1[0] at position 3");

        // Check domain segment flags: ds[0] at position 4, ds[3] at position 7
        prop_assert_eq!(stack[11], ds[0], "ds[0] at position 4");
        prop_assert_eq!(stack[10], ds[1], "ds[1] at position 5");
        prop_assert_eq!(stack[9], ds[2], "ds[2] at position 6");
        prop_assert_eq!(stack[8], ds[3], "ds[3] at position 7");

        // Check poe^2, f_tau, layer_ptr+8, poe^4, f_pos
        prop_assert_eq!(stack[7], poe2, "poe^2 at position 8");
        prop_assert_eq!(stack[6], f_tau, "f_tau at position 9");
        prop_assert_eq!(stack[5], layer_ptr + EIGHT, "layer_ptr+8 at position 10");
        prop_assert_eq!(stack[4], poe4, "poe^4 at position 11");
        prop_assert_eq!(stack[3], f_pos, "f_pos at position 12");

        // Check folded value
        prop_assert_eq!(stack[2], folded_value_base[1], "folded_value[1] at position 13");
        prop_assert_eq!(stack[1], folded_value_base[0], "folded_value[0] at position 14");

        // Check end ptr (should be moved from overflow table)
        prop_assert_eq!(stack[0], end_ptr, "end_ptr at position 15");
    }
}
