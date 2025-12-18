use alloc::vec::Vec;

use miden_core::{ExtensionOf, Felt, FieldElement, QuadFelt, StarkField};
use proptest::prelude::*;
use winter_prover::math::{fft, get_power_series_with_offset};
use winter_utils::transpose_slice;

use super::{
    super::stack_ops::op_push, DOMAIN_OFFSET, EIGHT, TAU_INV, TAU2_INV, TAU3_INV, TWO_INV,
    compute_evaluation_points, fold4 as fri_fold4, get_domain_segment_flags, get_tau_factor,
    op_fri_ext2fold4,
};
use crate::fast::{FastProcessor, NoopTracer, step::NeverStopper};

// FRI FOLDING TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    /// Tests FRI layer folding by a factor of 4.
    ///
    /// This test generates a random polynomial, evaluates it over a domain, and then folds
    /// the evaluations using both the Winterfell FRI folding procedure and our `fold4` function,
    /// verifying that they produce the same results.
    #[test]
    fn test_fold4(
        // Random coefficients for degree 7 polynomial (8 QuadFelt coefficients = 16 base field elements)
        p0_0 in any::<u64>(),
        p0_1 in any::<u64>(),
        p1_0 in any::<u64>(),
        p1_1 in any::<u64>(),
        p2_0 in any::<u64>(),
        p2_1 in any::<u64>(),
        p3_0 in any::<u64>(),
        p3_1 in any::<u64>(),
        p4_0 in any::<u64>(),
        p4_1 in any::<u64>(),
        p5_0 in any::<u64>(),
        p5_1 in any::<u64>(),
        p6_0 in any::<u64>(),
        p6_1 in any::<u64>(),
        p7_0 in any::<u64>(),
        p7_1 in any::<u64>(),
        // Random alpha challenge
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // Position within the domain (0-7, since we have 8 positions in the folded domain)
        pos in 0usize..8,
    ) {
        let blowup = 4_usize;

        // Generate the alpha challenge
        let alpha = QuadFelt::new(Felt::new(alpha_0), Felt::new(alpha_1));

        // Generate degree 7 polynomial f(x) from the random coefficients
        let poly: Vec<QuadFelt> = vec![
            QuadFelt::new(Felt::new(p0_0), Felt::new(p0_1)),
            QuadFelt::new(Felt::new(p1_0), Felt::new(p1_1)),
            QuadFelt::new(Felt::new(p2_0), Felt::new(p2_1)),
            QuadFelt::new(Felt::new(p3_0), Felt::new(p3_1)),
            QuadFelt::new(Felt::new(p4_0), Felt::new(p4_1)),
            QuadFelt::new(Felt::new(p5_0), Felt::new(p5_1)),
            QuadFelt::new(Felt::new(p6_0), Felt::new(p6_1)),
            QuadFelt::new(Felt::new(p7_0), Felt::new(p7_1)),
        ];

        // Evaluate the polynomial over domain of 32 elements
        let offset = Felt::GENERATOR;
        let twiddles = fft::get_twiddles(poly.len());
        let evaluations = fft::evaluate_poly_with_offset(&poly, &twiddles, offset, blowup);

        // Fold the evaluations using FRI folding procedure from Winterfell
        let transposed_evaluations = transpose_slice::<QuadFelt, 4>(&evaluations);
        let folded_evaluations =
            winter_fri::folding::apply_drp(&transposed_evaluations, offset, alpha);

        // Build the evaluation domain of 32 elements
        let n = poly.len() * blowup;
        let g = Felt::get_root_of_unity(n.trailing_zeros());
        let domain = get_power_series_with_offset(g, offset, n);

        // Fold evaluations at a single point using fold4 procedure
        let x = domain[pos];
        let ev = alpha.mul_base(x.inv());
        let (result, ..) = fri_fold4(transposed_evaluations[pos], ev, ev.square());

        // Make sure the results of fold4 are the same as results from Winterfell
        prop_assert_eq!(folded_evaluations[pos], result);
    }
}

/// Tests that the pre-computed FRI constants are correct.
#[test]
fn test_constants() {
    let tau = Felt::get_root_of_unity(2);

    assert_eq!(TAU_INV, tau.inv());
    assert_eq!(TAU2_INV, tau.square().inv());
    assert_eq!(TAU3_INV, tau.cube().inv());

    assert_eq!(Felt::new(2).inv(), TWO_INV);
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
        // Power of domain generator
        poe in any::<u64>(),
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
            QuadFelt::new(Felt::new(v0_0), Felt::new(v0_1)),
            QuadFelt::new(Felt::new(v1_0), Felt::new(v1_1)),
            QuadFelt::new(Felt::new(v2_0), Felt::new(v2_1)),
            QuadFelt::new(Felt::new(v3_0), Felt::new(v3_1)),
        ];

        // The previous value must match query_values[d_seg] for the operation to succeed
        let prev_value = query_values[d_seg as usize];
        let prev_value_base = prev_value.to_base_elements();

        let alpha = QuadFelt::new(Felt::new(alpha_0), Felt::new(alpha_1));
        let poe = Felt::new(poe);
        let f_pos = Felt::new(f_pos);
        let d_seg_felt = Felt::new(d_seg);
        let layer_ptr = Felt::new(layer_ptr);
        let end_ptr = Felt::new(end_ptr);

        // Build the stack inputs (only 16 elements for initial stack)
        // The operation expects the following layout after pushing v7 (17 elements):
        // [v7, v6, v5, v4, v3, v2, v1, v0, f_pos, d_seg, poe, pe1, pe0, a1, a0, cptr, end_ptr]
        //  ^0   1   2   3   4   5   6   7    8      9    10   11   12  13  14   15     overflow
        //
        // FastProcessor::new expects inputs in bottom-first order (index 0 = position 15).
        // We build the initial 16-element stack, then push v7 on top.
        let stack_inputs = [
            end_ptr,                              // position 15 (will be pushed to overflow)
            layer_ptr,                            // position 14 -> 15 after push
            Felt::new(alpha_0),                   // position 13 -> 14 (a0)
            Felt::new(alpha_1),                   // position 12 -> 13 (a1)
            prev_value_base[0],                   // position 11 -> 12 (pe0)
            prev_value_base[1],                   // position 10 -> 11 (pe1)
            poe,                                  // position 9 -> 10
            d_seg_felt,                           // position 8 -> 9
            f_pos,                                // position 7 -> 8
            query_values[0].to_base_elements()[0], // position 6 -> 7 (v0)
            query_values[0].to_base_elements()[1], // position 5 -> 6 (v1)
            query_values[1].to_base_elements()[0], // position 4 -> 5 (v2)
            query_values[1].to_base_elements()[1], // position 3 -> 4 (v3)
            query_values[2].to_base_elements()[0], // position 2 -> 3 (v4)
            query_values[2].to_base_elements()[1], // position 1 -> 2 (v5)
            query_values[3].to_base_elements()[0], // position 0 -> 1 (v6)
        ];

        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Push v7 to the top of the stack
        // This shifts everything down by one position, moving end_ptr to overflow
        let v7 = query_values[3].to_base_elements()[1];
        op_push(&mut processor, v7, &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Execute the operation
        let result = op_fri_ext2fold4(&mut processor, &mut tracer);
        prop_assert!(result.is_ok(), "op_fri_ext2fold4 failed: {:?}", result.err());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Compute expected values
        let f_tau = get_tau_factor(d_seg as usize);
        let x = poe * f_tau * DOMAIN_OFFSET;
        let x_inv = x.inv();

        let (ev, es) = compute_evaluation_points(alpha, x_inv);
        let (folded_value, tmp0, tmp1) = fri_fold4(query_values, ev, es);

        let tmp0_base = tmp0.to_base_elements();
        let tmp1_base = tmp1.to_base_elements();
        let ds = get_domain_segment_flags(d_seg as usize);
        let folded_value_base = folded_value.to_base_elements();
        let poe2 = poe.square();
        let poe4 = poe2.square();

        // Check the stack state
        let stack = processor.stack_top();

        // Check temp values (tmp0, tmp1)
        prop_assert_eq!(stack[15], tmp0_base[1], "tmp0[1] at position 0");
        prop_assert_eq!(stack[14], tmp0_base[0], "tmp0[0] at position 1");
        prop_assert_eq!(stack[13], tmp1_base[1], "tmp1[1] at position 2");
        prop_assert_eq!(stack[12], tmp1_base[0], "tmp1[0] at position 3");

        // Check domain segment flags
        prop_assert_eq!(stack[11], ds[3], "ds[3] at position 4");
        prop_assert_eq!(stack[10], ds[2], "ds[2] at position 5");
        prop_assert_eq!(stack[9], ds[1], "ds[1] at position 6");
        prop_assert_eq!(stack[8], ds[0], "ds[0] at position 7");

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
