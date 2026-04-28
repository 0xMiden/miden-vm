use crate::{
    Felt, ONE, ZERO,
    errors::OperationError,
    field::{BasedVectorSpace, Field, QuadFelt},
    processor::{Processor, StackInterface},
    tracer::OperationHelperRegisters,
};

#[cfg(test)]
mod tests;

// FRI OPERATIONS
// ================================================================================================

/// Performs FRI layer folding by a factor of 4 for FRI protocol executed in a degree 2
/// extension of the base field. Additionally, performs several computations which simplify
/// FRI verification procedure.
///
/// Specifically:
/// - Folds 4 query values (v0, v1), (v2, v3), (v4, v5), (v6, v7) into a single value (ne0, ne1).
/// - Computes new value of the domain generator power: poe' = poe^4.
/// - Increments layer pointer (cptr) by 8.
/// - Checks that the previous folding was done correctly.
/// - Shifts the stack to the left to move an item from the overflow table to stack position 15.
///
/// Bit-reversal handling:
/// - Query values exist on the stack in bit-reversed order.
/// - p on the stack is a bit-reversed tree index. The instruction internally computes d_seg = p & 3
///   (bit-reversed coset index) for the consistency check and tau factor. f_pos is provided
///   separately on the stack and the AIR constrains f_pos = p >> 2 via p = 4*f_pos + d_seg.
///
/// Stack transition for this operation looks as follows:
///
/// Input:
/// [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, p, poe, pe0, pe1, a0, a1, cptr, ...]
///
/// Output:
/// [t0, t1, s0, s1, df3, df2, df1, df0, poe^2, f_tau, cptr+8, poe^4, f_pos, ne0, ne1, eptr, ...]
///
/// In the above, eptr is moved from the stack overflow table and is expected to be the address
/// of the final FRI layer.
///
/// To keep the degree of the constraints low, a number of intermediate values are used.
/// Specifically, the operation relies on all 6 helper registers, and also uses the first 10
/// elements of the stack at the next state for degree reduction purposes. Thus, once the
/// operation has been executed, the top 10 elements of the stack can be considered to be
/// "garbage".
#[inline(always)]
pub(super) fn op_fri_ext2fold4<P>(
    processor: &mut P,
) -> Result<OperationHelperRegisters, OperationError>
where
    P: Processor,
{
    // --- read all relevant variables from the stack ---------------------
    let query_values = get_query_values(processor);
    // Reorder from bit-reversed to natural for fold4.
    let query_values_reordered = reorder_bitrev4(query_values);
    // p is the bit-reversed tree index; compute f_pos and d_seg from it
    let p = processor.stack().get(9).as_canonical_u64();
    let domain_segment = p & 3;
    let folded_pos = Felt::new_unchecked(p >> 2);
    // the power of the domain generator which can be used to determine current domain value x
    let poe = processor.stack().get(10);
    if poe.is_zero() {
        return Err(OperationError::FriError("domain size was 0".into()));
    }
    // the result of the previous layer folding
    let prev_value = {
        let pe0 = processor.stack().get(11);
        let pe1 = processor.stack().get(12);
        QuadFelt::from_basis_coefficients_fn(|i: usize| [pe0, pe1][i])
    };
    // the verifier challenge for the current layer
    let alpha = {
        let a0 = processor.stack().get(13);
        let a1 = processor.stack().get(14);
        QuadFelt::from_basis_coefficients_fn(|i: usize| [a0, a1][i])
    };
    // the memory address of the current layer
    let layer_ptr = processor.stack().get(15);

    // --- make sure the previous folding was done correctly --------------
    if domain_segment > 3 {
        return Err(OperationError::FriError(format!(
            "domain segment value cannot exceed 3, but was {domain_segment}"
        )));
    }

    // Consistency check: query_values[d_seg] == prev_value.
    // Both query_values and d_seg are bit-reversed, so indexing works out correctly.
    let d_seg = domain_segment as usize;
    if query_values[d_seg] != prev_value {
        return Err(OperationError::FriError(format!(
            "degree-respecting projection is inconsistent at d_seg={d_seg} poe={} fpos={}: expected {} but was {}; all values: [0]={} [1]={} [2]={} [3]={}",
            poe.as_canonical_u64(),
            folded_pos.as_canonical_u64(),
            prev_value,
            query_values[d_seg],
            query_values[0],
            query_values[1],
            query_values[2],
            query_values[3]
        )));
    }

    // --- fold query values ----------------------------------------------
    // Bit-reverse d_seg to get natural coset index for tau factor and domain segment flags.
    let d_seg_rev = bit_reverse_segment(d_seg);
    let f_tau = get_tau_factor(d_seg_rev);
    let x = poe * f_tau;
    let x_inv = x.inverse();

    let (ev, es) = compute_evaluation_points(alpha, x_inv);
    let (folded_value, tmp0, tmp1) = fold4(query_values_reordered, ev, es);

    // --- write the relevant values into the next state of the stack -----
    let tmp0 = tmp0.as_basis_coefficients_slice();
    let tmp1 = tmp1.as_basis_coefficients_slice();
    let ds = get_domain_segment_flags(d_seg_rev);
    let folded_value = folded_value.as_basis_coefficients_slice();

    let poe2 = poe * poe;
    let poe4 = poe2 * poe2;

    processor.stack_mut().decrement_size()?;

    processor.stack_mut().set(0, tmp0[0]);
    processor.stack_mut().set(1, tmp0[1]);
    processor.stack_mut().set(2, tmp1[0]);
    processor.stack_mut().set(3, tmp1[1]);
    processor.stack_mut().set_word(4, &ds.into());
    processor.stack_mut().set(8, poe2);
    processor.stack_mut().set(9, f_tau);
    processor.stack_mut().set(10, layer_ptr + EIGHT);
    processor.stack_mut().set(11, poe4);
    processor.stack_mut().set(12, folded_pos);
    processor.stack_mut().set(13, folded_value[0]);
    processor.stack_mut().set(14, folded_value[1]);

    Ok(OperationHelperRegisters::FriExt2Fold4 { ev, es, x, x_inv })
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

/// Returns 4 query values in the source domain. These values are to be folded into a single
/// value in the folded domain.
///
/// Stack layout: positions 0-7 contain coefficients for 4 QuadFelt elements.
/// QuadFelts are constructed as:
/// - query_values[0] = (v0, v1), query_values[1] = (v2, v3)
/// - query_values[2] = (v4, v5), query_values[3] = (v6, v7)
#[inline(always)]
fn get_query_values<P: Processor>(processor: &mut P) -> [QuadFelt; 4] {
    let [v0, v1, v2, v3]: [Felt; 4] = processor.stack().get_word(0).into();
    let [v4, v5, v6, v7]: [Felt; 4] = processor.stack().get_word(4).into();

    [
        QuadFelt::from_basis_coefficients_fn(|i: usize| [v0, v1][i]),
        QuadFelt::from_basis_coefficients_fn(|i: usize| [v2, v3][i]),
        QuadFelt::from_basis_coefficients_fn(|i: usize| [v4, v5][i]),
        QuadFelt::from_basis_coefficients_fn(|i: usize| [v6, v7][i]),
    ]
}

/// Bit-reverses a 2-bit segment index: 0->0, 1->2, 2->1, 3->3.
#[inline(always)]
fn bit_reverse_segment(domain_segment: usize) -> usize {
    match domain_segment {
        0 => 0,
        1 => 2,
        2 => 1,
        3 => 3,
        _ => panic!("invalid domain segment {domain_segment}"),
    }
}

/// Reorders 4 evals from bit-reversed order to natural order.
#[inline(always)]
fn reorder_bitrev4(values: [QuadFelt; 4]) -> [QuadFelt; 4] {
    [values[0], values[2], values[1], values[3]]
}

// HELPER FUNCTIONS
// ================================================================================================

const EIGHT: Felt = Felt::new_unchecked(8);
const TWO_INV: Felt = Felt::new_unchecked(9223372034707292161);

// Pre-computed powers of 1/tau, where tau is the generator of multiplicative subgroup of size 4
// (i.e., tau is the 4th root of unity). Correctness of these constants is checked in the test at
// the end of this module.
const TAU_INV: Felt = Felt::new_unchecked(18446462594437873665); // tau^{-1}
const TAU2_INV: Felt = Felt::new_unchecked(18446744069414584320); // tau^{-2}
const TAU3_INV: Felt = Felt::new_unchecked(281474976710656); // tau^{-3}

/// Determines tau factor (needed to compute x value) for the specified domain segment.
fn get_tau_factor(domain_segment: usize) -> Felt {
    match domain_segment {
        0 => ONE,
        1 => TAU_INV,
        2 => TAU2_INV,
        3 => TAU3_INV,
        _ => panic!("invalid domain segment {domain_segment}"),
    }
}

/// Determines a set of binary flags needed to describe the specified domain segment.
fn get_domain_segment_flags(domain_segment: usize) -> [Felt; 4] {
    match domain_segment {
        0 => [ONE, ZERO, ZERO, ZERO],
        1 => [ZERO, ONE, ZERO, ZERO],
        2 => [ZERO, ZERO, ONE, ZERO],
        3 => [ZERO, ZERO, ZERO, ONE],
        _ => panic!("invalid domain segment {domain_segment}"),
    }
}

/// Computes 2 evaluation points needed for [fold4] function.
fn compute_evaluation_points(alpha: QuadFelt, x_inv: Felt) -> (QuadFelt, QuadFelt) {
    let ev = alpha * x_inv;
    let es = ev * ev;
    (ev, es)
}

/// Performs folding by a factor of 4. ev and es are values computed based on x and
/// verifier challenge alpha as follows:
/// - ev = alpha / x
/// - es = (alpha / x)^2
fn fold4(values: [QuadFelt; 4], ev: QuadFelt, es: QuadFelt) -> (QuadFelt, QuadFelt, QuadFelt) {
    let tmp0 = fold2(values[0], values[2], ev);
    let tmp1 = fold2(values[1], values[3], ev * TAU_INV);
    let folded_value = fold2(tmp0, tmp1, es);
    (folded_value, tmp0, tmp1)
}

/// Performs folding by a factor of 2. ep is a value computed based on x and verifier challenge
/// alpha.
fn fold2(f_x: QuadFelt, f_neg_x: QuadFelt, ep: QuadFelt) -> QuadFelt {
    (f_x + f_neg_x + ((f_x - f_neg_x) * ep)) * TWO_INV
}
