use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{
    Felt, ONE, ZERO,
    field::{BasedVectorSpace, Field, PrimeField64, QuadFelt},
};

use crate::{
    ExecutionError,
    fast::Tracer,
    processor::{OperationHelperRegisters, Processor, StackInterface},
};

#[cfg(test)]
mod tests;

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
/// Stack transition for this operation looks as follows:
///
/// Input:
/// [v7, v6, v5, v4, v3, v2, v1, v0, f_pos, d_seg, poe, pe1, pe0, a1, a0, cptr, ...]
///
/// Output:
/// [t1, t0, s1, s0, df3, df2, df1, df0, poe^2, f_tau, cptr+2, poe^4, f_pos, ne1, ne0, eptr,
/// ...]
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
pub(super) fn op_fri_ext2fold4<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    // --- read all relevant variables from the stack ---------------------
    let query_values = get_query_values(processor);
    let folded_pos = processor.stack().get(8);
    // the segment identifier of the position in the source domain
    let domain_segment = processor.stack().get(9).as_canonical_u64();
    // the power of the domain generator which can be used to determine current domain value x
    let poe = processor.stack().get(10);
    if poe.is_zero() {
        return Err(ExecutionError::InvalidFriDomainGenerator);
    }
    // the result of the previous layer folding
    let prev_value = {
        let pe1 = processor.stack().get(11);
        let pe0 = processor.stack().get(12);
        QuadFelt::new_complex(pe0, pe1)
    };
    // the verifier challenge for the current layer
    let alpha = {
        let a1 = processor.stack().get(13);
        let a0 = processor.stack().get(14);
        QuadFelt::new_complex(a0, a1)
    };
    // the memory address of the current layer
    let layer_ptr = processor.stack().get(15);

    // --- make sure the previous folding was done correctly --------------
    if domain_segment > 3 {
        return Err(ExecutionError::InvalidFriDomainSegment(domain_segment));
    }

    let d_seg = domain_segment as usize;
    if query_values[d_seg] != prev_value {
        return Err(ExecutionError::InvalidFriLayerFolding(prev_value, query_values[d_seg]));
    }

    // --- fold query values ----------------------------------------------
    let f_tau = get_tau_factor(d_seg);
    let x = poe * f_tau * DOMAIN_OFFSET;
    let x_inv = x.inverse();

    let (ev, es) = compute_evaluation_points(alpha, x_inv);
    let (folded_value, tmp0, tmp1) = fold4(query_values, ev, es);

    // --- write the relevant values into the next state of the stack -----
    let tmp0 = tmp0.as_basis_coefficients_slice();
    let tmp1 = tmp1.as_basis_coefficients_slice();
    let ds = get_domain_segment_flags(d_seg);
    let folded_value = folded_value.as_basis_coefficients_slice();

    let poe2 = poe * poe;
    let poe4 = poe2 * poe2;

    processor.stack().decrement_size(tracer);

    processor.stack().set(0, tmp0[1]);
    processor.stack().set(1, tmp0[0]);
    processor.stack().set(2, tmp1[1]);
    processor.stack().set(3, tmp1[0]);
    processor.stack().set_word(4, &ds.into());
    processor.stack().set(8, poe2);
    processor.stack().set(9, f_tau);
    processor.stack().set(10, layer_ptr + EIGHT);
    processor.stack().set(11, poe4);
    processor.stack().set(12, folded_pos);
    processor.stack().set(13, folded_value[1]);
    processor.stack().set(14, folded_value[0]);

    Ok(P::HelperRegisters::op_fri_ext2fold4_registers(ev, es, x, x_inv))
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

/// Returns 4 query values in the source domain. These values are to be folded into a single
/// value in the folded domain.
#[inline(always)]
fn get_query_values<P: Processor>(processor: &mut P) -> [QuadFelt; 4] {
    let [v4, v5, v6, v7] = processor.stack().get_word(0).into();
    let [v0, v1, v2, v3] = processor.stack().get_word(4).into();

    [
        QuadFelt::new_complex(v0, v1),
        QuadFelt::new_complex(v2, v3),
        QuadFelt::new_complex(v4, v5),
        QuadFelt::new_complex(v6, v7),
    ]
}

// HELPER FUNCTIONS
// ================================================================================================

const EIGHT: Felt = Felt::new(8);
const TWO_INV: Felt = Felt::new(9223372034707292161);

const DOMAIN_OFFSET: Felt = Felt::GENERATOR;

// Pre-computed powers of 1/tau, where tau is the generator of multiplicative subgroup of size 4
// (i.e., tau is the 4th root of unity). Correctness of these constants is checked in the test at
// the end of this module.
const TAU_INV: Felt = Felt::new(18446462594437873665); // tau^{-1}
const TAU2_INV: Felt = Felt::new(18446744069414584320); // tau^{-2}
const TAU3_INV: Felt = Felt::new(281474976710656); // tau^{-3}

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
