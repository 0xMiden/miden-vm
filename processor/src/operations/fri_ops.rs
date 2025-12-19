use miden_core::{ExtensionOf, FieldElement, ONE, QuadFelt, StarkField, ZERO};

use super::{ExecutionError, Felt, Operation, Process};

// CONSTANTS
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

// FRI OPERATIONS
// ================================================================================================

impl Process {
    // FRI FOLDING OPERATION
    // --------------------------------------------------------------------------------------------
    /// Performs FRI layer folding by a factor of 4 for FRI protocol executed in a degree 2
    /// extension of the base field. Additionally, performs several computations which simplify
    /// FRI verification procedure.
    ///
    /// Specifically:
    /// - Folds 4 query values (v0, v1), (v2, v3), (v4, v5), (v6, v7) into a single value (ne0,
    ///   ne1).
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
    pub(super) fn op_fri_ext2fold4(&mut self) -> Result<(), ExecutionError> {
        // --- read all relevant variables from the stack ---------------------
        let query_values = self.get_query_values();
        let f_pos = self.get_folded_position();
        let d_seg = self.get_domain_segment().as_int();
        let poe = self.get_poe();
        let prev_value = self.get_previous_value();
        let alpha = self.get_alpha();
        let layer_ptr = self.get_layer_ptr();

        // --- make sure the previous folding was done correctly --------------
        if d_seg > 3 {
            return Err(ExecutionError::InvalidFriDomainSegment(d_seg));
        }

        let d_seg = d_seg as usize;
        if query_values[d_seg] != prev_value {
            return Err(ExecutionError::InvalidFriLayerFolding(prev_value, query_values[d_seg]));
        }

        // --- fold query values ----------------------------------------------
        // compute x corresponding to the query position
        let f_tau = get_tau_factor(d_seg);
        let x = poe * f_tau * DOMAIN_OFFSET;
        let x_inv = x.inv();

        let (ev, es) = compute_evaluation_points(alpha, x_inv);
        let (folded_value, tmp0, tmp1) = fold4(query_values, ev, es);

        // --- write the relevant values into the next state of the stack -----
        let tmp0 = tmp0.to_base_elements();
        let tmp1 = tmp1.to_base_elements();
        let ds = get_domain_segment_flags(d_seg);
        let folded_value = folded_value.to_base_elements();

        let poe2 = poe.square();
        let poe4 = poe2.square();

        self.stack.set(0, tmp0[1]);
        self.stack.set(1, tmp0[0]);
        self.stack.set(2, tmp1[1]);
        self.stack.set(3, tmp1[0]);
        self.stack.set(4, ds[3]);
        self.stack.set(5, ds[2]);
        self.stack.set(6, ds[1]);
        self.stack.set(7, ds[0]);
        self.stack.set(8, poe2);
        self.stack.set(9, f_tau);
        self.stack.set(10, layer_ptr + EIGHT);
        self.stack.set(11, poe4);
        self.stack.set(12, f_pos);
        self.stack.set(13, folded_value[1]);
        self.stack.set(14, folded_value[0]);

        self.set_helper_registers(ev, es, x, x_inv);

        self.stack.shift_left(16);
        Ok(())
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns 4 query values in the source domain. These values are to be folded into a single
    /// value in the folded domain.
    fn get_query_values(&self) -> [QuadFelt; 4] {
        let v7 = self.stack.get(0);
        let v6 = self.stack.get(1);
        let v5 = self.stack.get(2);
        let v4 = self.stack.get(3);
        let v3 = self.stack.get(4);
        let v2 = self.stack.get(5);
        let v1 = self.stack.get(6);
        let v0 = self.stack.get(7);

        [
            QuadFelt::new(v0, v1),
            QuadFelt::new(v2, v3),
            QuadFelt::new(v4, v5),
            QuadFelt::new(v6, v7),
        ]
    }

    /// Returns queried position in the folded domain.
    fn get_folded_position(&self) -> Felt {
        self.stack.get(8)
    }

    /// Returns segment identifier of the position in the source domain.
    ///
    /// This can be computed as pos / n, where pos is the position in the source domain and n is
    /// the size of the folded domain. Since source domain size is always 4x bigger than the
    /// folded domain size, possible set of values for domain segment are: 0, 1, 2, 3.
    fn get_domain_segment(&self) -> Felt {
        self.stack.get(9)
    }

    /// Returns power of domain generator which can be used to determine current domain value x.
    fn get_poe(&self) -> Felt {
        self.stack.get(10)
    }

    /// Returns the result of the previous layer folding.
    fn get_previous_value(&self) -> QuadFelt {
        let pe1 = self.stack.get(11);
        let pe0 = self.stack.get(12);
        QuadFelt::new(pe0, pe1)
    }

    /// Returns verifier challenge for the current layer.
    fn get_alpha(&self) -> QuadFelt {
        let a1 = self.stack.get(13);
        let a0 = self.stack.get(14);
        QuadFelt::new(a0, a1)
    }

    /// Returns memory address of the current layer.
    fn get_layer_ptr(&self) -> Felt {
        self.stack.get(15)
    }

    /// Populates helper registers with intermediate values used in the folding procedure.
    fn set_helper_registers(&mut self, ev: QuadFelt, es: QuadFelt, x: Felt, x_inv: Felt) {
        let ev_arr = [ev];
        let ev_felts = QuadFelt::slice_as_base_elements(&ev_arr);

        let es_arr = [es];
        let es_felts = QuadFelt::slice_as_base_elements(&es_arr);

        let values = [ev_felts[0], ev_felts[1], es_felts[0], es_felts[1], x, x_inv];
        self.decoder.set_user_op_helpers(Operation::FriE2F4, &values);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

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
    let ev = alpha.mul_base(x_inv);
    let es = ev.square();
    (ev, es)
}

/// Performs folding by a factor of 4. ev and es are values computed based on x and
/// verifier challenge alpha as follows:
/// - ev = alpha / x
/// - es = (alpha / x)^2
fn fold4(values: [QuadFelt; 4], ev: QuadFelt, es: QuadFelt) -> (QuadFelt, QuadFelt, QuadFelt) {
    let tmp0 = fold2(values[0], values[2], ev);
    let tmp1 = fold2(values[1], values[3], ev.mul_base(TAU_INV));
    let folded_value = fold2(tmp0, tmp1, es);
    (folded_value, tmp0, tmp1)
}

/// Performs folding by a factor of 2. ep is a value computed based on x and verifier challenge
/// alpha.
fn fold2(f_x: QuadFelt, f_neg_x: QuadFelt, ep: QuadFelt) -> QuadFelt {
    (f_x + f_neg_x + ((f_x - f_neg_x) * ep)).mul_base(TWO_INV)
}
