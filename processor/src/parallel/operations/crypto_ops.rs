use core::array;

use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, FieldElement, QuadFelt, ZERO};

use super::CoreTraceFragmentGenerator;
use crate::processor::Processor;

impl CoreTraceFragmentGenerator {
    /// Performs a hash permutation operation.
    /// Applies Rescue Prime Optimized permutation to the top 12 elements of the stack.
    pub(crate) fn op_hperm(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let (addr, computed_hash) = self.state.hasher.replay_permute();

        // Put the result back on the stack (in reverse order)
        for (i, &value) in computed_hash.iter().rev().enumerate() {
            self.stack_write(i, value);
        }

        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    /// Verifies a Merkle path.
    ///
    /// In this implementation, we don't actually verify the path.
    pub(crate) fn op_mpverify(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let root = self.stack_get_word(6);

        // Replay the Merkle path retrieval from the advice provider
        let (addr, computed_root) = self.state.hasher.replay_build_merkle_root();

        debug_assert_eq!(root, computed_root, "Merkle root mismatch");

        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    /// Updates the Merkle root.
    ///
    /// In this implementation, we replay the recorded operations from the advice provider.
    pub(crate) fn op_mrupdate(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let _old_node = self.stack_get_word(0);
        let old_root = self.stack_get_word(6);

        // Replay the Merkle root update operation from the hasher
        let (addr, _computed_old_root, computed_new_root) =
            self.state.hasher.replay_update_merkle_root();

        debug_assert_eq!(old_root, _computed_old_root, "Old root mismatch");

        // Replace the old node value with computed new root; everything else remains the same.
        self.stack_write_word(0, &computed_new_root);

        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    /// Evaluates a polynomial using Horner's method (base field).
    ///
    /// In this implementation, we replay the recorded operations and compute the result.
    pub(crate) fn op_horner_eval_base(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        // Constants from the original implementation
        const ALPHA_ADDR_INDEX: usize = 13;
        const ACC_HIGH_INDEX: usize = 14;
        const ACC_LOW_INDEX: usize = 15;

        // Read the coefficients from the stack (top 8 elements)
        let coef: [Felt; 8] = array::from_fn(|i| self.stack_get(i));

        // Read the evaluation point alpha from memory
        let addr = self.stack_get(ALPHA_ADDR_INDEX);
        let word = self.state.memory.replay_read_word(addr);
        let alpha = QuadFelt::new(word[0], word[1]);
        let k0 = word[2];
        let k1 = word[3];

        // Read the current accumulator
        let acc_old = QuadFelt::new(
            self.stack_get(ACC_LOW_INDEX),  // acc0
            self.stack_get(ACC_HIGH_INDEX), // acc1
        );

        // Compute the temporary accumulator (first 4 coefficients)
        let acc_tmp = coef
            .iter()
            .rev()
            .take(4)
            .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

        // Compute the final accumulator (remaining 4 coefficients)
        let acc_new = coef
            .iter()
            .rev()
            .skip(4)
            .fold(acc_tmp, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

        // Update the accumulator values on the stack
        let acc_new_base_elements = acc_new.to_base_elements();
        self.stack_write(ACC_HIGH_INDEX, acc_new_base_elements[1]);
        self.stack_write(ACC_LOW_INDEX, acc_new_base_elements[0]);

        // Return the user operation helpers
        let acc_tmp_base_elements = acc_tmp.to_base_elements();
        [
            alpha.base_element(0),    // alpha0
            alpha.base_element(1),    // alpha1
            k0,                       // k0
            k1,                       // k1
            acc_tmp_base_elements[0], // acc_tmp0
            acc_tmp_base_elements[1], // acc_tmp1
        ]
    }

    /// Evaluates a polynomial using Horner's method (extension field).
    ///
    /// In this implementation, we replay the recorded operations and compute the result.
    pub(crate) fn op_horner_eval_ext(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        // Constants from the original implementation
        const ALPHA_ADDR_INDEX: usize = 13;
        const ACC_HIGH_INDEX: usize = 14;
        const ACC_LOW_INDEX: usize = 15;

        // Read the coefficients from the stack as extension field elements (4 QuadFelt elements)
        // Stack layout: [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, ...]
        let coef = [
            QuadFelt::new(self.stack_get(1), self.stack_get(0)), // c0: (c0_0, c0_1)
            QuadFelt::new(self.stack_get(3), self.stack_get(2)), // c1: (c1_0, c1_1)
            QuadFelt::new(self.stack_get(5), self.stack_get(4)), // c2: (c2_0, c2_1)
            QuadFelt::new(self.stack_get(7), self.stack_get(6)), // c3: (c3_0, c3_1)
        ];

        // Read the evaluation point alpha from memory
        let addr = self.stack_get(ALPHA_ADDR_INDEX);
        let word = self.state.memory.replay_read_word(addr);
        let alpha = QuadFelt::new(word[0], word[1]);
        let k0 = word[2];
        let k1 = word[3];

        // Read the current accumulator
        let acc_old = QuadFelt::new(
            self.stack_get(ACC_LOW_INDEX),  // acc0
            self.stack_get(ACC_HIGH_INDEX), // acc1
        );

        // Compute the temporary accumulator (first 2 coefficients: c0, c1)
        let acc_tmp = coef.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);

        // Compute the final accumulator (remaining 2 coefficients: c2, c3)
        let acc_new = coef.iter().rev().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

        // Update the accumulator values on the stack
        let acc_new_base_elements = acc_new.to_base_elements();
        self.stack_write(ACC_HIGH_INDEX, acc_new_base_elements[1]);
        self.stack_write(ACC_LOW_INDEX, acc_new_base_elements[0]);

        // Return the user operation helpers (same as in Process::op_horner_eval_ext)
        let acc_tmp_base_elements = acc_tmp.to_base_elements();
        [
            alpha.base_element(0),    // alpha0
            alpha.base_element(1),    // alpha1
            k0,                       // k0
            k1,                       // k1
            acc_tmp_base_elements[0], // acc_tmp0
            acc_tmp_base_elements[1], // acc_tmp1
        ]
    }
}
