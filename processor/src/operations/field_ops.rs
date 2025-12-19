use miden_core::{ONE, Operation, ZERO};

use super::{ExecutionError, Felt, FieldElement, Process, utils::assert_binary};
use crate::ErrorContext;

// FIELD OPERATIONS
// ================================================================================================

impl Process {
    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------
    /// Pops two elements off the stack, adds them together, and pushes the result back onto the
    /// stack.
    pub(super) fn op_add(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);
        self.stack.set(0, a + b);
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its additive inverse, and pushes the result back
    /// onto the stack.
    pub(super) fn op_neg(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        self.stack.set(0, -a);
        self.stack.copy_state(1);
        Ok(())
    }

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    pub(super) fn op_mul(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);
        self.stack.set(0, a * b);
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
    /// back onto the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is ZERO.
    pub(super) fn op_inv(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        if a == ZERO {
            return Err(ExecutionError::divide_by_zero(self.system.clk(), err_ctx));
        }

        self.stack.set(0, a.inv());
        self.stack.copy_state(1);
        Ok(())
    }

    /// Pops an element off the stack, adds ONE to it, and pushes the result back onto the stack.
    pub(super) fn op_incr(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        self.stack.set(0, a + ONE);
        self.stack.copy_state(1);
        Ok(())
    }

    // BOOLEAN OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, computes their boolean AND, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    pub(super) fn op_and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = assert_binary(self.stack.get(0), err_ctx)?;
        let a = assert_binary(self.stack.get(1), err_ctx)?;
        if a == ONE && b == ONE {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
        }
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops two elements off the stack, computes their boolean OR, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    pub(super) fn op_or(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = assert_binary(self.stack.get(0), err_ctx)?;
        let a = assert_binary(self.stack.get(1), err_ctx)?;
        if a == ONE || b == ONE {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
        }
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its boolean NOT, and pushes the result back onto
    /// the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is not a binary value.
    pub(super) fn op_not(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let a = assert_binary(self.stack.get(0), err_ctx)?;
        self.stack.set(0, ONE - a);
        self.stack.copy_state(1);
        Ok(())
    }

    // COMPARISON OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack and compares them. If the elements are equal, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    pub(super) fn op_eq(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);

        // helper variable provided by the prover. If top elements are same, then, it can be set to
        // anything otherwise set it to the reciprocal of the difference between the top two
        // elements.
        let mut h0 = ZERO;

        if a == b {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
            // setting h0 to the inverse of the difference between the top two elements of the
            // stack.
            h0 = (b - a).inv();
        }

        // save h0 in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Eq, &[h0]);

        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack and compares it to ZERO. If the element is ZERO, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    pub(super) fn op_eqz(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);

        // helper variable provided by the prover. If the top element is zero, then, h0 can be set
        // to anything otherwise set it to the inverse of the top element in the stack.
        let mut h0 = ZERO;

        if a == ZERO {
            self.stack.set(0, ONE);
        } else {
            // setting h0 to the inverse of the top element of the stack.
            h0 = a.inv();
            self.stack.set(0, ZERO);
        }

        // save h0 in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Eq, &[h0]);

        self.stack.copy_state(1);
        Ok(())
    }

    /// Computes a single turn of exp accumulation for the given inputs. The top 4 elements in the
    /// stack are arranged as follows (from the top):
    /// - 0: least significant bit of the exponent in the previous trace if there's an expacc call,
    ///   otherwise ZERO,
    /// - 1: base of the exponentiation; i.e. `b` in `b^a`,
    /// - 2: accumulated result of the exponentiation so far,
    /// - 3: the exponent; i.e. `a` in `b^a`.
    ///
    /// It is expected that `Expacc` is called at least `num_exp_bits` times, where `num_exp_bits`
    /// is the number of bits needed to represent `exp`. The initial call to `Expacc` should set the
    /// stack as [0, base, 1, exponent]. The subsequent call will set the stack either as
    /// - [0, base^2, acc, exp/2], or
    /// - [1, base^2, acc * base, exp/2],
    ///
    /// depending on the least significant bit of the exponent.
    ///
    /// Expacc is based on the observation that the exponentiation of a number can be computed by
    /// repeatedly squaring the base and multiplying those powers of the base by the accumulator,
    /// for the powers of the base which correspond to the exponent's bits which are set to 1.
    ///
    /// For example, take b^5 = (b^2)^2 * b. Over the course of 3 iterations (5 = 101b), the
    /// algorithm will compute b, b^2 and b^4 (placed in `base_acc`). Hence, we want to multiply
    /// `base_acc` in `result_acc` when `base_acc = b` and when `base_acc = b^4`, which occurs on
    /// the first and third iterations (corresponding to the `1` bits in the binary representation
    /// of 5).
    pub(super) fn op_expacc(&mut self) -> Result<(), ExecutionError> {
        let old_base_acc = self.stack.get(1);
        let old_result_acc = self.stack.get(2);
        let old_exp = self.stack.get(3);

        // Compute new exponent.
        let new_exp = Felt::new(old_exp.as_int() >> 1);

        // Compute new accumulator. We update the accumulator only when the least significant bit of
        // the exponent is 1.
        let exp_lsb = old_exp.as_int() & 1;
        let result_acc_update = if exp_lsb == 1 { old_base_acc } else { ONE };
        let new_result_acc = old_result_acc * result_acc_update;

        // Compute the new base.
        let new_base_acc = old_base_acc * old_base_acc;

        // Update the stack with the new values.
        self.stack.set(0, Felt::new(exp_lsb));
        self.stack.set(1, new_base_acc);
        self.stack.set(2, new_result_acc);
        self.stack.set(3, new_exp);
        self.stack.copy_state(4);

        // save value multiplied in the accumulator in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Expacc, &[result_acc_update]);

        Ok(())
    }
}
