use miden_air::{RowIndex, trace::decoder::NUM_USER_OP_HELPERS};
use miden_core::{ExtensionOf, Felt, FieldElement, ONE, QuadFelt, StarkField, Word, ZERO};

use crate::{
    ErrorContext, ExecutionError, FMP_MIN, operations::utils::assert_binary, system::FMP_MAX,
    utils::split_element,
};

/// The `Processor` trait implements most of the core VM operations.
///
/// It does not include any operations that rely on the host; those need to be implemented
/// individually by the processor implementations.
///
/// We model the stack as a slice of `Felt` values, where the top of the stack is at the last index
/// of the slice. The stack is mutable, and the processor can manipulate it directly. A "stack top
/// pointer" tracks the current top of the stack. Indices are always taken relative to the top of
/// the stack, meaning that `stack_get(0)` returns the top element, `stack_get(1)` returns the
/// second element from the top, and so on. The stack is always at least 16 elements deep.
pub trait Processor {
    // -------------------------------------------------------------------------------------------
    // REQUIRED METHODS
    // -------------------------------------------------------------------------------------------

    /// Returns the value of the CALLER_HASH register, which is the hash of the procedure that
    /// called the currently executing procedure.
    fn caller_hash(&self) -> Word;

    /// Returns true if the processor is currently executing a syscall, false otherwise.
    fn in_syscall(&self) -> bool;

    /// Returns the current clock cycle of the processor.
    fn clk(&self) -> RowIndex;

    /// Returns the current value of the FMP register.
    fn fmp(&self) -> Felt;

    /// Sets the FMP register to a new value.
    fn set_fmp(&mut self, new_fmp: Felt);

    /// Returns the top 16 elements of the stack, such that the top of the stack is at the last
    /// index of the returned slice.
    fn stack_top(&self) -> &[Felt];

    /// Returns the element on the stack at index `idx`.
    fn stack_get(&self, idx: usize) -> Felt;

    /// Mutable variant of `stack_get()`.
    fn stack_get_mut(&mut self, idx: usize) -> &mut Felt;

    /// Returns the word on the stack starting at index `start_idx` in "stack order".
    ///
    /// That is, for `start_idx=0` the top element of the stack will be at the last position in the
    /// word.
    ///
    /// For example, if the stack looks like this:
    ///
    /// top                                                       bottom
    /// v                                                           v
    /// a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
    ///
    /// Then
    /// - `stack_get_word(0)` returns `[d, c, b, a]`,
    /// - `stack_get_word(1)` returns `[e, d, c ,b]`,
    /// - etc.
    fn stack_get_word(&self, start_idx: usize) -> Word;

    /// Returns the number of elements on the stack in the current context.
    fn stack_depth(&self) -> u32;

    /// Writes an element to the stack at the given index.
    fn stack_write(&mut self, idx: usize, element: Felt);

    /// Writes a word to the stack starting at the given index.
    ///
    /// The index is the index of the first element of the word, and the word is written in reverse
    /// order.
    fn stack_write_word(&mut self, start_idx: usize, word: &Word);

    /// Swaps the elements at the given indices on the stack.
    fn stack_swap(&mut self, idx1: usize, idx2: usize);

    /// Swaps the nth word from the top of the stack with the top word of the stack.
    ///
    /// Valid values of `n` are 1, 2, and 3.
    fn swapw_nth(&mut self, n: usize);

    /// Rotates the top `n` elements of the stack to the left by 1.
    ///
    /// For example, if the stack is [a, b, c, d], with `d` at the top, then `rotate_left(3)` will
    /// result in the top 3 elements being rotated left: [a, c, d, b].
    ///
    /// This operation is useful for implementing the `movup` instructions.
    ///
    /// The stack size doesn't change.
    ///
    /// Note: This method doesn't use the `stack_get()` and `stack_write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    fn rotate_left(&mut self, n: usize);

    /// Rotates the top `n` elements of the stack to the right by 1.
    ///
    /// Analogous to `rotate_left`, but in the opposite direction.
    ///
    /// Note: This method doesn't use the `stack_get()` and `stack_write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    fn rotate_right(&mut self, n: usize);

    /// Increments the stack top pointer by one, announcing the intent to add a new element to the
    /// stack. That is, the stack size is incremented, but the element is not written yet.
    ///
    /// This can be understood as pushing a `None` on top of the stack, such that a subsequent call
    /// to `stack_write(0)` or `stack_write_word(0)` will write an element to that new position.
    ///
    /// It is guaranteed that any operation that calls `increment_stack_size()` will subsequently
    /// call `stack_write(0)` or `stack_write_word(0)` to write an element to that position on the
    /// stack.
    fn increment_stack_size(&mut self);

    /// Decrements the stack size by one, removing the top element from the stack.
    ///
    /// Concretely, this decrements the stack top pointer by one (removing the top element), and
    /// pushes a `ZERO` at the bottom of the stack if the stack size is already at 16 elements
    /// (since the stack size can never be less than 16).
    fn decrement_stack_size(&mut self);

    // -------------------------------------------------------------------------------------------
    // PROVIDED METHODS
    // -------------------------------------------------------------------------------------------

    // SYSTEM METHODS
    // -------------------------------------------------------------------------------------------

    /// Adds the current FMP value to the top of the stack.
    fn op_fmpadd(&mut self) {
        let fmp = self.fmp();
        let top = self.stack_get_mut(0);

        *top += fmp;
    }

    /// Adds the value on the top of the stack to the current FMP value.
    fn op_fmpupdate(&mut self) -> Result<(), ExecutionError> {
        let top = self.stack_get(0);

        let new_fmp = self.fmp() + top;
        let new_fmp_int = new_fmp.as_int();
        if !(FMP_MIN..=FMP_MAX).contains(&new_fmp_int) {
            return Err(ExecutionError::InvalidFmpValue(self.fmp(), new_fmp));
        }

        self.set_fmp(new_fmp);
        self.decrement_stack_size();
        Ok(())
    }

    /// Writes the current stack depth to the top of the stack.
    fn op_sdepth(&mut self) {
        let depth = self.stack_depth();
        self.increment_stack_size();
        self.stack_write(0, depth.into());
    }

    /// Analogous to `Process::op_caller`.
    fn op_caller(&mut self) -> Result<(), ExecutionError> {
        if !self.in_syscall() {
            return Err(ExecutionError::CallerNotInSyscall);
        }

        let caller_hash = self.caller_hash();
        self.stack_write_word(0, &caller_hash);

        Ok(())
    }

    /// Writes the current clock value to the top of the stack.
    fn op_clk(&mut self) {
        self.increment_stack_size();
        self.stack_write(0, self.clk().into());
    }

    // STACK METHODS
    // -------------------------------------------------------------------------------------------

    /// Pushes a new element onto the stack.
    fn op_push(&mut self, element: Felt) {
        self.increment_stack_size();
        self.stack_write(0, element);
    }

    /// Pushes a `ZERO` on top of the stack.
    fn op_pad(&mut self) {
        self.increment_stack_size();
        self.stack_write(0, ZERO);
    }

    /// Swaps the top two elements of the stack.
    fn op_swap(&mut self) {
        self.stack_swap(0, 1);
    }

    /// Swaps the top two double words of the stack.
    fn op_swap_double_word(&mut self) {
        self.stack_swap(0, 8);
        self.stack_swap(1, 9);
        self.stack_swap(2, 10);
        self.stack_swap(3, 11);
        self.stack_swap(4, 12);
        self.stack_swap(5, 13);
        self.stack_swap(6, 14);
        self.stack_swap(7, 15);
    }

    /// Duplicates the n'th element from the top of the stack to the top of the stack.
    ///
    /// The size of the stack is incremented by 1.
    fn dup_nth(&mut self, n: usize) {
        let to_dup = self.stack_get(n);
        self.increment_stack_size();
        self.stack_write(0, to_dup);
    }

    /// Analogous to `Process::op_cswap`.
    fn op_cswap(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let condition = self.stack_get(0);
        self.decrement_stack_size();

        match condition.as_int() {
            0 => {
                // do nothing, a and b are already in the right place
            },
            1 => {
                self.stack_swap(0, 1);
            },
            _ => {
                return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
            },
        }

        Ok(())
    }

    /// Analogous to `Process::op_cswapw`.
    fn op_cswapw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let condition = self.stack_get(0);
        self.decrement_stack_size();

        match condition.as_int() {
            0 => {
                // do nothing, the words are already in the right place
            },
            1 => {
                self.stack_swap(0, 4);
                self.stack_swap(1, 5);
                self.stack_swap(2, 6);
                self.stack_swap(3, 7);
            },
            _ => {
                return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
            },
        }

        Ok(())
    }

    // U32 METHODS
    // -------------------------------------------------------------------------------------------

    /// Removes and splits the top element of the stack into two 32-bit values, and pushes them onto
    /// the stack.
    #[inline(always)]
    fn op_u32split(&mut self) {
        let top = self.stack_get(0);
        let (hi, lo) = split_element(top);

        self.increment_stack_size();
        self.stack_write(0, hi);
        self.stack_write(1, lo);
    }

    /// Adds the top two elements of the stack and pushes the result onto the stack.
    fn op_u32add(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a + b, err_ctx)
    }

    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    ///
    /// The size of the stack is decremented by 1.
    #[inline(always)]
    fn op_u32add3(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (sum_hi, sum_lo) = {
            let c = self.stack_get(0).as_int();
            let b = self.stack_get(1).as_int();
            let a = self.stack_get(2).as_int();

            // Check that a, b, and c are u32 values.
            if a > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(a), ZERO, err_ctx));
            }
            if b > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(b), ZERO, err_ctx));
            }
            if c > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(c), ZERO, err_ctx));
            }
            let result = Felt::new(a + b + c);
            split_element(result)
        };

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.decrement_stack_size();
        self.stack_write(0, sum_hi);
        self.stack_write(1, sum_lo);
        Ok(())
    }

    /// Pops two elements off the stack, subtracts the top element from the second element, and
    /// pushes the result as well as a flag indicating whether there was underflow back onto the
    /// stack.
    #[inline(always)]
    fn op_u32sub(
        &mut self,
        op_idx: usize,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let op_idx = Felt::from(op_idx as u32);
        self.u32_pop2_applyfn_push_results(
            op_idx,
            |first_old, second_old| {
                let result = second_old.wrapping_sub(first_old);
                let first_new = result >> 63;
                let second_new = result & u32::MAX as u64;

                Ok((first_new, second_new))
            },
            err_ctx,
        )
    }
    /// Pops two elements off the stack, multiplies them, splits the result into low and high
    /// 32-bit values, and pushes these values back onto the stack.
    #[inline(always)]
    fn op_u32mul(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a * b, err_ctx)
    }

    /// Pops three elements off the stack, multiplies the first two and adds the third element to
    /// the result, splits the result into low and high 32-bit values, and pushes these values
    /// back onto the stack.
    #[inline(always)]
    fn op_u32madd(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (result_hi, result_lo) = {
            let b = self.stack_get(0).as_int();
            let a = self.stack_get(1).as_int();
            let c = self.stack_get(2).as_int();

            // Check that a, b, and c are u32 values.
            if b > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(a), ZERO, err_ctx));
            }
            if a > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(b), ZERO, err_ctx));
            }
            if c > u32::MAX as u64 {
                return Err(ExecutionError::not_u32_value(Felt::new(c), ZERO, err_ctx));
            }
            let result = Felt::new(a * b + c);
            split_element(result)
        };

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.decrement_stack_size();
        self.stack_write(0, result_hi);
        self.stack_write(1, result_lo);
        Ok(())
    }

    /// Pops two elements off the stack, divides the second element by the top element, and pushes
    /// the quotient and the remainder back onto the stack.
    ///
    /// # Errors
    /// Returns an error if the divisor is ZERO.
    #[inline(always)]
    fn op_u32div(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let clk = self.clk();
        self.u32_pop2_applyfn_push_results(
            ZERO,
            |first, second| {
                if first == 0 {
                    return Err(ExecutionError::divide_by_zero(clk, err_ctx));
                }

                // a/b = n*q + r for some n>=0 and 0<=r<b
                let q = second / first;
                let r = second - q * first;

                // r is placed on top of the stack, followed by q
                Ok((r, q))
            },
            err_ctx,
        )
    }

    /// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
    /// onto the stack.
    fn op_u32and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a & b, err_ctx)
    }

    /// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
    /// the stack.
    #[inline(always)]
    fn op_u32xor(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a ^ b, err_ctx)
    }

    /// Pops top two element off the stack, splits them into low and high 32-bit values, checks if
    /// the high values are equal to 0; if they are, puts the original elements back onto the
    /// stack; if they are not, returns an error.
    #[inline(always)]
    fn op_u32assert2(
        &mut self,
        err_code: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_results(err_code, |first, second| Ok((first, second)), err_ctx)
    }

    // FIELD OPS
    // ----------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, adds them together, and pushes the result back onto the
    /// stack.
    fn op_add(&mut self) {
        self.pop2_applyfn_push(|a, b| Ok(a + b)).unwrap()
    }

    /// Pops an element off the stack, computes its additive inverse, and pushes the result back
    /// onto the stack.
    fn op_neg(&mut self) {
        let element = self.stack_get(0);
        self.stack_write(0, -element);
    }

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    fn op_mul(&mut self) {
        self.pop2_applyfn_push(|a, b| Ok(a * b)).unwrap();
    }

    /// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
    /// back onto the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is ZERO.
    #[inline(always)]
    fn op_inv(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let top = self.stack_get_mut(0);
        if (*top) == ZERO {
            return Err(ExecutionError::divide_by_zero(self.clk(), err_ctx));
        }
        *top = top.inv();
        Ok(())
    }

    /// Pops an element off the stack, adds ONE to it, and pushes the result back onto the stack.
    fn op_incr(&mut self) {
        *self.stack_get_mut(0) += ONE;
    }

    /// Pops two elements off the stack, computes their boolean AND, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    #[inline(always)]
    fn op_and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE && b == ONE { Ok(ONE) } else { Ok(ZERO) }
        })
    }

    /// Pops two elements off the stack, computes their boolean OR, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    #[inline(always)]
    fn op_or(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE || b == ONE { Ok(ONE) } else { Ok(ZERO) }
        })
    }

    /// Pops an element off the stack, computes its boolean NOT, and pushes the result back onto
    /// the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is not a binary value.
    #[inline(always)]
    fn op_not(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let top = self.stack_get_mut(0);
        if *top == ZERO {
            *top = ONE;
        } else if *top == ONE {
            *top = ZERO;
        } else {
            return Err(ExecutionError::not_binary_value_op(*top, err_ctx));
        }
        Ok(())
    }

    /// Pops two elements off the stack and compares them. If the elements are equal, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    fn op_eq(&mut self) {
        self.pop2_applyfn_push(|a, b| if a == b { Ok(ONE) } else { Ok(ZERO) }).unwrap()
    }

    /// Pops an element off the stack and compares it to ZERO. If the element is ZERO, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    fn op_eqz(&mut self) {
        let top = self.stack_get_mut(0);
        if (*top) == ZERO {
            *top = ONE;
        } else {
            *top = ZERO;
        }
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
    fn op_expacc(&mut self) {
        let old_base = self.stack_get(1);
        let old_acc = self.stack_get(2);
        let old_exp_int = self.stack_get(3).as_int();

        // Compute new exponent.
        let new_exp = Felt::new(old_exp_int >> 1);

        // Compute new accumulator. We update the accumulator only when the least significant bit of
        // the exponent is 1.
        let exp_lsb = old_exp_int & 1;
        let acc_update_val = if exp_lsb == 1 { old_base } else { ONE };
        let new_acc = old_acc * acc_update_val;

        // Compute the new base.
        let new_base = old_base * old_base;

        self.stack_write(0, Felt::new(exp_lsb));
        self.stack_write(1, new_base);
        self.stack_write(2, new_acc);
        self.stack_write(3, new_exp);
    }

    /// Gets the top four values from the stack [b1, b0, a1, a0], where a = (a1, a0) and
    /// b = (b1, b0) are elements of the extension field, and outputs the product c = (c1, c0)
    /// where c0 = b0 * a0 - 2 * b1 * a1 and c1 = (b0 + b1) * (a1 + a0) - b0 * a0. It pushes 0 to
    /// the first and second positions on the stack, c1 and c2 to the third and fourth positions,
    /// and leaves the rest of the stack unchanged.
    fn op_ext2mul(&mut self) {
        const TWO: Felt = Felt::new(2);
        let [a0, a1, b0, b1] = self.stack_get_word(0).into();

        /* top 2 elements remain unchanged */

        let b0_times_a0 = b0 * a0;
        self.stack_write(2, (b0 + b1) * (a1 + a0) - b0_times_a0);
        self.stack_write(3, b0_times_a0 - TWO * b1 * a1);
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Pops the top two elements from the stack, applies the given function to them, and pushes the
    /// result back onto the stack.
    ///
    /// The size of the stack is decremented by 1.
    #[inline(always)]
    fn pop2_applyfn_push(
        &mut self,
        f: impl FnOnce(Felt, Felt) -> Result<Felt, ExecutionError>,
    ) -> Result<(), ExecutionError> {
        let b = self.stack_get(0);
        let a = self.stack_get(1);

        self.decrement_stack_size();
        self.stack_write(0, f(a, b)?);

        Ok(())
    }

    /// Equivalent to `pop2_applyfn_push`, but for u32 values.
    #[inline(always)]
    fn u32_pop2_applyfn_push(
        &mut self,
        f: impl FnOnce(u64, u64) -> u64,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let b = self.stack_get(0).as_int();
        let a = self.stack_get(1).as_int();

        // Check that a and b are u32 values.
        if b > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(b), ZERO, err_ctx));
        }
        if a > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(a), ZERO, err_ctx));
        }

        let result = f(a, b);
        self.decrement_stack_size();
        self.stack_write(0, Felt::new(result));

        Ok(())
    }

    /// Pops 2 elements from the stack, applies the given function to them, and pushes the low/high
    /// u32 values of the result back onto the stack.
    ///
    /// Specifically, this function
    /// 1. pops the top two elements from the stack,
    /// 2. applies the given function to them,
    /// 3. splits the result into low/high u32 values, and
    /// 4. pushes the low/high values back onto the stack.
    ///
    /// The size of the stack doesn't change.
    #[inline(always)]
    fn u32_pop2_applyfn_push_lowhigh(
        &mut self,
        f: impl FnOnce(u64, u64) -> u64,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let b = self.stack_get(0).as_int();
        let a = self.stack_get(1).as_int();

        // Check that a and b are u32 values.
        if a > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(a), ZERO, err_ctx));
        }
        if b > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(b), ZERO, err_ctx));
        }

        let result = Felt::new(f(a, b));
        let (hi, lo) = split_element(result);

        self.stack_write(0, hi);
        self.stack_write(1, lo);
        Ok(())
    }

    /// Pops 2 elements from the stack, applies the given function to them, and pushes the resulting
    /// 2 u32 values back onto the stack.
    ///
    /// The size of the stack doesn't change.
    #[inline(always)]
    fn u32_pop2_applyfn_push_results(
        &mut self,
        err_code: Felt,
        f: impl FnOnce(u64, u64) -> Result<(u64, u64), ExecutionError>,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let first_old = self.stack_get(0).as_int();
        let second_old = self.stack_get(1).as_int();

        // Check that a and b are u32 values.
        if first_old > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(first_old), err_code, err_ctx));
        }
        if second_old > u32::MAX as u64 {
            return Err(ExecutionError::not_u32_value(Felt::new(second_old), err_code, err_ctx));
        }

        let (first_new, second_new) = f(first_old, second_old)?;

        self.stack_write(0, Felt::new(first_new));
        self.stack_write(1, Felt::new(second_new));
        Ok(())
    }

    // FIELD OPS
    // ----------------------------------------------------------------------------------------------

    fn op_fri_ext2fold4(&mut self) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
        // --- read all relevant variables from the stack ---------------------
        let query_values = self.get_query_values();
        let folded_pos = self.stack_get(8);
        // the segment identifier of the position in the source domain
        let domain_segment = self.stack_get(9).as_int();
        // the power of the domain generator which can be used to determine current domain value x
        let poe = self.stack_get(10);
        // the result of the previous layer folding
        let prev_value = {
            let pe1 = self.stack_get(11);
            let pe0 = self.stack_get(12);
            QuadFelt::new(pe0, pe1)
        };
        // the verifier challenge for the current layer
        let alpha = {
            let a1 = self.stack_get(13);
            let a0 = self.stack_get(14);
            QuadFelt::new(a0, a1)
        };
        // the memory address of the current layer
        let layer_ptr = self.stack_get(15);

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

        self.decrement_stack_size();

        self.stack_write(0, tmp0[1]);
        self.stack_write(1, tmp0[0]);
        self.stack_write(2, tmp1[1]);
        self.stack_write(3, tmp1[0]);
        self.stack_write_word(4, &ds.into());
        self.stack_write(8, poe2);
        self.stack_write(9, f_tau);
        self.stack_write(10, layer_ptr + EIGHT);
        self.stack_write(11, poe4);
        self.stack_write(12, folded_pos);
        self.stack_write(13, folded_value[1]);
        self.stack_write(14, folded_value[0]);

        Ok(get_helper_registers(ev, es, x, x_inv))
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns 4 query values in the source domain. These values are to be folded into a single
    /// value in the folded domain.
    fn get_query_values(&self) -> [QuadFelt; 4] {
        let [v4, v5, v6, v7] = self.stack_get_word(0).into();
        let [v0, v1, v2, v3] = self.stack_get_word(4).into();

        [
            QuadFelt::new(v0, v1),
            QuadFelt::new(v2, v3),
            QuadFelt::new(v4, v5),
            QuadFelt::new(v6, v7),
        ]
    }
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

fn get_helper_registers(
    ev: QuadFelt,
    es: QuadFelt,
    x: Felt,
    x_inv: Felt,
) -> [Felt; NUM_USER_OP_HELPERS] {
    let ev_arr = [ev];
    let ev_felts = QuadFelt::slice_as_base_elements(&ev_arr);

    let es_arr = [es];
    let es_felts = QuadFelt::slice_as_base_elements(&es_arr);

    [ev_felts[0], ev_felts[1], es_felts[0], es_felts[1], x, x_inv]
}

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
