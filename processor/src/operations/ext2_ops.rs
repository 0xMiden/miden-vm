use super::{ExecutionError, Felt, Process};

// EXTENSION FIELD OPERATIONS
// ================================================================================================

const SEVEN: Felt = Felt::new(7);

impl Process {
    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------
    /// Gets the top four values from the stack [b1, b0, a1, a0], where a = (a1, a0) and
    /// b = (b1, b0) are elements of the extension field, and outputs the product c = (c1, c0)
    /// where c0 = a0 * b0 + 7 * a1 * b1 and c1 = a0 * b1 + a1 * b0.
    ///
    /// The extension field is defined by the irreducible polynomial x² - 7, which means
    /// x² = 7 in the arithmetic (7 is a quadratic non-residue in the Goldilocks field).
    ///
    /// The operation pushes b1, b0 to stack positions 0 and 1, c1 and c0 to positions 2 and 3,
    /// and leaves the rest of the stack unchanged.
    pub(super) fn op_ext2mul(&mut self) -> Result<(), ExecutionError> {
        let [a0, a1, b0, b1] = self.stack.get_word(0).into();
        self.stack.set(0, b1);
        self.stack.set(1, b0);
        self.stack.set(2, a0 * b1 + a1 * b0);
        self.stack.set(3, a0 * b0 + SEVEN * a1 * b1);
        self.stack.copy_state(4);
        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{BasedVectorSpace, Operation, QuadFelt, ZERO, mast::MastForest};
    use miden_utils_testing::rand::rand_value;

    use super::*;
    use crate::{DefaultHost, StackInputs, operations::MIN_STACK_DEPTH};

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_ext2mul() {
        // initialize the stack with a few values
        let [a0, a1, b0, b1] = [rand_value(); 4];

        let stack = StackInputs::new(vec![a0, a1, b0, b1]).expect("inputs lenght too long");
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy(stack);
        let program = &MastForest::default();

        // multiply the top two values
        process.execute_op(Operation::Ext2Mul, program, &mut host).unwrap();
        let a = QuadFelt::new([a0, a1]);
        let b = QuadFelt::new([b0, b1]);
        let c = b * a;
        let c = c.as_basis_coefficients_slice();
        let expected = build_expected(&[b1, b0, c[1], c[0]]);

        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());

        // calling ext2mul with a stack of minimum depth is ok
        let stack = StackInputs::new(vec![]).expect("inputs lenght too long");
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::Ext2Mul, program, &mut host).is_ok());
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn build_expected(values: &[Felt]) -> [Felt; 16] {
        let mut expected = [ZERO; 16];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = value;
        }
        expected
    }
}
