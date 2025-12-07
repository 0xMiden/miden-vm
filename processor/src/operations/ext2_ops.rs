use super::{ExecutionError, Felt, Process};

// EXTENSION FIELD OPERATIONS
// ================================================================================================

const TWO: Felt = Felt::new(2);

impl Process {
    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------
    /// Gets the top four values from the stack [b1, b0, a1, a0], where a = (a1, a0) and
    /// b = (b1, b0) are elements of the extension field, and outputs the product c = (c1, c0)
    /// where c0 = b0 * a0 - 2 * b1 * a1 and c1 = (b0 + b1) * (a1 + a0) - b0 * a0. It pushes 0 to
    /// the first and second positions on the stack, c1 and c2 to the third and fourth positions,
    /// and leaves the rest of the stack unchanged.
    pub(super) fn op_ext2mul(&mut self) -> Result<(), ExecutionError> {
        let [a0, a1, b0, b1] = self.stack.get_word(0).into();
        self.stack.set(0, b1);
        self.stack.set(1, b0);
        self.stack.set(2, (b0 + b1) * (a1 + a0) - b0 * a0);
        self.stack.set(3, b0 * a0 - TWO * b1 * a1);
        self.stack.copy_state(4);
        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{Operation, QuadFelt, ZERO, mast::MastForest};
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
        let a = QuadFelt::new(a0, a1);
        let b = QuadFelt::new(b0, b1);
        let c = (b * a).to_base_elements();
        let expected = build_expected(&[b1, b0, c[1], c[0]]);

        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());

        // calling ext2mul with a stack of minimum depth is ok
        let stack = StackInputs::new(vec![]).expect("inputs lenght too long");
        let mut process = Process::new_dummy(stack);
        process.execute_op(Operation::Ext2Mul, program, &mut host).unwrap();
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
