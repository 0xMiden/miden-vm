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
