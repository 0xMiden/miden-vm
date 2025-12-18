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
