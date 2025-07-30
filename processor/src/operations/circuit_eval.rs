use crate::{ExecutionError, Process, chiplets::eval_circuit, errors::ErrorContext};

impl Process {
    /// Checks that the evaluation of an arithmetic circuit is equal to zero.
    ///
    /// The inputs are composed of:
    ///
    /// 1. a pointer to the memory region containing the arithmetic circuit description, which
    ///    itself is arranged as:
    ///
    ///    a. `Read` section:
    ///       1. Inputs to the circuit which are elements in the quadratic extension field,
    ///       2. Constants of the circuit which are elements in the quadratic extension field,
    ///
    ///    b. `Eval` section, which contains the encodings of the evaluation gates of the circuit.
    ///    Each gate is encoded as a single base field element.
    /// 2. the number of rows in the `READ` section,
    /// 3. the number of rows in the `EVAL` section,
    ///
    /// Stack transition:
    /// [ptr, num_read_rows, num_eval_rows, ...] -> [ptr, num_read_rows, num_eval_rows, ...]
    pub fn op_eval_circuit(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let num_eval_rows = self.stack.get(2);
        let num_read_rows = self.stack.get(1);
        let ptr = self.stack.get(0);
        let ctx = self.system.ctx();
        let clk = self.system.clk();
        let circuit_evaluation = eval_circuit(
            ctx,
            ptr,
            clk,
            num_read_rows,
            num_eval_rows,
            &mut self.chiplets.memory,
            err_ctx,
        )?;
        self.chiplets.ace.add_circuit_evaluation(clk, circuit_evaluation);

        self.stack.copy_state(0);

        Ok(())
    }
}
