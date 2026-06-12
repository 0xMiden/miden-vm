
## miden::core::sys::vm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes the out-of-domain (OOD) evaluations of all committed polynomials.<br /><br />Takes a Poseidon2 hasher state, a destination pointer, and the current Horner accumulator. Loads<br />one OOD frame from advice, stores it at `ptr`, absorbs it into the transcript, and folds it into<br />the accumulator.<br /><br />Inputs:  [R0, R1, C, ptr, acc0, acc1]<br />Outputs: [R0, R1, C, ptr, acc0', acc1']<br /> |
