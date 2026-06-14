
## miden::core::sys::vm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes the out-of-domain (OOD) evaluations of all committed polynomials.<br /><br />Loads one OOD row from advice, absorbs it into the Eidos transcript, and updates the<br />Horner accumulator used by the DEEP fixed terms.<br /><br />Inputs:  [scratch0, scratch1, scratch2, ptr, alpha_ptr, acc0, acc1]<br />Outputs: [scratch0, scratch1, scratch2, ptr, alpha_ptr, acc0', acc1']<br /> |
