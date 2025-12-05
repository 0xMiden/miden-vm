
## miden::core::sys::vm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes the out-of-domain (OOD) evaluations of all committed polynomials.<br /><br />Takes as input an RPO hasher state and a pointer, and loads from the advice provider the OOD<br />evaluations and stores at memory region using pointer `ptr` while absorbing the evaluations<br />into the hasher state and simultaneously computing a random linear combination using Horner<br />evaluation.<br /><br /><br />Inputs:  [R2, R1, C, ptr, acc1, acc0]<br />Outputs: [R2, R1, C, ptr, acc1`, acc0`]<br /><br />Cycles: 72<br /> |
