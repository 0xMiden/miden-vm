
## miden::core::sys::vm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes the out-of-domain (OOD) evaluations of all committed polynomials.<br /><br />Takes a Poseidon2 hasher state and a pointer. Loads OOD evaluations from the advice provider,<br />stores them at `ptr`, absorbs them into the hasher state, and simultaneously computes a random<br />linear combination using Horner evaluation.<br /><br /><br />Inputs:  [R0, R1, C, ptr, acc0, acc1]<br />Outputs: [R0, R1, C, ptr, acc0`, acc1`]<br /><br /> |
