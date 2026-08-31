
## miden::core::sys::pvm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes one PVM row of out-of-domain evaluations.<br /><br />The row is the LMCS-aligned wire sequence used by the lifted PCS, in commitment-group order:<br /><br />- 8 preprocessed extension-field slots;<br />- 440 main extension-field slots across ten AIRs in proof order;<br />- 312 auxiliary-coordinate extension-field slots across ten AIRs in proof order;<br />- 8 quotient extension-field slots (four quadratic-extension chunks).<br /><br />This is 768 extension-field values = 1,536 felts = 192 `adv_pipe` blocks. Each block is stored,<br />folded into the DEEP fixed term with `horner_eval_ext`, length-tagged as an eight-felt absorb,<br />and permuted into the transcript.<br /><br />Inputs:  [R0, R1, C, ptr, alpha_ptr, acc0, acc1]<br />Outputs: [R0, R1, C, ptr, alpha_ptr, acc0`, acc1`]<br /> |
