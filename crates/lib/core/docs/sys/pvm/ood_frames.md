
## miden::core::sys::pvm::ood_frames
| Procedure | Description |
| ----------- | ------------- |
| process_row_ood_evaluations | Processes one PVM row of out-of-domain evaluations.<br /><br />The row is the LMCS-aligned wire sequence used by the lifted PCS, in commitment-group order:<br /><br />- 8 preprocessed extension-field slots;<br />- 528 main extension-field slots across ten AIRs in proof order;<br />- 280 auxiliary-coordinate extension-field slots across ten AIRs in proof order;<br />- 8 quotient extension-field slots (four quadratic-extension chunks).<br /><br />This is 824 extension-field values = 1,648 felts = 206 `adv_pipe` blocks. Each block is stored,<br />folded into the DEEP fixed term with `horner_eval_ext`, and compressed into the Eidos<br />transcript.<br /><br />Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]<br />Outputs: [scratch0, scratch1, cv', ptr, alpha_ptr, acc0', acc1']<br /> |
