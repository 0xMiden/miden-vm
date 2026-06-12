
## miden::core::sys::vm::public_inputs
| Procedure | Description |
| ----------- | ------------- |
| process_public_inputs | Processes the public inputs (step I of the verifier).<br /><br />See module banner for the memory layout, the canonical FS schedule and the advice tape<br />order.<br /><br />Precondition:  random coin input_len=0 (guaranteed by `init_seed`, which absorbs the<br />protocol parameters as one full rate block).<br />Postcondition: random coin input_len=0, output_len=8.<br /><br />Input:  [...]<br />Output: [...]<br /> |
