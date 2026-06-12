
## miden::core::sys::vm::constraints_eval_inputs
| Procedure | Description |
| ----------- | ------------- |
| set_up_auxiliary_inputs_ace | Sets up the Miden VM stark-vars region of the recursive-verifier ACE circuit input layout.<br /><br />The stark-vars block is 10 EF slots (5 words) laid out as:<br /><br />Word 0 (slots 0-1): alpha, z^N<br />Word 1 (slots 2-3): z_k, is_first<br />Word 2 (slots 4-5): is_last, is_transition<br />Word 3 (slots 6-7): gamma, weight0<br />Word 4 (slots 8-9): f, s0<br /><br />Multi-AIR appends 18 more EF slots:<br />slot 10:      beta_multi<br />slot 11:      reserved<br />slots 12-23: lifted selectors for Core, Chiplets, Poseidon2Permutation, and And8Lookup<br />slots 24-27: trace lengths for Core, Chiplets, Poseidon2Permutation, and And8Lookup<br /><br />Input:  [max_cycle_len_log, ...]<br />Output: [...]<br /> |
