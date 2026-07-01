
## miden::core::sys::vm::constraints_eval_inputs
| Procedure | Description |
| ----------- | ------------- |
| set_up_auxiliary_inputs_ace | Sets up the Miden VM ACE input layout.<br /><br />The stark-vars block starts with 10 EF slots:<br /><br />Word 0 (slots 0-1): alpha, z^N<br />Word 1 (slots 2-3): z_k, is_first<br />Word 2 (slots 4-5): is_last, is_transition<br />Word 3 (slots 6-7): gamma, weight0<br />Word 4 (slots 8-9): f, s0<br /><br />The Miden multi-AIR layout then appends:<br />slot 10: proof-order beta<br />slots 11-13: lifted Core selectors<br />slots 14-16: lifted Chiplets selectors<br />slots 17-19: lifted Poseidon2Permutation selectors<br /><br />Input:  [max_cycle_len_log, ...]<br />Output: [...]<br /> |
