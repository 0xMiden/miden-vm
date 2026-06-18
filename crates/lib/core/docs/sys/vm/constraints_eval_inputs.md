
## miden::core::sys::vm::constraints_eval_inputs
| Procedure | Description |
| ----------- | ------------- |
| set_up_auxiliary_inputs_ace | Sets up the Miden VM ACE input layout.<br /><br />The first 10 EF slots are the base STARK variables:<br /><br />slot 0: alpha         slot 5: is_transition<br />slot 1: z^N           slot 6: gamma<br />slot 2: z_k           slot 7: weight0<br />slot 3: is_first      slot 8: f<br />slot 4: is_last       slot 9: s0<br /><br />The Miden multi-AIR layout appends one beta slot, one reserved slot, three lifted<br />selectors per AIR, and one trace-length slot per AIR.<br /><br />Input:  [max_cycle_len_log, ...]<br />Output: [...]<br /> |
