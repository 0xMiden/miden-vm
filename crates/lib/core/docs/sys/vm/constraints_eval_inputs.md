
## miden::core::sys::vm::constraints_eval_inputs
| Procedure | Description |
| ----------- | ------------- |
| set_up_auxiliary_inputs_ace | Sets up the Miden VM ACE input layout.<br /><br />Generated constraint-evaluation modules call `stark::utils` directly. This wrapper keeps the<br />old module path valid for any stale generated artifact.<br /><br />Input:  [max_cycle_len_log, ...]<br />Output: [...]<br /> |
