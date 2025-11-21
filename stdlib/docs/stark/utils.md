
## std::stark::utils
| Procedure | Description |
| ----------- | ------------- |
| compute_lde_generator | Compute the LDE domain generator from the log2 of its size.<br /><br />Input: [log2(domain_size), ..]<br />Output: [domain_gen, ..]<br />Cycles: 63<br /> |
| validate_inputs | Validates the inputs to the recursive verifier.<br /><br />Input: [log(trace_length), num_queries, grinding, ...]<br />Output: [log(trace_length), num_queries, grinding, ...]<br /><br />Cycles: 45<br /> |
| set_up_auxiliary_inputs_ace | Sets up auxiliary inputs to the arithmetic circuit for the constraint evaluation check.<br /><br />These inputs are:<br /><br />1) OOD evaluation point z,<br />2) random challenge used in computing the DEEP composition polynomial,<br />3) z^N where N is the execution trace length<br />4) z^k where k = min_num_cycles = trace_len / max_cycle_len and max_cycle_len is the longest cycle<br />among all the cycles of periodic columns.<br />5) g^{-1} where g is the trace domain generator.<br /><br />The only input to this procedure is the log2 of the max cycle length across all periodic columns.<br /><br />Input: [max_cycle_len_log, ...]<br />Output: [...]<br /> |
| store_dynamically_executed_procedures | Stores digests of dynamically executed procedures.<br /><br />Input: [D3, D2, D1, D0, ...]<br />Output: [...]<br /> |
