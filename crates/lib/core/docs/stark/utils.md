
## miden::core::stark::utils
| Procedure | Description |
| ----------- | ------------- |
| load_security_params | Loads the proof's security parameters from advice into the generic verifier context.<br /><br />Advice order: [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits].<br />Inputs:  [...]<br />Outputs: [...]<br /> |
| compute_lde_generator | Compute the LDE domain generator from the log2 of its size.<br /><br />Input: [log2(domain_size), ..]<br />Output: [domain_gen, ..]<br /> |
| compute_lde_shift | Compute the canonical LDE coset shift from the log2 of its size.<br /><br />This mirrors `LiftedDomain::canonical_lde_shift(log_lde_order)` on the Rust side:<br />`Felt::GENERATOR^(2^(TWO_ADICITY - log_lde_order))`.<br /><br />Input: [log2(domain_size), ..]<br />Output: [domain_shift, ..]<br /> |
| validate_inputs | Validates generic security parameters for the recursive verifier.<br /><br />The instance-specific wrapper validates shape and stores these parameters before calling the<br />generic verifier.<br /><br />Input: [...]<br />Output: [...]<br /> |
| execute_constraint_evaluation_check | Executes the constraints evaluation check.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Invocation: exec<br /> |
| observe_aux_trace | Observes the auxiliary trace: draws aux randomness, reseeds with the aux trace commitment,<br />and absorbs aux trace boundary values into the transcript.<br /><br />For AIRs without an auxiliary trace, the implementation should be a no-op.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Invocation: exec<br /> |
| store_dynamically_executed_procedures | Stores digests of dynamically executed procedures.<br /><br />Input: [D0, D1, D2, D3, D4, ...]<br />Output: [...]<br /> |
| factorial | Computes x! for small x.<br /><br />Input:  [x]<br />Output: [x!]<br /> |
