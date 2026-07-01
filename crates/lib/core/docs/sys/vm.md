
## miden::core::sys::vm
| Procedure | Description |
| ----------- | ------------- |
| load_air_context | Loads the VM-specific AIR context used by the generic STARK verifier.<br /><br />Advice supplies log heights in fixed instance order:<br />[log_core, log_chiplets, log_poseidon2_permutation]<br /><br />Writes per-AIR log heights, the maximum log height, ORDER_TAG, RELATION_DIGEST, and<br />ACE_REGISTRY_ROOT to memory.<br /> |
| verify_proof | Verifies a STARK proof attesting to the correct execution of a program in the Miden VM.<br /><br />Security parameters (num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits) are<br />loaded from the advice stack, validated against the acceptable security policy, and<br />stored in memory for use by the generic verifier.<br /><br />- Public inputs contain fixed-size input/output stacks, the program digest, and kernel procedure<br />digests.<br />- The wrapper records the AIR context before calling the generic STARK verifier.<br />- The constraints evaluator authenticates the ACE program selected by the derived proof order.<br /><br />Inputs:  []<br />Outputs: []<br /> |
