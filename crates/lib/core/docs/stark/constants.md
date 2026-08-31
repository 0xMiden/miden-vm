
## miden::core::stark::constants
| Procedure | Description |
| ----------- | ------------- |
| set_lde_domain_info_word | Store details about the LDE domain.<br /><br />The info stored is `[lde_size, log(lde_size), lde_g, 0]`.<br /> |
| get_lde_domain_info_word | Load details about the LDE domain.<br /><br />The info stored is `[lde_size, log(lde_size), lde_g, 0]`.<br /> |
| get_lde_domain_depth | Returns log(lde_size), i.e., the depth of the LDE domain Merkle tree.<br /> |
| air_trace_length_logs_ptr | Returns the base pointer of the per-AIR log-height cells.<br /><br />Generic consumers take this pointer and a count as arguments; the relation owns the<br />meaning of each offset.<br /><br />Inputs:  []<br />Outputs: [ptr]<br /><br />Where:<br />- `ptr` is the base address of the per-AIR log-height cells.<br /><br />Invocation: exec<br /> |
| air_trace_length_logs_capacity | Number of per-AIR log-height cells reserved in the shared memory map.<br /> |
| z_ptr | Address for the point `z` and its exponentiation `z^N` where `N=trace_len`.<br /><br />The word stored is `[z^n_0, z^n_1, z_0, z_1]`.<br /> |
| c_ptr | Returns the pointer to the capacity word of the Poseidon2-based random coin.<br /> |
| r1_ptr | Returns the pointer to the first rate word of the Poseidon2-based random coin.<br /> |
| r2_ptr | Returns the pointer to the second rate word of the Poseidon2-based random coin.<br /> |
| assert_valid_order_tag | Rejects an order tag outside a relation's active registry leaves.<br /><br />The relation supplies its active order count (`n!` for `n` AIRs), not the registry tree's<br />power-of-two leaf count. This keeps padding leaves unreachable before `mtree_get`.<br /><br />Inputs:  [order_tag_count, ...]<br />Outputs: [...]<br /> |
| zeroize_stack_word | Overwrites the top stack word with zeros.<br /> |
