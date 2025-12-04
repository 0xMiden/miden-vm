
## miden::core::stark::constants
| Procedure | Description |
| ----------- | ------------- |
| set_lde_domain_info_word | Store details about the LDE domain.<br /><br />The info stored is `[lde_size, log(lde_size), lde_g, 0]`.<br /> |
| get_lde_domain_info_word | Load details about the LDE domain.<br /><br />The info stored is `[lde_size, log(lde_size), lde_g, 0]`.<br /> |
| z_ptr | Address for the point `z` and its exponentiation `z^N` where `N=trace_len`.<br /><br />The word stored is `[z_0, z_1, z^n_0, z^n_1]`.<br /> |
| c_ptr | Returns the pointer to the capacity word of the RPO-based random coin.<br /> |
| r1_ptr | Returns the pointer to the first rate word of the RPO-based random coin.<br /> |
| r2_ptr | Returns the pointer to the second rate word of the RPO-based random coin.<br /> |
| zeroize_stack_word | Overwrites the top stack word with zeros.<br /> |
