
## miden::core::stark::constants
| Procedure | Description |
| ----------- | ------------- |
| assert_valid_order_tag | Rejects an order tag outside a relation's active registry leaves.<br /><br />The relation supplies its active order count (`n!` for `n` AIRs), not the registry tree's<br />power-of-two leaf count. This keeps padding leaves unreachable before `mtree_get`.<br /><br />Inputs:  [order_tag_count, ...]<br />Outputs: [...]<br /> |
| zeroize_stack_word | Overwrites the top stack word with zeros.<br /> |
