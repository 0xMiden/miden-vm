
## miden::core::debug
| Procedure | Description |
| ----------- | ------------- |
| print_stack | Prints the entire operand stack.<br /><br />Prints the entire operand stack.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Cycles: 3<br /> |
| print_mem | Prints the contents of memory in the range `[start, end)` of the current context, consuming the<br />two range arguments.<br /><br />Inputs:  [start, end, ...]<br />Outputs: [...]<br /><br />Where:<br />- start is the (inclusive) start address of the range to print.<br />- end is the (exclusive) end address of the range to print.<br /><br />Cycles: 5<br /> |
| print_mem_all | Prints the full memory of the current context.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Cycles: 3<br /> |
| print_adv_stack | Prints the advice stack in the range `[start, end)`, consuming the two range arguments.<br /><br />Inputs:  [start, end, ...]<br />Outputs: [...]<br /><br />Where:<br />- start is the (inclusive) start index of the range to print.<br />- end is the (exclusive) end index of the range to print.<br /><br />Cycles: 5<br /> |
| print_adv_stack_all | Prints the full advice stack.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Cycles: 7<br /> |
| print_adv_map_all | Prints the full advice map.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Cycles: 3<br /> |
| print_adv_map_item | Looks up the WORD key in the advice map and prints the associated list of field elements,<br />consuming the key.<br /><br />Inputs:  [KEY, ...]<br />Outputs: [...]<br /><br />Where:<br />- KEY is the word used as the advice map key.<br /><br />Cycles: 7<br /> |
