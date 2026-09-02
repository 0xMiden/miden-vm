
## miden::core::pcs::fri::helper
| Procedure | Description |
| ----------- | ------------- |
| evaluate_fri_remainder_poly_max_degree_plus_1_half | Evaluates FRI remainder polynomial of degree strictly less than `(max_degree + 1) / 2`.<br /> |
| evaluate_fri_remainder_poly_max_degree_plus_1 | Evaluates FRI remainder polynomial of degree strictly less than `max_degree + 1`.<br /> |
| generate_fri_parameters | Compute the number of FRI layers given log2 of the size of LDE domain. It also computes the<br />LDE domain generator and, from it, the trace generator and store these for later use.<br /><br />Input: [...]<br />Output: [num_fri_layers, ...]<br /> |
| load_fri_layer_commitments | Get FRI layer commitments and reseed with them in order to draw folding challenges.<br /><br />Input: [...]<br />Output: [...]<br /> |
| load_and_verify_remainder | Load and save the remainder polynomial from the advice provider and check that its hash<br />corresponds to its commitment and reseed with the latter.<br /><br />Input: [...]<br />Output: [...]<br /> |
| compute_query_pointer | Compute the pointer to the first word storing the FRI queries.<br /><br />Since the FRI queries are laid out just before the FRI commitments, we compute the address<br />to the first FRI query by subtracting from the pointer to the first FRI layer commitment<br />the total number of queries.<br /><br />Input: [...]<br />Output: [...]<br /> |
