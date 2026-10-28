
## miden::core::pcs::fri::helper
| Procedure | Description |
| ----------- | ------------- |
| evaluate_fri_remainder_poly_max_degree_plus_1_half | Evaluates FRI remainder polynomial of degree strictly less than `(max_degree + 1) / 2`.<br /> |
| evaluate_fri_remainder_poly_max_degree_plus_1 | Evaluates FRI remainder polynomial of degree strictly less than `max_degree + 1`.<br /> |
| generate_fri_parameters | Computes and stores the number of FRI layers and the remainder polynomial size from the LDE<br />domain size.<br /><br />Input: [...]<br />Output: [...]<br /> |
| load_fri_layer_commitments | Get FRI layer commitments and reseed with them in order to draw folding challenges.<br /><br />Input: [...]<br />Output: [...]<br /> |
| load_and_verify_remainder | Loads the FRI remainder polynomial into memory and absorbs it into the transcript.<br /><br />Inputs:  [...]<br />Outputs: [...]<br /><br />Invocation: exec<br /> |
| compute_query_pointer | Compute the pointer to the first word storing the FRI queries.<br /><br />Since the FRI queries are laid out just before the FRI commitments, we compute the address<br />to the first FRI query by subtracting from the pointer to the first FRI layer commitment<br />the total number of queries.<br /><br />Input: [...]<br />Output: [...]<br /> |
