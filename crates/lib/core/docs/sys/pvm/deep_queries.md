
## miden::core::sys::pvm::deep_queries
| Procedure | Description |
| ----------- | ------------- |
| compute_deep_composition_polynomial_queries | Computes the DEEP composition-polynomial FRI queries.<br /><br />The opened row is reduced in commitment-group order: preprocessed, main, auxiliary, quotient.<br />The preprocessed group authenticates at its setup-fixed depth using the low bits of the<br />full-domain query index; every other group authenticates at the full query depth.<br /><br />Call after `stark::deep_queries::prepare_stack_deep_queries_computation`. The word-aligned<br />range [query_ptr, query_end_ptr) must be nonempty. Each [index, depth, index, 0] record is<br />replaced by [domain_generator^index, index, evaluation_0, evaluation_1].<br /><br />Inputs:  [scratch(4), query_ptr, query_end_ptr, fixed_terms(4), queries_start, ...]<br />Outputs: [...]<br /> |
