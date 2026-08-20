
## miden::core::sys::pvm::deep_queries
| Procedure | Description |
| ----------- | ------------- |
| compute_deep_composition_polynomial_queries | Computes the PVM DEEP composition-polynomial FRI queries.<br /><br />The opened row is reduced in commitment-group order: preprocessed, main, auxiliary, quotient.<br />The preprocessed group authenticates at its setup-fixed depth using the low 19 bits of the<br />full-domain query index; every other group authenticates at the full query depth.<br /><br />Inputs:  [Y, query_ptr, query_end_ptr, W, query_ptr]<br />Outputs: []<br /> |
