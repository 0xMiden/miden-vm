
## miden::core::sys::pvm::fixed_boundary
| Procedure | Description |
| ----------- | ------------- |
| compute_fixed_boundary_correction | Sums the inverses of the compressed fixed-environment UintVal and EcGroup bus messages.<br /><br />Reads beta and alpha from the relation's auxiliary-randomness region, stores beta^18 in<br />BUS_GAMMA_PTR, and stores the sum in C_TOTAL_PTR. All caller stack elements are preserved.<br />Fails if an encoded message denominator is zero.<br /><br />Input:  [...]<br />Output: [...]<br /> |
