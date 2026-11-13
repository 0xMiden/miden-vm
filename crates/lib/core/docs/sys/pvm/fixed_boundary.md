
## miden::core::sys::pvm::fixed_boundary
| Procedure | Description |
| ----------- | ------------- |
| compute_fixed_boundary_correction | Sums the inverses of the compressed fixed-environment UintVal and EcGroup bus messages.<br /><br />Reads beta and alpha from the shared auxiliary-randomness region, stores the bus separator<br />in BUS_GAMMA_PTR, and returns the sum. Preserves caller stack elements and transcript state.<br />Fails if an encoded message denominator is zero.<br /><br />Input:  [...]<br />Output: [correction0, correction1, ...]<br /> |
