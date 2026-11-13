
## miden::core::sys::pvm::aux_trace
| Procedure | Description |
| ----------- | ------------- |
| scatter_aux_bus_boundary | Places the 12 proof-ordered sums in canonical AIR order for ACE and trace weighting.<br /><br />The map from AIR ids to proof positions must be staged, and the sums must already be absorbed.<br />All pairs are loaded onto the stack before any are stored back, so no separate buffer is needed.<br /><br />Input:  [...]<br />Output: [...]<br /> |
| observe_aux_trace | Samples lookup challenges, absorbs the auxiliary commitment and 12 normalized LogUp<br />sums in proof order, and checks the relation's external LogUp identity.<br /><br />Each canonical sum is weighted by its AIR's trace length. The relation's correction procedure<br />supplies the signed external contribution from the sampled challenges and statement.<br /><br />Requires the relation's boundary inputs, validated canonical heights, and a map from canonical<br />AIR ids to proof positions at PROOF_ORDER_POSITIONS_PTR. The challenger input buffer must be<br />empty. Leaves 4 input felts buffered and no cached challenger output.<br /><br />Input:  [...]<br />Output: [...]<br /> |
