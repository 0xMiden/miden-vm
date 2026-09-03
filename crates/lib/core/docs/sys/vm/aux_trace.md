
## miden::core::sys::vm::aux_trace
| Procedure | Description |
| ----------- | ------------- |
| push_proof_order_log_heights | Push the four AIR log heights in the same proof order as the absorbed auxiliary boundary values.<br /><br />`ORDER_TAG` is the Lehmer rank of the proof-order permutation over<br />[Core, Chiplets, EidosCompression, And8Lookup].<br />The AIR set is fixed, so direct dispatch loads each height once instead of rescanning the<br />height array for every output position.<br /><br />Input:  [...]<br />Output: [log_0, log_1, log_2, log_3, ...]<br /> |
| observe_aux_trace | Observes the auxiliary trace for the Miden VM AIR.<br /><br />Draws auxiliary randomness, absorbs the auxiliary trace commitment and four normalized<br />boundary sums, then checks the modeless outer-LogUp boundary identity.<br /><br />The advice provider supplies:<br />[commitment, sigma_prime_0, sigma_prime_1, sigma_prime_2, sigma_prime_3]<br /><br />Input:  [...]<br />Output: [...]<br /> |
