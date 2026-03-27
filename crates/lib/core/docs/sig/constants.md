Memory layout and hardcoded parameters for the STARK-based signature verifier.<br /><br /># Variant: e2_105<br /><br />- Trace:     8 columns x 8 rows (RPO8 permutation: 7 rounds + input state)<br />- Code domain: \|D\| = 2048, blowup = 256 (= 2048 / 8)<br />- Extension: quadratic (e = 2), 128-bit challenge field<br />- Queries:   q = 53<br />- Mask degree: md = \|H\| + 2*(e+q) - 1 = 8 + 110 - 1 = 117<br />- Message size: ms = md + 1 = 118  (number of masked witness coefficients)<br />- Quotient:  7*md - 6 = 813 coefficients, segmented into 15 chunks of length 55<br />- Aux width: 15 chunks + 1 DEEP mask R = 16 committed EF columns<br /><br /># Sponge memory<br /><br />This verifier shares the Poseidon2 sponge memory region with `stark/constants.masm`<br />(R1_PTR, R2_PTR, C_PTR, output_len, input_len). It cannot coexist with a VM proof<br />verifier in the same execution context. Sig-specific storage lives in a separate<br />memory region starting at SIG_MEM_BASE.<br />


## miden::core::sig::constants
| Procedure | Description |
| ----------- | ------------- |
