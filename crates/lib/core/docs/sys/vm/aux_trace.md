
## miden::core::sys::vm::aux_trace
| Procedure | Description |
| ----------- | ------------- |
| observe_aux_trace | Observes the auxiliary trace for the Miden VM AIR.<br /><br />Draws auxiliary randomness, reseeds the transcript with the auxiliary trace commitment,<br />and absorbs the 4 words of auxiliary trace boundary values (8 aux columns, each an<br />extension field element = 16 base field elements = 4 words).<br /><br />The advice provider must supply exactly 5 words in order:<br />[commitment, W0, W1, W2, W3]<br /><br />The commitment is stored at aux_trace_com_ptr and the boundary values at<br />aux_bus_boundary_ptr (sequentially).<br /><br />Precondition:  input_len=0 (guaranteed by the preceding reseed_direct in the generic verifier).<br />Postcondition: input_len=0, output_len=8.<br /><br />Input:  [...]<br />Output: [...]<br /> |
