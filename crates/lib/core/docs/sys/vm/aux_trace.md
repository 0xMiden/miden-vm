
## miden::core::sys::vm::aux_trace
| Procedure | Description |
| ----------- | ------------- |
| observe_aux_trace | Observes the auxiliary trace for the Miden VM AIR.<br /><br />Draws auxiliary randomness, reseeds the transcript with the auxiliary trace commitment,<br />and absorbs the boundary values (3 extension field elements = 6 base field elements).<br /><br />The advice provider supplies the commitment, then aux finals in proof order:<br />[commitment, aux0, aux1, aux2]<br /><br />The commitment is stored at aux_trace_com_ptr and the boundary values at<br />aux_bus_boundary_ptr.<br /><br />Precondition:  input_len=0 (guaranteed by the preceding reseed_direct in the generic verifier).<br />Postcondition: input_len=0, output_len=8.<br /><br />Input:  [...]<br />Output: [...]<br /> |
