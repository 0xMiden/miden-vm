
## miden::core::sys::vm::claim
| Procedure | Description |
| ----------- | ------------- |
| materialize_claim | Fetches a claim preimage from the advice map, copies it into memory, and checks its commitment.<br /><br />The advice-map value under CLAIM_COMMITMENT must be the canonical 40-felt claim encoding.<br /><br />Inputs:  [claim_ptr, CLAIM_COMMITMENT, ...]<br />Outputs: [...]<br /> |
| claim_commitment | Computes the canonical claim commitment (CLAIM_HASH) over a claim region.<br /><br />The region must hold the fully populated 40-felt claim encoding P ‖ K ‖ I ‖ O. The commitment<br />names the claim: it forms proof-request keys and binds verified claims into a consumer's own<br />statement. The procedure verifies nothing.<br /><br />Inputs:  [claim_ptr, ...]<br />Outputs: [CLAIM_HASH, ...]<br /><br />Where:<br />- claim_ptr is the word-aligned address of the claim region.<br />- CLAIM_HASH is the domain-tagged Poseidon2 hash of the 40-element encoding.<br /> |
