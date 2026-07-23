
## miden::core::sys::vm::claim
| Procedure | Description |
| ----------- | ------------- |
| claim_hash | Computes the canonical claim commitment (CLAIM_HASH) over a claim region.<br /><br />The region must hold the fully populated 40-felt claim encoding P ‖ K ‖ I ‖ O. This procedure<br />is pure: it does not verify anything, it only names the claim. It is the value used to form<br />proof-request keys and to bind verified claims into a consumer's own statement.<br /><br />Inputs:  [claim_ptr, ...]<br />Outputs: [CLAIM_HASH, ...]<br /><br />Where:<br />- claim_ptr is the word-aligned address of the claim region.<br />- CLAIM_HASH is the domain-tagged Poseidon2 hash of the 40-element encoding.<br /> |
