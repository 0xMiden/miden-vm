Keccak256 precompile wrapper using event handling for efficient computation.<br /><br />This module provides a wrapper function around the keccak precompile event handler,<br />allowing efficient keccak256 computation by deferring to the native verifier.<br />


## std::crypto::hashes::keccak_precompile
| Procedure | Description |
| ----------- | ------------- |
| keccak256_precompile | Compute keccak256 hash using precompile event handler.<br /><br />This function takes a memory slice as input, computes its keccak256 hash using the<br />precompile event handler, writes the hash to the specified output location, and<br />returns a cryptographic commitment to the precompile call on the stack.<br /><br />The commitment is computed as RPO([RPO(input), RPO(keccak256(input))]) and can be<br />used for proof verification and precompile call validation.<br /><br />Expected stack state:<br />[ptr, len, ...]<br /><br />Final stack state:<br />[commitment, keccak_hi, keccak_lo, ...]<br /><br />Where:<br />- ptr:             memory address where input bytes start<br />- len:             number of bytes to hash<br />- commitment:      RPO hash of [RPO(input), RPO(keccak256(input))]<br />- keccak_{hi, lo}: words todo<br /> |
