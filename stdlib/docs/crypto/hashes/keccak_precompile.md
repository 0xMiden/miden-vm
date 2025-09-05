
## std::crypto::hashes::keccak_precompile
| Procedure | Description |
| ----------- | ------------- |
| hash_mem | Computes Keccak256 hash of memory data via deferred computation.<br /><br />Input: [ptr, len_bytes, ...]<br />Output: [commitment, keccak_lo, keccak_hi, ...]<br /><br />Where:<br />- ptr: starting memory address (must be word-aligned)<br />- len_bytes: number of bytes to hash<br />- commitment: returned for future kernel tracking of deferred computations<br />- keccak_lo, keccak_hi: 256-bit digest as two words<br /> |
| merge_stack | Merges two 256-bit digests via Keccak256 hash.<br /><br />Input: [digest_left_lo, digest_left_hi, digest_right_lo, digest_right_hi, ...]<br />Output: [commitment, keccak_lo, keccak_hi, ...]<br /><br />Where:<br />- digest_left_lo/hi, digest_right_lo/hi: two digests to merge (as four words)<br />- commitment: returned for future kernel tracking of deferred computations<br />- keccak_lo, keccak_hi: Keccak256(left \|\| right) as two words<br /> |
