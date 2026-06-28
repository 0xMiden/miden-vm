Keccak256 hash procedures.<br /><br />These procedures call `::miden::precompiles::crypto::hashes::keccak256` for hashing, event<br />handling, and deferred verification.<br />


## miden::core::crypto::hashes::keccak256
| Procedure | Description |
| ----------- | ------------- |
| hash_bytes | Computes Keccak256 hash of data stored in memory.<br /><br />Input: [ptr, len_bytes, ...]<br />Output: [DIGEST_U32[8], ...]<br /> |
| hash | Computes Keccak256 hash of a single 256-bit input.<br /><br />Input: [INPUT_U32[8], ...]<br />Output: [DIGEST_U32[8], ...]<br /> |
| merge | Merges two 256-bit digests via Keccak256 hash.<br /><br />Input: [INPUT_L_U32[8], INPUT_R_U32[8], ...]<br />Output: [DIGEST_U32[8], ...]<br /> |
