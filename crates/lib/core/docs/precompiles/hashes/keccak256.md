
## miden::core::precompiles::hashes::keccak256
| Procedure | Description |
| ----------- | ------------- |
| hash_bytes_mem | Low-level deferred Keccak256 assertion over memory.<br /><br />Input:  [in_ptr, len_bytes, out_ptr, ...]<br />Output: [...]  (DIGEST_U32[8] = Keccak256(INPUT_U8[len_bytes]) written to out_ptr)<br /><br />Where:<br />- in_ptr:   word-aligned address holding INPUT_U32[⌈len_bytes/4⌉] (unused bytes in the final u32<br />and any remaining felts in the final 32-byte CHUNKS block must be 0)<br />- len_bytes: number of bytes to hash<br />- out_ptr:  word-aligned destination for DIGEST_U32[8]<br /><br />Advice is untrusted: the advised digest is bound by the logged generic hash assertion.<br /> |
| hash_1_chunk_mem | Low-level deferred Keccak256 assertion over exactly one 32-byte CHUNKS block.<br /><br />Input:  [in_ptr, len_bytes, out_ptr, ...]<br />Output: [...]  (DIGEST_U32[8] = Keccak256(INPUT_U8[len_bytes]) written to out_ptr)<br /> |
| hash_2_chunks_mem | Low-level deferred Keccak256 assertion over exactly two contiguous 32-byte CHUNKS blocks.<br /><br />Input:  [in_ptr, len_bytes, out_ptr, ...]<br />Output: [...]  (DIGEST_U32[8] = Keccak256(INPUT_U8[len_bytes]) written to out_ptr)<br /> |
