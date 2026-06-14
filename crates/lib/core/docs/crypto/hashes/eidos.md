BlakeG compression helpers used by Eidos.<br /><br />State layout is `[BLOCK_LO, BLOCK_HI, CV]`, three words on the stack.<br />


## miden::core::crypto::hashes::eidos
| Procedure | Description |
| ----------- | ------------- |
| compress | Performs one BlakeG compression.<br /><br />Input:  [BLOCK_LO, BLOCK_HI, CV, ...]<br />Output: [BLOCK_LO, BLOCK_HI, DIGEST, ...]<br /> |
| digest | Extracts the digest from a post-compression state.<br /><br />Input:  [BLOCK_LO, BLOCK_HI, DIGEST, ...]<br />Output: [DIGEST, ...]<br /> |
