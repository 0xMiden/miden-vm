
## miden::core::precompiles::curves::secp256k1
| Procedure | Description |
| ----------- | ------------- |
| load_digest_pair | Constructs an affine curve VALUE node from two coordinate digests.<br />Input:  [X_DIGEST, Y_DIGEST, ...]<br />Output: [POINT_DIGEST, ...]<br /> |
| load_digest_pair_mem_stream | Loads two registered coordinate digests from memory, returning point digest and advanced pointer.<br />Input:  [ptr, ...]<br />Output: [POINT_DIGEST, ptr+8, ...]<br />Memory layout: ptr[0..4] = X_DIGEST, ptr[4..8] = Y_DIGEST.<br /> |
| load_digest_pair_mem | Loads two registered coordinate digests from memory and returns the point digest.<br />Input:  [ptr, ...]<br />Output: [POINT_DIGEST, ...]<br /> |
| load_mem_stream | Loads two consecutive base-field elements from memory as an affine point.<br />Input:  [ptr, ...]<br />Output: [POINT_DIGEST, ptr+16, ...]<br />Memory layout: ptr[0..8] = X_U32[8], ptr[8..16] = Y_U32[8].<br /> |
| load_mem | Loads two consecutive base-field elements from memory as an affine point.<br />Input:  [ptr, ...]<br />Output: [POINT_DIGEST, ...]<br /> |
| push_identity | Pushes the registered digest of the curve identity point.<br /> |
| push_generator | Pushes the registered digest of the conventional curve generator.<br /> |
| add | Registers `lhs + rhs` and returns the result expression digest.<br />Input:  [LHS_DIGEST, RHS_DIGEST, ...]<br />Output: [SUM_DIGEST, ...]<br /> |
| sub | Registers `lhs - rhs` and returns the result expression digest.<br />Input:  [LHS_DIGEST, RHS_DIGEST, ...]<br />Output: [DIFF_DIGEST, ...]<br /> |
| mul_scalar | Registers `[k]point` for a scalar-field digest.<br />Input:  [POINT_DIGEST, SCALAR_DIGEST, ...]<br />Output: [PRODUCT_POINT_DIGEST, ...]<br /> |
| mul_scalar_generator | Registers `[k]GENERATOR` for a scalar-field digest.<br />Input:  [SCALAR_DIGEST, ...]<br />Output: [PRODUCT_POINT_DIGEST, ...]<br /> |
| msm_mem | Registers an MSM PairList staged in memory.<br />Input:  [ptr, n, ...]<br />Output: [MSM_POINT_DIGEST, ...]<br />Memory layout: pair i at ptr + 8*i is `[POINT_DIGEST, SCALAR_DIGEST]`.<br /> |
| msm2 | Registers a two-pair MSM from stack operands.<br />Input:  [POINT0_DIGEST, SCALAR0_DIGEST, POINT1_DIGEST, SCALAR1_DIGEST, ...]<br />Output: [MSM_POINT_DIGEST, ...]<br /> |
| msm2_generator | Registers `[scalar0]GENERATOR + [scalar1]point1` as a two-pair MSM.<br />Input:  [SCALAR0_DIGEST, SCALAR1_DIGEST, POINT1_DIGEST, ...]<br />Output: [MSM_POINT_DIGEST, ...]<br /> |
| assert_eq | Asserts two curve expressions are equal by logging an EQ predicate into the deferred root.<br />Input:  [LHS_DIGEST, RHS_DIGEST, ...]<br />Output: [...]<br /> |
| eval | Evaluates a curve expression and binds the advised canonical VALUE payload to the input digest.<br />Input:  [POINT_EXPR_DIGEST, ...]<br />Output: [POINT_VALUE_DIGEST, X_OR_TRUE_DIGEST, Y_OR_TRUE_DIGEST, ...]<br />Advice is untrusted. This wrapper re-hashes the advised VALUE payload with the registered VALUE_TAG and<br />logs `eq(EXPR_DIGEST, VALUE_DIGEST)` before returning the value digest and coordinate digests.<br /> |
| is_eq | Evaluates two curve expression digests and returns whether their canonical VALUE digests match.<br />Input:  [LHS_DIGEST, RHS_DIGEST, ...]<br />Output: [is_equal, ...]<br /> |
| is_eq_digest | Evaluates a curve expression digest and returns whether its canonical VALUE digest matches target.<br />Input:  [TARGET_DIGEST, EXPR_DIGEST, ...]<br />Output: [is_equal, ...]<br /> |
| is_identity | Evaluates a curve expression and returns whether it is the identity point.<br />Input:  [POINT_DIGEST, ...]<br />Output: [is_identity, ...]<br /> |
| assert_eq_digest | Asserts a curve expression equals a target curve expression by logging an EQ predicate.<br />Input:  [TARGET_DIGEST, EXPR_DIGEST, ...]<br />Output: [...]<br /> |
| assert_identity | Asserts a curve expression is the identity point.<br />Input:  [POINT_DIGEST, ...]<br />Output: [...]<br /> |
| assert_not_identity | Evaluates a curve expression and asserts it is not the identity point.<br />Input:  [POINT_DIGEST, ...]<br />Output: [...]<br /> |
| neg | Negates a point by computing O - P.<br />Input:  [POINT_DIGEST, ...]<br />Output: [NEG_POINT_DIGEST, ...]<br /> |
| double | Doubles a point by computing P + P.<br />Input:  [POINT_DIGEST, ...]<br />Output: [DOUBLE_POINT_DIGEST, ...]<br /> |
