Random coin procedures for the STARK verifier.<br /><br />The `eidos_*` procedures implement the Eidos challenger. Unprefixed sampling and observe<br />helpers are recursive-verifier entry points over that state machine.<br /><br />Eidos challenger memory layout:<br />random_coin_cv_ptr          - 4-felt chaining value<br />random_coin_output_word_ptr - 4-felt output cache<br />random_coin_block_ptr       - 8-felt absorb block<br />random_coin_buffer_len_ptr  - position in the absorb block, 0..8<br />random_coin_counter_ptr     - 0 = absorbing; otherwise next counter-mode block index<br />random_coin_output_len_ptr  - felts left in the output cache, 0..4<br />


## miden::core::stark::random_coin
| Procedure | Description |
| ----------- | ------------- |
| eidos_enter_absorbing | Enter absorbing mode after an Eidos absorb.<br /><br />Input: [...]<br />Output: [...]<br /> |
| eidos_clear_buffer | Clear the generic Eidos absorb buffer.<br /><br />Input: [...]<br />Output: [...]<br /> |
| eidos_compress_block | Compress the block stored at `random_coin_block_ptr` into the Eidos chaining value.<br /><br />Input: [...]<br />Output: [...]<br /> |
| eidos_absorb_block | Absorb a fully specified 8-felt Eidos block.<br /><br />Input: [block_lo, block_hi, ...]<br />Output: [...]<br /> |
| eidos_observe_felt | Observe one felt through the generic Eidos streaming interface.<br /><br />Input: [value, ...]<br />Output: [...]<br /> |
| eidos_observe_word | Observe one word through the generic Eidos streaming interface.<br /><br />The fast path expects word-aligned transcript state (`buffer_len` 0 or 4), which is the shape<br />used by the recursive verifier except for proof-of-work witnesses.<br /><br />Input: [word, ...]<br />Output: [...]<br /> |
| eidos_observe_piped_words | Observe the top two stack words as one Eidos block without changing the stack.<br /><br />Intended for `adv_pipe` loops that must keep both piped words available.<br /> |
| eidos_absorb_word | Absorb one word as `[word, 0, 0, 0, 0]`.<br /><br />Input: [word, ...]<br />Output: [...]<br /> |
| eidos_absorb_main_trace_root | Absorb the main trace commitment root.<br /><br />Input: [root, ...]<br />Output: [...]<br /> |
| eidos_absorb_aux_trace_root | Absorb the auxiliary trace commitment root.<br /><br />Input: [root, ...]<br />Output: [...]<br /> |
| eidos_absorb_quotient_root | Absorb the quotient commitment root.<br /><br />Input: [root, ...]<br />Output: [...]<br /> |
| eidos_init_challenger | Initialize the Eidos challenger from a transcript-init CV and relation digest.<br /><br />Input: [relation_digest, transcript_init_cv, ...]<br />Output: [...]<br /> |
| eidos_refill_output_word | Refill the 4-felt Eidos output word.<br /><br />Input: [...]<br />Output: [...]<br /> |
| eidos_sample_felt | Sample one base field element from the Eidos transcript.<br /><br />Input: [...]<br />Output: [x, ...]<br /> |
| eidos_sample_ext | Sample one quadratic extension element from the Eidos transcript.<br /><br />Input: [...]<br />Output: [x0, x1, ...]<br /> |
| eidos_sample_bits | Sample bits from the Eidos transcript.<br /><br />Input: [bits, ...]<br />Output: [value, ...]<br /> |
| eidos_squeeze_word | Return the next full Eidos output word.<br /><br />Input: [...]<br />Output: [word, ...]<br /> |
| sample_felt | Sample a single base field element from the transcript.<br /><br />Input: [...]<br />Output: [x, ...]<br /> |
| sample_ext | Sample a quadratic extension field element from the transcript.<br /><br />Input: [...]<br />Output: [x0, x1, ...]<br /> |
| sample_bits | Sample a number of bits from the transcript.<br /><br />Input: [bits, ...]<br />Output: [value, ...]<br /> |
| observe_felt | Observe a single felt through the transcript stream.<br /><br />Input: [value, ...]<br />Output: [...]<br /> |
| init_seed | Initializes the Eidos Fiat-Shamir transcript, then derives trace domain parameters.<br /><br />RELATION_DIGEST is a compile-time tagged meta digest over all supported<br />proof-order ACE circuit commitments. The instance-specific wrapper stores it<br />in memory before calling the generic verifier.<br /><br />Currently assumes a blowup factor equal to 8.<br /><br />Precondition: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits,<br />RELATION_DIGEST, and per-AIR log heights must already be stored in memory before<br />calling this procedure.<br /><br />Input: [...]<br />Output: [...]<br /> |
| reseed_main_after_shape | Observe the main-trace commitment after statement shape binding.<br /><br />Input: [c0, c1, c2, c3, ...]<br />Output: [...]<br /> |
| reseed_with_felt | Observe a commitment word and stage the per-round PoW witness.<br /><br />Input: [felt, w0, w1, w2, w3, ...]<br />Output: [...]<br /> |
| reseed_direct | Observe one commitment word.<br /><br />Input: [w0, w1, w2, w3, ...]<br />Output: [...]<br /> |
| sample_folding_pow_and_ext | Verify per-round FRI folding proof-of-work and sample one extension field element.<br /><br />The folding PoW bit count is read from memory (set by load_security_params).<br />When folding_pow_bits=0 the check is trivially satisfied (mask=0).<br /><br />Equivalent to: `get_folding_pow_bits sample_bits assertz; sample_ext`<br /><br />Must be called immediately after `reseed_with_felt`; the witness is staged in `tmp3`.<br /><br />Input: [...]<br />Output: [a0, a1, ...]<br /> |
| generate_aux_randomness | Draw a list of random extension field elements related to the auxiliary segment of the execution<br />trace and store them.<br /><br />More specifically, we draw two challenges, alpha and beta. This means that our multi-set hash function<br />has the form `h(m) = alpha + \sum_{i=0}^{\|m\| - 1} m_i * beta^i` for a message `m`.<br /><br />As these random challenges have already been used non-deterministically in prior computations, we<br />also check that the generated challenges match the non-deterministically provided one.<br /><br />Input: [...]<br />Output: [...]<br /> |
| generate_constraint_composition_coefficients | Draw constraint composition random coefficient and save it at `compos_coef_ptr`.<br /><br />Input: [...]<br />Output: [...]<br /> |
| generate_deep_composition_random_coefficients | Draw deep composition polynomial random coefficient and save it at `deep_rand_coef_ptr`.<br /><br />As this random challenge has already been used non-deterministically in prior computations, we<br />also check that the generated challenge matches the non-deterministically provided one.<br /><br />Input: [...]<br />Output: [...]<br /> |
| generate_z_zN | Generate the OOD challenge point `z = (z0, z1)` and compute `z^N` where N is<br />the trace length. The resulting word `[(z_0, z_1)^N, z0, z1]` is stored in the<br />global memory address `exec.z_ptr` reserved for it.<br /><br />Input: [X, ...]<br />Output: [...]<br />Note: The top word on the stack is consumed by this procedure.<br /> |
| generate_list_indices | Generate a list of `num_queries` number of random indices in the range<br />[0, lde_size) and store it in memory starting from `query_ptr`.<br />The list is stored as `(index, depth, index, 0)` where `index` is the sampled domain-order<br />index and `depth` is `log(lde_domain_size)`, which is needed when computing the DEEP queries.<br /><br />Input: [...]<br />Output: [...]<br /> |
| check_deep_pow | Check the DEEP proof-of-work.<br /><br />Called before sampling DEEP composition polynomial challenges.<br /><br />Input: [...]<br />Output: [...]<br /> |
| check_query_pow | Check the query proof-of-work.<br /><br />Called after loading the FRI remainder, before sampling query indices.<br /><br />Input: [...]<br />Output: [...]<br /> |
