Generated MASM module for the SZ modmul_k1_base verifier.<br />DO NOT EDIT BY HAND. Regenerate via `cargo run -p miden-sz-codegen --bin regen`.<br />


## miden::core::math::u256_sz_modmul_k1_base
| Procedure | Description |
| ----------- | ------------- |
| modmul_k1_base | Schwartz-Zippel-based modmul_k1_base modular-multiplication verifier.<br /><br />Contract:<br />- Inputs are u256 values encoded as 8 u32 limbs. The proc assumes this limb<br />bound; callers must validate untrusted or advice-derived inputs before calling.<br />- On success, returns the canonical residue c = a * b mod m, with c < m.<br />- The standard witness handler is complete when floor(a * b / m) fits in u256.<br />This holds if either input is canonical (< m) and the other is a well-formed u256.<br />- Malformed or inconsistent advice traps.<br /><br />Main checked identity:<br />a(alpha) * b(alpha) - q(alpha) * p(alpha) - c(alpha) = (W - alpha) * (e_shifted(alpha) - offset(alpha))<br />at a Fiat-Shamir-derived alpha in the Miden base-field extension (W = 2^16).<br /> |
