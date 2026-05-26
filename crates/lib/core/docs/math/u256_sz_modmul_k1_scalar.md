Generated MASM module for the SZ modmul_k1_scalar verifier.<br />DO NOT EDIT BY HAND. Regenerate via `cargo run -p miden-sz-codegen --bin regen`.<br />


## miden::core::math::u256_sz_modmul_k1_scalar
| Procedure | Description |
| ----------- | ------------- |
| modmul_k1_scalar | Schwartz-Zippel-based modmul_k1_scalar modular-multiplication verifier.<br />Main checked identity:<br />a(alpha) * b(alpha) - q(alpha) * n(alpha) - c(alpha) = (W - alpha) * (e_shifted(alpha) - offset(alpha))<br />at a Fiat-Shamir-derived alpha in the Miden base-field extension (W = 2^16).<br /> |
