# Miden AIR definitions

This crate contains the handwritten constraints and trace schemas used to author Miden AIRs.
The `vm` module describes the VM's four AIRs, public inputs, typed LogUp messages, and
auxiliary-trace construction. The `precompiles` module describes the precompile VM's AIRs,
trace schemas, lookup messages, and fixed boundary contributions. `shared::eidos` owns the
common compression equations, physical layout, lookup encoding, and trace coordinates. VM and
precompile adapters supply their bus mappings and controller, AEAD, or transcript interfaces.
Common geometry helpers also live in `shared`.

Authored equations implement `miden_stark::air::LiftedAir`; concrete auxiliary witnesses
implement `ProverAir<EF>`. Setup owns fixed matrices and lends them to witness construction.
See the [AIR API](../../stark/core/README.md#air-api) and
[generated runtime wrappers](../generated/README.md).

`vm::MidenAir` evaluates handwritten constraints directly. The constraint compiler captures
these definitions to generate the evaluators consumed by `miden-air`; independent checks
compare the generated evaluators and degree metadata against this source. Production AIR
owns PCS presets, protocol IDs, and identity pins. Authored statement binding, input validation,
and external LogUp closure live in `vm::statement` and `precompiles::statement`. Production
`MultiAir` implementations select generated evaluators and call these source functions; the
source crate does not define ordinary runtime `MultiAir` types.

The normal runtime does not include the ACE compiler. Enable `compiler` for symbolic capture,
relation compilation, and generation tooling in `compiler::vm` and `compiler::precompiles`. Production builds use these tools as host build
dependencies and embed compiled ACE instructions. Without default features, the authored AIRs
support `no_std` with `alloc`.

## Testing AIRs

Test standalone and composed AIRs through their complete evaluators on valid traces with active
lookups. For optimized evaluators, compare constraint values and assertion order with the
authored evaluator on arbitrary field assignments.

## Writing constraints

Use the builder method that states the obligation: `assert_eq`, `assert_one`, and their array
and extension variants express equalities directly. Use `assert_bool` or `assert_bools` for the
canonical Boolean polynomial `x * (x - 1)`; use `.bool_check()` when that polynomial is part of
another equation. Name common gates and use `when(gate)` around related obligations. Array
assertions preserve independent constraints in element order; never replace them with one
assertion on their sum.

Write mathematical reductions with `.map(...).sum()` or `sum_array`. Use `dot_product` for
homogeneous weighted sums and `Algebra<Base>::mixed_dot_product` for algebra values with base
coefficients. Keep coefficients and gates in the narrowest available domain. Factor a repeated
extension value through a sum of base gates, and group subtraction tails into a positive sum or
an equality when that makes the equation easier to audit.

Use ring operations such as `.square()`, `.double()`, and `.mul_2exp_u64()` to retain their meaning
in symbolic capture. Preserve useful shared prefixes, readable Horner forms, and independently
derived reference equations. Uniform subexpressions depend only on constants, public values,
challenges, and exports; trace values and row selectors remain row-dependent even when named.
Explicit algebra operations expose intent, while generated-code comparisons and measurements
determine whether a scheduling change improves evaluation.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
