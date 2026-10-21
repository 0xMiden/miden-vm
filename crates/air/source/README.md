# Miden AIR source

This crate contains the handwritten constraints and trace schemas used to author Miden AIRs.
The `vm` module describes the VM's four AIRs, public inputs, typed LogUp messages, and
auxiliary-trace construction. The `precompile` module describes the precompile VM's AIRs,
trace schemas, lookup messages, and fixed boundary contributions. Shared Eidos equations and
common geometry helpers live in `shared`.

`vm::MidenAir` evaluates handwritten constraints directly. The constraint compiler captures
these definitions to generate the evaluators consumed by `miden-air`; independent checks
compare the generated evaluators and degree metadata against this source. Production AIR
owns PCS presets, protocol IDs, and identity pins. Authored statement binding, input validation,
and external LogUp closure live in `vm::statement` and `precompile::statement`. Production
`MultiAir` implementations select generated evaluators and call these source functions; the
source crate does not define ordinary runtime `MultiAir` types.

The normal runtime does not include the ACE compiler. Enable `compiler` for symbolic capture,
relation compilation, and generation tooling. Production builds use these tools as host build
dependencies and embed compiled ACE instructions. Without default features, the authored AIRs
support `no_std` with `alloc`.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
