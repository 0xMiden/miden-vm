# Miden VM AIR
This crate contains *algebraic intermediate representation* (AIR) of Miden VM execution logic.

AIR is a STARK-specific format of describing a computation. It consists of defining a set of constraints expressed as low-degree polynomials. Miden prover evaluates these polynomials over an execution trace produced by Miden processor and includes the results in the execution proof. To verify the proof, the verifier checks that the constraints are evaluated correctly against the execution trace committed to by the prover.

Miden VM is a four-AIR statement:

* `CoreAir` contains the [decoder](https://docs.miden.xyz/miden-vm/design/decoder), operand
  [stack](https://docs.miden.xyz/miden-vm/design/stack), and system constraints.
* `ChipletsAir` contains the stacked hash controller, bitwise, memory, ACE, and kernel-ROM
  chiplets.
* `EidosCompressionAir` proves the 32-row Eidos compression computations requested by the hash controller.
* `And8LookupAir` is a fixed byte-pair table for byte AND, Eidos compression rotation contributions, and
  [16-bit range checks](https://docs.miden.xyz/miden-vm/design/range).

These AIRs and their internal components are tied together with typed LogUp relations.

## Generated artifacts

Production VM constraint evaluation uses optimized Rust generated from the independent authored
AIR in `miden-air-source`. The package ships that exact source compressed in
`artifacts/vm-evaluator.rs.zlib`. A small host build script validates its checksum, decompressed
size and UTF-8, wraps it in its module, and writes `OUT_DIR/vm_evaluator.rs` for compilation.
Ordinary builds do not run AIR capture or optimization. The pure Rust decoder runs on the host
when cross compiling and adds no target `std` requirement.

Production VM/PVM `Air::degrees()` and `LiftedAir::constraint_degree()` read the small generated
`artifacts/{vm,precompile}-degrees.rs` tables. They preserve separate base/extension symbolic
degree multiples and do not run source evaluation. Independent tests compare every entry against
fresh symbolic evaluation of the authored equations. Both regeneration commands include these
tables; the artifact manifest records their hashes and sizes.

`Air::metadata()` reads `artifacts/{vm,precompile}-metadata.rs`: raw column widths,
base/extension constraint counts and lookup facts, with degrees supplied by `Air::degrees()`.
`vm::geometry`/`precompile::geometry` derive committed widths, quotient layout and security
shape from explicit nonempty AIR slices. Raw auxiliary widths are extension-valued; the distinct
committed-width type uses base coordinates after separate matrix padding. Checked const
arithmetic rejects overflow and invalid u32 shapes. Canonical security wrappers consume this
geometry; source helpers retain authored policy and independent symbolic shape oracles.

Canonical VM/PVM ACE circuits and their metadata also live in `artifacts/`; deliberately accepted
protocol identities remain in `protocol/accepted.json`. Generated verifier MASM stays checked
in under core-lib's existing `asm/sys/{vm,pvm}` paths for direct compiler consumption.

From the workspace root, `make regenerate-constraints` updates managed outputs and
`make check-constraints` checks their freshness. Follow the repository AC-power gate before Rust
compilation or tests. These commands check accepted pins without replacing them and preserve
independent authored-versus-production equivalence checks.

All AIR constraints for Miden VM are described in detail in the [design](https://docs.miden.xyz/miden-vm/design) section of Miden VM documentation.

If you'd like to learn more about AIR, the following blog posts from StarkWare are an excellent resource:

* [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
* [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
* [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
