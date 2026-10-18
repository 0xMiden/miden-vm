# miden-air-source

Authored VM and precompile AIR equations, stable trace schemas, statement binding, fixed data,
and auxiliary-trace kernels. Ordinary relation types are `vm::Air` / `vm::MultiAir` and
`precompile::Air` / `precompile::MultiAir`. `tooling` adds AIR capture, ACE generation, and Askama-based MASM rendering; it never
changes constraint evaluation. Production optimized evaluators and staged artifacts live in
`miden-air`.

`metadata` supplies lower const geometry types without any generated/product dependency.
Source security provides `*_with_shape` helpers plus independent full-relation symbolic oracles;
canonical const shape/security wrappers live in production `miden-air`. Raw source width/schema
accessors and default symbolic degrees remain independent of generated tables. Source tooling
captures counts/degrees and emits the small production metadata tables as well as the existing
artifacts. Memory models remain here for processor consumers.

Verifier templates live in `templates/verifier`; typed compilation adapters and pure rendering live
in `src/codegen`. `codegen::render_and_validate` prepares the complete batch without writes.
Core's explicit developer command checks or delivers it:

```sh
cargo run -p miden-core-lib-codegen --features air --bin verifier-codegen -- <workspace-root> --check
```

`--write` updates all managed MASM/evaluator/table outputs after accepted/protected and destination
preflight, without accepting protocol pins. Core-lib's ordinary build assembles tracked MASM and
does not enable AIR tooling. Embedded `air-codegen` command hints retain their pre-cutover bytes;
use the command above or the workspace Make targets. The separate `air-artifacts` CLI retains its
explicit accepted-file/artifact-directory contract and independent transport validation.

The compiler adapters derive rendering metadata from ACE's compiler-only `CompiledCircuit`,
which retains the encoding, originating READ layout and cached commitment together. Code-owned
ACE builders, compiler adapters and rendering/planning return values directly and panic on
invariant violations. Destination and accepted-input validation retain their fallible contracts. New authored
PVM glue shapes use release assertions. Typed plans/templates derive canonical height rules,
one-per-AIR boundary slots, fixed message pushes, statement counts and transcript remainders;
VM custom claim observation remains separate. The generated PVM aux/public hooks stay tracked
in core-lib and are included in full-source freshness checks. Ordinary
production builds continue to decode the precompiled canonical ACE artifacts.

See the workspace [MASM generation guide](../../../docs/masm-verifier-generation.md) for ownership,
the clean-room migration, compatibility checks, and protected-file policy.

PVM `MultiAir::with_variant` selects canonical optional hash AIRs while retaining Eidos, transcript,
uint, curve and lookup support. Tooling captures the exact selected slice, including its periodic
basis. `codegen::pvm_variants` renders seven internal selected wrapper/layout pairs from the same typed templates
as ALL; every wrapper remains protected/check-only. Initial creation and identity acceptance are
explicit feature updates; ordinary generation rejects missing or drifted wrappers before managed
writes. All eight canonical ACE streams are packaged in `miden-air`, with explicit accepted JSON
identities and manifest fingerprints.

Consolidated runtime generation emits `sys::verifier` once across VM and all eight PVM masks.
Reduced selections retain only wrapper/layout modules; full VM/PVM module paths provide explicit
standalone adapters. One named 80-felt ABI map generates trusted field constants and complete
per-invocation stagers. Shared count/width kernels preserve transcript order and fixed stack frames.
The core developer command completes global accepted/protected preflight before any managed write;
obsolete reduced algorithm copies reject explicitly. No runtime/ordinary build enables tooling.
Actual assembled roots are accepted separately from frozen circuit/relation/setup/ACE/evaluator
identities and native ALL payload compatibility.
