# miden-air-source

Authored VM and precompile AIR equations, stable trace schemas, statement binding, fixed data,
and auxiliary-trace kernels. Ordinary relation types are `vm::Air` / `vm::MultiAir` and
`precompile::Air` / `precompile::MultiAir`. `tooling` adds AIR capture and ACE generation; it never
changes constraint evaluation. Production optimized evaluators and staged artifacts live in
`miden-air`.

`metadata` supplies lower const geometry types without any generated/product dependency.
Source security provides `*_with_shape` helpers plus independent full-relation symbolic oracles;
canonical const shape/security wrappers live in production `miden-air`. Raw source width/schema
accessors and default symbolic degrees remain independent of generated tables. Source tooling
captures counts/degrees and emits the small production metadata tables as well as the existing
artifacts. Memory models remain here for processor consumers.
