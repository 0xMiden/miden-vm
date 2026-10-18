# miden-air-source

Authored VM and precompile AIR equations, stable trace schemas, statement binding, fixed data,
and auxiliary-trace kernels. Ordinary relation types are `vm::Air` / `vm::MultiAir` and
`precompile::Air` / `precompile::MultiAir`. `tooling` adds AIR capture and ACE generation; it never
changes constraint evaluation. Production optimized evaluators and staged artifacts live in
`miden-air`.
