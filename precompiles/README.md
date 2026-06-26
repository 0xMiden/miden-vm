# Miden precompiles

This crate is the home for official deferred precompile implementations for the Miden VM.

At this point in the history stack, the crate is intentionally a scaffold: it reserves the
`miden::precompiles` MASM namespace, embeds that package at build time, and exposes an empty
`PrecompileRegistry`. Concrete hash, arithmetic, curve, and signature precompiles are added in later
commits.
