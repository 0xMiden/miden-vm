# Changelog

## v0.25.0 (TBD)

#### Changes

- Added the `miden-precompiles` crate as the home for concrete deferred precompile implementations,
  built on top of the deferred framework in `miden_core::deferred`
  ([#3170](https://github.com/0xMiden/miden-vm/pull/3170)).
- Added the `miden-precompiles` MASM package (namespace `miden::precompiles`) and the
  `PrecompilesLibrary` wrapper that embeds and loads it, with shared deferred-DAG helpers exported
  from the root `miden::precompiles` module.
