# Pinned p3-security with an optional upstream AIR adapter

This is the published `p3-security` 0.8.0 source from the exact registry archive
identified in [provenance.json](provenance.json). Its numerical security types,
functions, formulas and published test source are retained unchanged. Miden
supplies checked native AIR metadata to that existing numerical API.

The upstream convenience method `StarkAirParams::from_air` depends on upstream
AIR traits and symbolic inference. The `upstream-air` feature gates only that
method's impl/imports and enables optional `p3-air` and `p3-commit` dependencies.
It is enabled by default, preserving the published crate's default API. Miden's
workspace dependency disables default features, so it uses numerical security
APIs without that adapter. `src/air.rs` is numerical composition-error analysis
and remains unconditional; its module name does not denote the retired AIR
trait integration.

The patch is limited to three published files:

- `Cargo.toml`: add the default-enabled feature and mark its two adapter
  dependencies optional.
- `src/shape.rs`: add feature attributes to four adapter import items and the
  unchanged `StarkAirParams::from_air` impl. The two public shape structs and
  every method-body expression retain their published bytes.
- `src/lib.rs`: describe the optional adapter in the dependency diagram;
  executable code is unchanged.

`Cargo.toml.upstream` preserves the original normalized published manifest.
`Cargo.toml.orig` preserves the published workspace-style source manifest.
`upstream-vcs-info.json` preserves the archive's VCS metadata. The source is
pinned to Plonky3 commit `a21e3ed42905040ad49c519e402f018381c12d0c`, package path
`security`. The archive contains no README or license texts. This README is
local; the MIT and Apache-2.0 texts are copied from the independently retained
same-commit upstream license inputs, whose exact hashes and URLs are recorded
in provenance. Registry installation/checksum artifacts are not included.

The provenance record distinguishes upstream input hashes from local patched
output hashes for every copied published file. Static integrity checking is
not a numerical security or protocol-equivalence test. No compiler, linter,
formatter, tests, benchmark, proof, observer or numerical comparison was run
while authoring this patch. Workspace dependency/lock wiring and subsequent
focused checks belong to the parent integration step. Keep the untouched
numeric files in their published form rather than formatting this vendor tree.

This code is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), matching the pinned upstream package metadata.
