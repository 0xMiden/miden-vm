# Independent native AIR observations

`FORMAT.md` is the independently authored observation contract.
`../../native_air_reference.rs` contains the base-interface observer and read-only
comparisons. It uses authored sources and compiler entrypoints; generated
constraint evaluators and embedded ACE instruction streams are not its oracle.

The three supplied files are preserved unchanged:

| File | SHA-256 |
|---|---|
| `reference.txt` | `2ffa5cda0fec36c05d4e1e5a6ba88df3533043065d2bf0bce739d0aae90f7581` |
| `coverage.txt` | `d9c6a8d6fdc71857ec9a43a0009e8f4bb4e4fa1cd7136251c74437a1c67d4e96` |
| `PROVENANCE.md` | `c1aea0c8a7490f263c28ae62481b7bdbf7cc8ed68010c371fc17ea950380f38e` |

Historical producer/observer/lock labels in those files describe the handoff's
attribution. Their source objects were not opened. The frozen digest framing,
complete historical auxiliary inputs and synthetic coverage body are not
provided, so opaque hashes, historical Horner samples, auxiliary outputs and
coverage records are explicitly excluded from claimed comparisons. See the
usage map and exact new v1 recipe in FORMAT.md.

The metadata comparison enforces the full ordered4VM/12PVM registry, dimensions,
period lengths and assertion counts. The protocol comparison independently
rebuilds source ACE circuits and fixed setup trees, compares explicit
commitments/identities/shapes, and derives PVM raw widths and quotient chunks.
It does not establish Fiat-Shamir call order or all polynomial/witness behavior.

No test, observer or benchmark has been executed during authoring. No new
numerical baseline has been captured. The ignored print-only observer has no
file-writing or environment-controlled regeneration mode. Its eventual baseline
must come from the first observer commit, before any production equation/API
migration, with the exact commit/toolchain/lock hash recorded. Execution requires
separate authorization and the user's power guards; the standing no-tests
request remains active. Never regenerate expectations from a later migrated
implementation to make comparisons pass.
