# Native Miden security arithmetic provenance

The security implementation in the parent directory adapts the numerical subset of published
`p3-security` 0.8.0, from Plonky3 commit
`a21e3ed42905040ad49c519e402f018381c12d0c` (upstream package path `security`).
The published archive SHA-256 is
`9c20542aa9e2a1249996d4cb0a461a236a58d2cf61fae712cec63c04b3765c03`.
[upstream.json](upstream.json) records exact input-file and license hashes. These identify the
independent upstream inputs; they are not hashes of the adapted native output.

The code is dual-licensed under the preserved [MIT](LICENSE-MIT) and
[Apache-2.0](LICENSE-APACHE) texts. Copyright (c) 2022 The Plonky3 Authors.
Local adaptations are also covered by the workspace license. Imported mathematical documentation
and references are retained with their owning operations.

| Native module | Independent upstream inputs | Local adaptation |
|---|---|---|
| `shape.rs` | `budget/shape.rs` | Own Miden numeric shapes; omit upstream AIR trait adapter. |
| `fixed.rs` | `fixed.rs` | Preserve const Q16 math and conservative rounding. |
| `budget.rs` | `budget/mod.rs` | Derive inputs from Miden PCS configuration; assemble hash/boundary-corrected named rounds directly. |
| `report.rs` | `budget/report.rs`, `report.rs`, `error.rs` | Preserve separate Q16 and proven report semantics, term ordering, ties and serialization. |
| `fri.rs` | `fri.rs` | Retain concrete FRI bounds/candidates; omit generic low-degree-test implementations and unsupported protocols. |
| `proximity.rs` | `proximity.rs`, required UDR/Johnson functions from `assumption.rs` | Keep the formulas required by Miden's FRI and opening batching. |
| `proven.rs` | `air.rs`, `deep.rs`, `stark.rs`, applied accounting from `grinding.rs` | Evaluate complete UDR/LDR reports with candidate-specific lookup and batching losses; omit generic extras/audit frameworks. |
| `testing.rs`, reference/test modules | `tests/budget_parity.rs` and relevant numerical unit cases | Preserve independent fixed/floating-point and regression comparisons; expose synthetic inputs only with test support. |

The general WHIR/hiding, binary, word, bus, multilinear, AIR inference, generic grinding-audit
and multi-protocol orchestration APIs are deliberately omitted. This is an adapted numerical
implementation for Miden, not a source-compatible replacement for the entire upstream crate.
No upstream AIR, commitment or field dependency is required by the extracted arithmetic.

The existing Miden wrapper supplies challenger support, commitment collision resistance,
lookup-boundary corrections, compiled relation geometry and actual FRI scheduling. Their
operation and rounding order are part of the compatibility contract; changing module ownership
does not establish numerical or protocol equivalence. Test execution remains subject to the
user's validation policy; compile-only checks must not be reported as numerical comparisons.
