# Workflow preferences

## Non-trivial structural changes

For non-trivial structural changes — e.g. σ/n adoption, the `*Requires → *Prover` split, ROL, the
`LookupAir` migration, the `Bitwise64Requires` HashMap rework — use a **plan-confirm-implement**
loop.

State the proposed shape before implementing:

- selector encoding
- aux column layout
- constraint degrees
- IR changes
- secondary consequences and edge cases

Wait for confirmation before implementation. Surface secondary consequences before locking in, such
as the dummy-LOGIC problem when ROL came up, or the ROL `s < 31` bound when the `+2³²` offset trick
was re-audited.

## After a feature lands

The user often asks for a **denoise pass** after a feature lands. Good targets:

- over-eager rustdoc
- dead helpers
- vestigial parameters
- historical commentary
- redundant trait bounds

Worth proposing when a feature or refactor is otherwise complete.
