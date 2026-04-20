# Chiplet interaction domain-separation investigation

## Problem statement

Today, all chiplet interactions share `BUS_CHIPLETS` as the outer domain separator (via
`challenges.bus_prefix[BUS_CHIPLETS]`), and rely on `label` in payload slot `β^0` to separate
interaction kinds.

This is explicit in the current `LookupMessage` encoders for:

- `HasherMsg`
- `MemoryMsg`
- `BitwiseMsg`
- `KernelRomMsg`
- `AceInitMsg`
- `MemoryResponseMsg`
- `KernelRomResponseMsg`
- `BitwiseResponseMsg`

Each encoder starts from `bus_prefix[BUS_CHIPLETS]` and then inserts a label (or op value) at
`β^0`.

## Current architecture constraints

1. `bus_types::CHIPLETS_BUS` is currently a *single* domain for all chiplet interactions.
2. The encoding contract for the shared chiplet bus says the payload begins with the operation
   label at `β^0`.
3. Other buses are already domain-separated by bus id and often do not require an additional label
   discriminator (e.g. `BUS_RANGE_CHECK`, `BUS_ACE_WIRING`).

This means chiplet interactions are not "first-class" bus domains in the same way as the other
buses.

## Direction: split `BUS_CHIPLETS` into per-interaction domains

To domain-separate each chiplet interaction individually and align with the rest of the bus
architecture, introduce **interaction-level bus ids** and treat each interaction family as its own
bus domain.

### Proposed interaction domains

The minimal practical split that preserves current semantics is:

- `BUS_CHIPLET_HASHER`
- `BUS_CHIPLET_MEMORY`
- `BUS_CHIPLET_BITWISE`
- `BUS_CHIPLET_ACE_INIT`
- `BUS_CHIPLET_KERNEL_ROM`

Optionally (for stricter unification):

- `BUS_CHIPLET_LOG_PRECOMPILE` (if we want to isolate log-precompile from hasher labels)
- `BUS_CHIPLET_ACE_MEMORY` (if we want ACE->memory requests to be independently namespaced)

## Two implementation variants

### Variant A (low-risk): keep labels, add per-interaction bus prefixes

- Keep current payload shape (`label` at `β^0`) unchanged.
- Only change the prefix bus id selected by each message type.
- Example: `HasherMsg::encode` uses `BUS_CHIPLET_HASHER`; `MemoryMsg::encode` uses
  `BUS_CHIPLET_MEMORY`.

Pros:

- Minimal algebraic risk.
- No transition-degree changes expected.
- Existing row-gating logic in request/response emitters can remain mostly unchanged.

Cons:

- Redundant discrimination (`bus_prefix` + `label`) remains for families with fixed shape.

### Variant B (full unification): remove discriminator labels where redundant

- Move separation responsibility entirely to bus id for interaction families where labels are only
  type tags.
- Keep labels only where they carry *semantic state* used by constraints (e.g. runtime muxed
  variants or operation-specific subtyping).

Pros:

- Cleaner and more uniform with label-free buses.
- Potentially smaller encoded messages for some families.

Cons:

- Requires coordinated updates to request and response emitters and proof compatibility logic.
- Higher migration risk.

## Recommended path

Implement **Variant A first**, then optionally collapse labels in a second pass.

This gets the requested per-interaction domain separation now, while keeping proof algebra and
constraint degree behavior close to current code.

## Concrete code touch points

### 1) Add new bus type constants

File: `air/src/trace/mod.rs` (`bus_types` module).

- Replace or deprecate single `CHIPLETS_BUS` usage in LogUp encoding paths.
- Add per-interaction bus ids and update `NUM_BUS_TYPES`.

### 2) Add bus-id compatibility aliases

File: `air/src/constraints/lookup/bus_id.rs`.

- Introduce aliases like `BUS_CHIPLET_HASHER`, `BUS_CHIPLET_MEMORY`, etc.
- Keep `BUS_CHIPLETS` temporarily as compatibility alias if needed during migration.

### 3) Repoint message encoders to interaction bus ids

File: `air/src/constraints/logup_msg.rs`.

Update `LookupMessage::encode` impls:

- `HasherMsg` -> `BUS_CHIPLET_HASHER`
- `MemoryMsg` and `MemoryResponseMsg` -> `BUS_CHIPLET_MEMORY`
- `BitwiseMsg` and `BitwiseResponseMsg` -> `BUS_CHIPLET_BITWISE`
- `KernelRomMsg` and `KernelRomResponseMsg` -> `BUS_CHIPLET_KERNEL_ROM`
- `AceInitMsg` -> `BUS_CHIPLET_ACE_INIT`

### 4) Keep emitters intact except for documentation and any mixed-bus comments

Files:

- `air/src/constraints/lookup/buses/chiplet_requests.rs`
- `air/src/constraints/lookup/buses/chiplet_responses.rs`
- `air/src/constraints/lookup/buses/hash_kernel.rs`

Because emitters construct typed message structs, most routing changes happen in message encoding,
not emitter gate logic.

### 5) Update lookup docs to reflect per-interaction chiplet buses

Files:

- `air/src/constraints/lookup/message.rs`
- comments in `air/src/trace/challenges.rs` and related lookup modules.

## Compatibility and risk notes

1. **Proof compatibility**: changing bus ids changes denominators, so proofs/witnesses are not
   backward-compatible across this change.
2. **Degree**: Variant A should preserve degrees; labels remain in-place.
3. **Hash-kernel C2 path**: ACE memory reads currently use `MemoryMsg` and therefore naturally move
   with memory-domain separation (good).
4. **Boundary assumptions**: any test/helper asserting only one chiplet bus id must be updated.

## Validation plan

1. Unit/property tests for each `LookupMessage::encode` implementation to assert expected bus
   prefix index.
2. Chiplet request/response bus closure tests (existing `processor/src/trace/tests/chiplets/*`)
   should continue to pass without semantic changes under Variant A.
3. Regenerate and compare degree audits / snapshots impacted by bus-id constants.

## Summary

A per-interaction bus-id split is feasible with low risk by changing only message-to-bus routing in
`LookupMessage::encode` and extending `bus_types`. This satisfies per-interaction domain separation
and aligns chiplet interactions with the same domain-separation model used by other buses.
