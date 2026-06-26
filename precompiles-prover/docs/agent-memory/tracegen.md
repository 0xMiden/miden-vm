# Trace-gen construction

Every chiplet's `generate_trace` builds its main trace the **same way** — the bitwise64 shape in
[`../../src/primitives/bitwise64.rs`](../../src/primitives/bitwise64.rs) is the reference:
`Vec::with_capacity(height · W)`, append each row, then `resize(height · W, ZERO)` (or extend
explicit padding rows when the tail isn't all-zero). The Vec's length *is* the running row counter;
there is no `trace[r·W + COL] = …` random access. This structurally enforces single-pass,
forward-only generation (a row can't be addressed out of order) and keeps every trace-gen one shape.

## Row assembly

The row is assembled one of two ways.

### Default: column-order `extend`

Append each field group in column order, so the source order of the extends *is* the layout:

```rust
values.extend(a.to_le_bytes().map(Felt::from)); // COL_A_BEGIN..
values.extend(b.to_le_bytes().map(Felt::from)); // COL_B_BEGIN..
values.extend([Felt::from(op.tag()), Felt::ONE, Felt::ZERO]); // op, is_logic, is_rol
```

Writing a row then reconciles trace-gen against the AIR's `COL_*` constants — a free standing
cross-check. The AIR indexes `COL_*`; trace-gen never does. This is the point of the convention; use
it wherever a row's set columns are written in a fixed order, even if many are zero (extend the
zeros explicitly). Pull a `push_row` helper out when the row shape recurs (node, poseidon2).

### Fallback: `[Felt; W]` scratch + named index, then `extend`

Use only for rows whose set columns **scatter by branch**, e.g. the sponge's per-lane `lo/hi` pairs
at non-adjacent columns + the `COL_B_BEGIN + …` byte-offset selector. Zero-init a stack `[Felt; W]`,
write the scattered columns by `COL_*` index, then `values.extend(scratch)`. The outer extend and
its forward-only guarantee are preserved; only the inner fill is index-based — honest, since there's
no column order to reconcile when columns genuinely scatter per branch.

## Bus routing and terminal trace-gen

Per-row bus `require`s — Range16 on `out_mult` / multiplicities, and cross-chiplet demand the rows
consume (a relation block's store lookups → the store's ledger, the round→bw64 pattern) — fire in
the same single pass, padding rows included. Free-standing `route_*` / `require_*_checks` companions
that re-iterate the records are not used; they double the witness derivation and can desync from the
laid rows.

`generate_trace` therefore **consumes its accumulator** by value — trace-gen is terminal. Laying
twice, which would double-route demand, is a compile error: the same move-only discipline as
`Truthy`. Read accumulator state (counts, recorded ops) before generating. Where the row index is
recovered from a record's allocated range (chunk `chunk_seq_id`, p2 cycle), `debug_assert!` the
running counter against that range so the forward-only assumption is checked, not just assumed.
