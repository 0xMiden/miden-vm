# Poseidon2 permutation chiplet

> **AIR reference:** [`airs/poseidon2.md`](../airs/poseidon2.md) — complete column / constraint / bus reference for this chiplet.

A standalone Poseidon2-f[12] permutation, exposed exclusively over
LogUp. One permutation per 16-row cycle; in-trace absorption chains
carry capacity through structural constraints rather than the bus.
Implemented in [`src/transcript/poseidon2/`](../../src/transcript/poseidon2/).

Algorithm and packed schedule are ported from
[`miden-vm`'s hasher chiplet (perm sub-chiplet)](https://github.com/0xMiden/miden-vm/tree/3176d1f/air/src/constraints/chiplets/permutation);
the surface area is reshaped to drop the controller bridge that Miden
uses to pair `(state_in, state_out)`, replacing it with `perm_seq_id`-tagged
bus tuples and an `is_absorb` chain selector.

## Architecture

- **One permutation = one 16-row cycle.** Same packed schedule as
  Miden: 8 external rounds + 22 internal rounds folded into 16 rows
  by merging the linear-layer init with ext1 (row 0), packing 3
  internal rounds per row using S-box-output witnesses for lane 0
  (rows 4–10), merging int22 with ext5 (row 11), and leaving row 15
  as the cycle-final (no-transition) boundary.
- **State is 12 Goldilocks felts, laid out as
  `[rate0[4], rate1[4], capacity[4]]`.** `rate0` doubles as the digest
  on output. The chiplet treats all 12 lanes uniformly — rate / capacity
  is just labelling for the caller's purposes.
- **Two LogUp buses.** `Poseidon2In` carries per-cycle input chunks
  with a 0/1/2 tag (`rate0` / `rate1` / `capacity`); `Poseidon2Out`
  carries the post-permutation digest (`rate0`). Tuples include a
  cycle-constant `perm_seq_id` so chunk-mixing across distinct permutations
  is foreclosed.
- **Absorption chains are in-trace.** A cycle marked `is_absorb = 1`
  inherits its input capacity from the previous cycle's row-15
  capacity via a transition constraint — neither cycle publishes the
  intermediate capacity to the bus. The chain head (`is_absorb = 0`)
  is the only cycle that needs an `InCap` consume from the caller,
  and only the chain tail (`is_absorb_next = 0`) publishes its
  `OutRate0` digest.
- **Split multiplicity (in / out).** `in_multiplicity` counts
  caller-side consumes of the In-side bus messages (`InCap`,
  `InRate0`, `InRate1`); `out_multiplicity` counts consumes of the
  digest on `OutRate0`. For content-addressed-DAG patterns
  `out_multiplicity` typically exceeds `in_multiplicity` (one
  creator, many readers). Both are committed cycle-constant `usize`
  counts — **not** range-checked: each is pinned to its bus's consumer
  count by balance, and every consumer consumes with a constant `+1`
  weight (the VM-wide fixed-consume invariant, see
  [`../lookup-argument.md`](../lookup-argument.md)), so a "negative
  felt" can't satisfy balance. True dedup, no `2^16` cap, no spill.
- **Sum gate against fake digests.** Step transitions are gated by
  `activity = (in_multiplicity + out_multiplicity) · selector`. Any
  cycle with bus emissions on either side runs the real Poseidon2
  chain, so every published digest is a genuine permutation output of
  the prover-committed row-0 state. The gate can't be wrapped to
  `activity ≡ 0` on a live cycle: balance pins each summand to a real
  small consumer count (`< trace height ≪ p`), so `activity = 0` ⟺
  genuine padding. Targeted-digest forgery requires breaking Poseidon2
  preimage resistance.

## Parameters

| Parameter | Value |
|---|---|
| Field | Goldilocks (p = 2⁶⁴ − 2³² + 1) |
| State width | 12 |
| S-box | `x⁷` |
| External rounds | 8 (4 initial + 4 terminal) |
| Internal rounds | 22 |
| `M_E` | Per-block M4 + cross-block sums |
| `M_I` | `I + diag(MAT_DIAG)` |

`MAT_DIAG`, `ARK_EXT_INITIAL`, `ARK_EXT_TERMINAL`, `ARK_INT[0..22]`
are imported from `miden_core::chiplets::hasher::Hasher`.

## Packed 16-row schedule

| Row | Step | Selector | Constraint deg | Witness use |
|---|---|---|---|---|
| 0 | init + ext1: `h' = M_E(S(M_E(h) + ark))` | `is_init_ext` | 9 | none |
| 1–3 | single ext: `h' = M_E(S(h + ark))` | `is_ext` | 9 | none |
| 4–10 | 3× internal packed | `is_packed_int` | 9 (witness), 3 (next-state) | `w0, w1, w2` = sbox outs |
| 11 | int22 + ext5 (`ARK_INT[21]` hardcoded) | `is_int_ext` | 9 | `w0` |
| 12–14 | single ext | `is_ext` | 9 | none |
| 15 | boundary (final state, no transition) | (none) | — | none |

Row 15 has all four step selectors equal to 0; the four selectors
otherwise form a partition of the cycle. The complement
`p_last_in_cycle = 1 − is_init_ext − is_ext − is_packed_int − is_int_ext`
fires exactly on row 15 and is used to gate cycle-boundary constraints
without a separate periodic column.

The packing rationale ports verbatim from Miden VM's `permutation/state.rs`:
the only S-box layer per row keeps each ext-row constraint at deg 7
under a deg-2 gate (= 9); packed-internal rows substitute witnesses
for the S-box of lane 0 so the M_I follow-up stays affine in trace
columns; row 11's hardcoded `ARK_INT[21]` saves one ark slot since
no other row needs that constant under `is_int_ext`.

## Per-row format

### Main columns (19)

| Col | Role |
|---|---|
| `state[0..12]` | 12 lanes; row 0 holds the input state, row 15 holds the output |
| `w[0..3]` | sbox-output witnesses (rows 4–10 use `w[0..3]`, row 11 uses `w[0]`, all 0 elsewhere by gating) |
| `perm_seq_id` | cycle-constant permutation identifier; row 0 of cycle K holds value K |
| `in_multiplicity` | cycle-constant; # caller-side consumes of the In-side bus tuples per cycle |
| `out_multiplicity` | cycle-constant; # caller-side consumes of `OutRate0` per cycle |
| `is_absorb` | cycle-constant binary; `1` ⇒ this cycle inherits capacity from the previous cycle |

Step transitions are gated by `(in_multiplicity + out_multiplicity)`,
so a cycle is "inert padding" iff both multiplicities are zero.

### Periodic columns (16, period 16)

| Col | Role |
|---|---|
| `is_init_ext` | 1 on row 0 |
| `is_ext` | 1 on rows 1–3, 12–14 |
| `is_packed_int` | 1 on rows 4–10 |
| `is_int_ext` | 1 on row 11 |
| `ark[0..12]` | round constants (see schedule below) |

Selector mutex pattern is exactly Miden's. `ark` content per row:

| Rows | `ark[0..12]` content |
|---|---|
| 0–3 | `ARK_EXT_INITIAL[0..4]` (lane-by-lane) |
| 4–10 | `ARK_INT[3·triple + k]` in lanes 0..3 (= 3 internal RCs per row), zeros in lanes 3..12 |
| 11 | `ARK_EXT_TERMINAL[0]` (lanes 0..12); `ARK_INT[21]` is hardcoded into the row-11 constraint |
| 12–14 | `ARK_EXT_TERMINAL[1..4]` |
| 15 | all zero |

## Bus contract

Two new bus ids registered alongside the existing chiplets:

| Bus | Direction | Tuple shape | Width |
|---|---|---|---|
| `Poseidon2In` | provided by this chiplet | `(perm_seq_id, tag, c[0..4])` with `tag ∈ {0, 1, 2}` | 6 |
| `Poseidon2Out` | provided by this chiplet | `(perm_seq_id, digest[0..4])` | 5 |

Tag encoding on `Poseidon2In`: `0 = rate0`, `1 = rate1`, `2 = capacity`.
`Poseidon2Out` carries `rate0` only — the post-permutation back half
of rate and the post-permutation capacity stay private to the chiplet.
If a future caller needs them, either add tags to `Poseidon2Out` or
split into additional bus ids; both extensions are additive.

### Provider gates

Sign convention: provide = `−m`, consume = `+m`. In-side providers
use `in_multiplicity`; the Out-side provider uses `out_multiplicity`:

| Message | Row | Multiplier | Tuple |
|---|---|---|---|
| `Poseidon2In(tag=0)` | 0 (`is_init_ext = 1`) | `−in_multiplicity · is_init_ext` | `(perm_seq_id, 0, state[0..4])` |
| `Poseidon2In(tag=1)` | 0 | `−in_multiplicity · is_init_ext` | `(perm_seq_id, 1, state[4..8])` |
| `Poseidon2In(tag=2)` | 0 | `−in_multiplicity · is_init_ext · (1 − is_absorb)` | `(perm_seq_id, 2, state[8..12])` |
| `Poseidon2Out` | 15 (`p_last_in_cycle = 1`) | `−out_multiplicity · p_last_in_cycle · (1 − next.is_absorb)` | `(perm_seq_id, state[0..4])` |

`is_absorb` is read from the current row; `next.is_absorb` is the
next row's `is_absorb` (= the next cycle's, since `is_absorb` is
constant within a cycle). Next-row reads inside LogUp interactions
are first-class in the LogUp framework — `LookupBuilder::main()`
returns a two-row `WindowAccess` window, and existing chiplets in
the repo emit both payloads (`Bitwise64`'s chain trick:
`c_lo, c_hi` read from next row's `a_bytes`) and multiplicities
(`KeccakSponge`'s `is_pad := is_zero_next − is_zero`) sourced from
the next row. The `Poseidon2Out` gate uses the same idiom.

### Caller consume patterns

The caller's surface is the [`Absorption`](#caller-facing-trace-api)
type. After calling `generate_trace`, the returned
`AbsorptionOutput` carries the digest and the `PermSpan` of occupied
cycles (`PermSeqId` handles minted by the accumulator — raw sequence
numbers only surface at trace cells via `.seq()`). The caller emits
these bus consumes:

- For every block (= every cycle in the span):
  `Poseidon2In::rate0(perm_seq_id, rate0)` and
  `Poseidon2In::rate1(perm_seq_id, rate1)`.
- Once at `span.head()`: `Poseidon2In::cap(perm_seq_id, cap)`.
- Once at `span.tail()`: `Poseidon2OutMsg { perm_seq_id, digest }`.

**Bus cost per absorption.** For an N-block absorption: `2N + 2`
chunk consumes (= `2N` rate halves + 1 cap + 1 digest). Compared
with a hypothetical unchained design that emitted a full
state in/out per perm (`4N`), chains amortize from N = 2 upward.
A 1-shot absorption costs 4 consumes flat.

Intermediate capacities never appear on the bus; the chiplet
threads them via the capacity-carry constraint.

### Multiplicities are not range-checked

`in_multiplicity` / `out_multiplicity` are committed cycle-constant
counts, **not** range-checked. Earlier revisions emitted two
`Range16` requires (one per multiplicity) as defense-in-depth against
"negative felt" attacks; that was removed once the VM-wide
fixed-consume invariant ([`../lookup-argument.md`](../lookup-argument.md))
became the documented contract. Under it, every In/Out consumer
consumes with a constant `+1` weight, so bus balance pins each
multiplicity to its real consumer count (`< trace height ≪ p`); a
wrapped `p − k` would demand `p − k` consumers, impossible. The
activity gate (`in + out`) therefore can't be wrapped to `0` on a
live cycle, and the multiplicities are plain `usize` at trace-gen with
no `2^16` cap or spill. (Were a future consumer ever to consume the
In/Out bus with a *witnessed* multiplicity, the provide-side range
check would have to come back — but the invariant forbids that.)

## Local constraints

Constraint degrees count Plonky3 periodic columns at deg 1 (see
[Plonky3 periodic-column degree](../forward-looking.md)). The
structural constraints below are scoped to the 16-row cycle by the
periodic step selectors: a constraint that must skip the row-15 →
row-0 trace-boundary edge is gated by a selector that vanishes on row
15, so no separate `when_transition`-edge bookkeeping is needed. (This
is unrelated to the LogUp running sum, which is a plain accumulator
that closes naturally on the last row — no cyclic wrap; see
[`../lookup-argument.md`](../lookup-argument.md).)

### Boundary (`when_first_row`)

- `perm_seq_id − 0 = 0`. Row counter starts at 0; addresses on the bus
  are interpretable, and `perm_seq_id` increments deterministically from
  there.
- `is_absorb = 0`. Cycle 0 must be a fresh perm (or chain head),
  never a chain continuation. `perm_seq_id` is *not* a torus (it counts
  `0, 1, …, N−1` with a discontinuity at the wrap), so a chain
  spanning the row-(N−1) → row-0 wrap would force the caller to
  encode perm_seq_ids across the discontinuity — awkward and brittle to
  trace-size changes. Constraining `is_absorb_0` eliminates the
  wrap-chain mode entirely.

`in_multiplicity` and `out_multiplicity` are deliberately *not*
pinned at row 0. An all-padding trace (both = 0 everywhere) is valid
and contributes zero to every bus.

### `perm_seq_id` chain

- Cycle-constant within cycles (deg 2):
  `(1 − p_last_in_cycle) · (perm_seq_id' − perm_seq_id) = 0`.
- Cycle-to-cycle increment by 1 (`when_transition`, deg 2):
  `p_last_in_cycle · (perm_seq_id' − perm_seq_id − 1) = 0`.

The cyclic wrap (row N−1 → row 0) is unenforced by `when_transition`;
the boundary on row 0 plus the per-cycle step pins `perm_seq_id` to
`0, 1, 2, …` along the trace deterministically.

### Multiplicity constancy

Both `in_multiplicity` and `out_multiplicity` are cycle-constant:

- `(1 − p_last_in_cycle) · (in_multiplicity' − in_multiplicity) = 0`. Deg 2.
- `(1 − p_last_in_cycle) · (out_multiplicity' − out_multiplicity) = 0`. Deg 2.

They carry no range / binarity constraint: each is pinned to its bus's
`+1`-weighted consumer count by balance (see
[§ Split multiplicity](#design-choices)).

### `is_absorb` structure

- Binary: `is_absorb · (1 − is_absorb) = 0`. Deg 2.
- Cycle-constant: `(1 − p_last_in_cycle) · (is_absorb' − is_absorb) = 0`.
  Deg 2.

`is_absorb` is unconstrained at cycle boundaries (the prover toggles
freely from cycle to cycle); chain coherence is enforced collectively
by the capacity-carry constraint and the bus.

### Capacity carry

For each capacity lane `i ∈ [8, 12)`:

```
p_last_in_cycle · is_absorb' · (state'[i] − state[i]) = 0
```

Deg 3. Applied ungated: at row 15 of cycle K, if cycle K+1 is an
absorb continuation (`is_absorb' = 1`), the row-0 input capacity of
cycle K+1 must equal the row-15 output capacity of cycle K. At every
other row, `p_last_in_cycle = 0` zeroes the constraint. The cyclic
wrap (last row's `next` is row 0) is allowed to either close the
loop with `is_absorb_0 = 0` (the normal, chain-fresh case — no
constraint fires) or `is_absorb_0 = 1` (chain wraps the torus —
unusual, but algebraically benign; per-tuple bus balance still
forces the chain ends to connect to real consumes on both sides).

### Poseidon2 step transitions

Ported from Miden's `permutation/state.rs`. Each step transition is
gated by `activity · selector`, where
`activity = in_multiplicity + out_multiplicity`. The activity factor
makes the constraint vacuate on padding cycles (both mults = 0),
freeing the prover to zero-fill the padded suffix of the trace
rather than evaluate a dummy permutation. On cycles with bus
emissions on either side, step transitions fire and `state_15` is
the real Poseidon2 output of `state_0` — preventing the fake-digest
attack where `in_multiplicity = 0` but `out_multiplicity > 0`.
Witness zeroing on non-packed rows is left ungated — it imposes no
constraint on padding rows where the witness is already zero by
construction.

| Step | Gate | Constraint | Deg |
|---|---|---|---|
| Init + ext1 | `activity · is_init_ext` | per-lane: `state'[i] − apply_init_plus_ext(state, ark)[i] = 0` | 9 |
| Single ext | `activity · is_ext` | per-lane: `state'[i] − M_E(S(state + ark))[i] = 0` | 9 |
| Packed internal — witness | `activity · is_packed_int` | for k ∈ 0..3: `w[k] − (state^{(k)}_0 + ark_int[k])^7 = 0` | 9 |
| Packed internal — next-state | `activity · is_packed_int` | per-lane: `state'[i] − affine_in_witnesses(state, w, ark_int, MAT_DIAG)[i] = 0` | 5 |
| Int + ext (row 11) | `activity · is_int_ext` | witness: `w[0] − (state[0] + ARK_INT[21])^7 = 0`; per-lane: `state'[i] − apply_internal_plus_ext(state, w[0], ARK_INT[21], ark, MAT_DIAG)[i] = 0` | 9 |
| Witness zeroing on non-packed rows | `(1 − is_packed_int) · (1 − is_int_ext)` for `w[0]`, `(1 − is_packed_int)` for `w[1], w[2]` | `w[k] = 0` | 3 |

`activity` is a sum of two cycle-constant deg-1 columns, so it
remains deg 1 in the witness. Constraint expansions follow Miden's
helpers `apply_matmul_external`, `matmul_m4`, `apply_matmul_internal`,
`apply_init_plus_ext`, `apply_packed_internals`,
`apply_internal_plus_ext` exactly. The witness-zeroing constraints
are defensively included so unused witness slots don't accidentally
contribute to other rows' algebra (matches Miden's behaviour).

The deg-9 ceiling (`1 + 1 + 7` = activity × selector × S-box) is
the chiplet's tightest constraint, fixing `log_quotient_degree = 3`.

### Constraint degree summary

- Local poly constraints (Poseidon2 transitions): max **deg 9** —
  `activity · selector · sbox` = `1 + 1 + 7`. This is the
  chiplet-wide ceiling and fixes `log_quotient_degree = 3`.
- Structural (perm_seq_id, in/out_mult, is_absorb, capacity carry):
  max **deg 3**.
- Bus interactions (see [§ Aux structure](#aux-structure)): aux
  column constraint deg **5** after the mutex split below — strictly
  below the step-transition ceiling, so the bus is no longer the
  binding constraint.

The Poseidon2 S-box (deg 7) is the chiplet's hard floor; everything
else is shaped to fall under that ceiling without overshooting it.

## Aux structure

A single σ residue exposed publicly. Per-row insert breakdown:

| Row | Inserts | Notes |
|---|---|---|
| 0 (`is_init_ext`) | 3 | `InRate0`, `InRate1`, `InCap` (`InCap` mult goes to 0 on chain-interior/tail cycles via the `(1 − is_absorb)` factor) |
| 1–14 | 0 | No bus emissions |
| 15 (`p_last_in_cycle`) | 1 | `OutRate0` (mult 0 on non-tail cycles via `(1 − is_absorb_next)`) |

One aux column hosting one group with **two mutex batches**
(`column_shape = [4]`, 3 + 1):

- **Batch A** (outer flag `is_init_ext`, periodic deg 1): the 3
  Poseidon2In provides at row 0. `d_A = 3`; max inner mult deg = 2
  (InCap's `in_multiplicity · (1 − is_absorb)`); batch numerator deg
  `n_A = 2 + 2 = 4`.
- **Batch B** (outer flag `p_last_in_cycle`, periodic deg 1): the
  OutRate0 provide at row 15. `d_B = 1`; max inner mult deg = 2
  (OutRate0's `out_multiplicity · (1 − is_absorb_next)`); `n_B = 2`.

The two flags are periodic-disjoint (`is_init_ext · p_last_in_cycle = 0`),
so the simple-group composition `u_g += (d − 1)·f`, `v_g += n·f` is
sound (batch A dominates):

- `u_g` deg = max((d_A − 1)·f_A, (d_B − 1)·f_B) = max(2+1, 0+1) = 3.
- `v_g` deg = max(n_A·f_A, n_B·f_B) = max(4+1, 2+1) = 5.
- Column constraint deg = max(1 + u_g, v_g) = 5.

`log_quotient_degree` stays fixed at 3 by the step transitions;
the bus column at deg 5 sits slack against the deg-9 step
transitions. (Batch B lost its two `Range16` multiplicity requires —
multiplicities are pinned by balance, not range-checked — leaving the
lone OutRate0 provide; the mutex is now 3 + 1.)

Sign convention: provide = `−m`, consume = `+m` (matches all other
chiplets in the repo).

## Caller-facing trace API

The trace generator is built around **absorptions**, not individual
permutations. `is_absorb` is a chiplet-internal selector that the
caller never has to compute or thread.

```rust
pub struct Absorption {
    pub cap: [Felt; 4],                       // initial capacity (domain sep)
    pub blocks: Vec<([Felt; 4], [Felt; 4])>,  // (rate0, rate1) per block; non-empty
    pub in_multiplicity: u16,                 // # callers consuming In-side bus tuples
    pub out_multiplicity: u16,                // # callers consuming the digest
}

pub struct AbsorptionOutput {
    pub digest: [Felt; 4],
    pub span: PermSpan,                       // head..=tail handles; n_cycles = blocks.len()
}

pub fn generate_trace(absorptions: &[Absorption])
    -> (RowMajorMatrix<Felt>, Vec<AbsorptionOutput>);
```

The chiplet lays each absorption down as consecutive 16-row cycles,
auto-threads intermediate capacities across cycle boundaries, and
returns the digest + allocated `perm_seq_id` range per absorption. The
caller then builds its own bus consumes:

- `Poseidon2In::rate0/rate1` for every `perm_seq_id` in the range
  (× `in_multiplicity` per caller; the chiplet provides
  `in_multiplicity` copies of each tuple).
- `Poseidon2In::cap` only at `perm_seq_id_range.start` (the chain
  head), also gated by `in_multiplicity`.
- `Poseidon2OutMsg` only at `perm_seq_id_range.end - 1` (the chain
  tail), gated by `out_multiplicity`.

Intermediate capacity values never appear in the type system — they
live only in the rows the prover commits.

**Interning** lives at the absorption level: two callers asking for
the same `(cap, blocks)` collapse into one `Absorption` with the
summed `in_multiplicity` (= the count of creators). The matching
`out_multiplicity` separately counts how many places reference the
digest — for content-addressed-DAG nodes referenced by many parents,
`out_multiplicity ≫ in_multiplicity` is the common case.

## Caller obligations

`perm_seq_id` increments per cycle, so each cycle in the trace has a
unique id. This means **block order is bound by the bus for free**:
block k of an absorption sits at `perm_seq_id = head + k`, so a
malicious prover that permutes the blocks emits `InRate0`/`InRate1`
tuples at different ids than the caller consumes → bus imbalance →
reject. Order is not a caller obligation.

What the chiplet does *not* bind — and what the caller AIR must
enforce — is the **head↔tail pairing** for multi-block absorptions:

1. **Head/tail pairing (multi-block only).** `InCap` lands at the
   head (`perm_seq_id = head`); `OutRate0` lands at the tail
   (`perm_seq_id = head + N − 1`). The chiplet does not tie the two
   ids together, so a malicious prover could pair `InCap` from
   absorption A with `OutRate0` from a different absorption B and
   claim B's digest is the hash of A's input. The caller AIR closes
   this by consuming `OutRate0` at exactly `head + N − 1` — i.e. it
   must know the block count `N` and address the tail accordingly.
   **For one-shot absorptions (`N = 1`) this is vacuous**: head and
   tail coincide, `InCap.perm_seq_id == OutRate0.perm_seq_id`, which
   any natural caller row structure already pins. So every one-shot
   consumer (2-to-1 compression, leaf hashing, Merkle paths) is
   immune by construction.

   **The only multi-block consumer in this VM is the chunk chiplet**
   (variable-length message hashing), and it enforces the pairing as
   part of its own block accounting. We accept the obligation rather
   than spend a chiplet column to bind head↔tail, precisely because
   the multi-block client surface is that one chiplet. (See
   [Design rationale → Head/tail binding](#headtail-binding) for the
   per-absorption-id and carried-`head_seq_id` alternatives that were
   weighed and dropped.)

2. **At-least-one-creator per referenced digest.** Whenever some
   caller emits a `Poseidon2OutMsg` consume for cycle K, at least
   one caller (typically the same one) must also consume the
   In-side messages for cycle K. Otherwise `in_multiplicity = 0`
   on that cycle, the chiplet's `InCap` / `InRate0` / `InRate1`
   providers vanish on the bus, and no caller-side consume of those
   tuples will balance — the malicious prover gets caught by bus
   imbalance. Sane applications that have a "creator row" per
   referenced node satisfy this naturally.

## Chain semantics (internal AIR view)

The `is_absorb` selector classifies each cycle by its relationship to
the previous one. The caller never sees this directly, but it's how
the AIR enforces capacity threading.

| Role | `is_absorb` | `next.is_absorb` | Bus surface |
|---|---|---|---|
| 1-shot | 0 | 0 | `InRate0`, `InRate1`, `InCap` (in), `OutRate0` (out) |
| Chain head | 0 | 1 | `InRate0`, `InRate1`, `InCap` (in), no `OutRate0` |
| Chain interior | 1 | 1 | `InRate0`, `InRate1` (in), no caps, no `OutRate0` |
| Chain tail | 1 | 0 | `InRate0`, `InRate1` (in), no `InCap`, `OutRate0` (out) |

A chain of length L spans L consecutive cycles = 16·L rows. Capacity
threads through the chain on every cycle boundary via the
capacity-carry transition; only `InCap` (at the head) and `OutRate0`
(at the tail) cross the bus.

**Trace-boundary wrap.** The trace is cyclic at its row boundary (the
`next` of row N−1 is row 0), so an unconstrained chain selector could in
principle thread capacity across that edge. The `is_absorb_0 = 0`
boundary forbids chains that span the row-(N−1) → row-0 trace boundary.
Chains must start and end strictly within `[0, N−1]`. This eliminates the
only `perm_seq_id`-encoding cliff the caller would otherwise face (the
chain's identity would have to straddle the perm_seq_id discontinuity at
the wrap).

**Padding cycles.** Trailing cycles to round trace height up to a
power of two have `multiplicity = 0`. Every step transition is
mult-gated, so padding cycles vacuate the Poseidon2 algebra
entirely — the trace gen zero-fills state and witnesses rather than
evaluate a dummy permutation. Bus emissions are likewise mult-gated,
so padding contributes nothing to any bus.

## Trace size

Per permutation: **16 rows**. Stacked N permutations: 16·N rows,
padded to the next power of two.

| N permutations | Rows used | Trace size | Rows wasted |
|---|---|---|---|
| 1 | 16 | 16 | 0 |
| 64 | 1,024 | 1,024 | 0 |
| 65 | 1,040 | 2,048 | 1,008 |
| 128 | 2,048 | 2,048 | 0 |
| 4,096 | 65,536 | 65,536 | 0 |
| 65,536 | 1,048,576 | 1,048,576 | 0 |

Any N divisible by `2^k / 16 = 2^{k−4}` is tight. Compared to Keccak
at 3200 rows/perm, Poseidon2 is ~200× more compact — the packed
schedule is the load-bearing optimization.

## Design rationale

### `perm_seq_id` semantics across chiplet instances

Caller AIRs allocate their own `perm_seq_id` values matching the chiplet's
allocation order (`0, 1, 2, …` along the trace). Any caller that
needs to reference a specific permutation by id pre-computes that id
in its own trace and consumes the matching bus tuples. We don't
expose `perm_seq_id` choice to the caller — it's purely the chiplet's
own ordering.

### Head/tail binding

`perm_seq_id` increments per cycle, so block *order* is bound by the
bus (block k at `head + k`), but head↔tail pairing is left to the
caller (see [Caller obligations](#caller-obligations)). Two
alternatives that would bind head↔tail *in-chiplet* were weighed and
dropped:

- **Per-absorption `perm_seq_id`** — constant across a chain's
  cycles. Collapses head/tail pairing to a single-column equality,
  but in doing so erases the per-cycle ids that bind block order:
  blocks become freely reorderable on the bus. Rejected — it trades
  a caller obligation we can document for a soundness hole we cannot.
- **Carried `head_seq_id`** — an extra main column threading the
  head's id down to the tail, surfaced in `Poseidon2OutMsg`. Restores
  both order *and* head/tail binding, but costs a column on every
  cycle and widens the Out message for the benefit of a single
  client. Rejected — the only multi-block consumer is the chunk
  chiplet, which already tracks block counts and can pair head/tail
  itself.

We keep per-cycle `perm_seq_id` (order bound by the bus) and push
head/tail pairing to the caller.

### Multiplicity range checks (dropped)

Earlier revisions emitted two `Range16` requires per cycle (one per
multiplicity), as defense-in-depth against "negative felt" attacks
regardless of caller hygiene. They were removed once the VM adopted
the fixed-consume invariant ([`../lookup-argument.md`](../lookup-argument.md))
as a documented contract: every In/Out consumer consumes with a
constant `+1` weight, so balance already pins each multiplicity to a
real small consumer count — the range check was provably redundant.
Their removal shrank the row-15 batch from 3 to 1 fraction
(`column_shape [6] → [4]`). If a consumer is ever added that consumes
the In/Out bus with a *witnessed* multiplicity, the check must return
(the invariant would no longer hold); a stack-wide test asserting all
consume weights are constant is the cheaper guard.
