# Lifted STARK Protocol

Multi-trace STARK prover and verifier using LMCS commitments, DEEP quotient
batching, and lifted FRI for low-degree testing.

This README is protocol-level documentation (intended for maintainers and
reviewers). Per-module API details live in `src/prover/README.md` and
`src/verifier/README.md`.

## Overview

This crate contains the full lifted STARK implementation: shared types,
prover, and verifier.

```
miden-lifted-stark              ← this crate
├── src/prover/                    ← Proving: trace commitment, constraint evaluation, quotient construction
├── src/verifier/                  ← Verification: OOD check, quotient reconstruction, transcript canonicality
├── src/pcs/                       ← PCS (DEEP + FRI)
├── src/lmcs/                      ← Merkle commitments with lifting
└── miden-lifted-air            ← AIR traits (aux columns, periodic columns)
```

The system supports **multiple traces of different power-of-two heights**.
Shorter traces are virtually lifted to the maximum height via LMCS upsampling,
so the PCS and verifier operate on a single uniform view.

## Notation

- `N = 2^n`: maximum trace height across all traces in a proof.
- `n_j`: height of trace `j`.
- `r_j = N / n_j`: lift ratio (a power of two).
- `H`: two-adic subgroup of size `N` with generator `omega_H`.
- `g`: multiplicative coset shift (`F::GENERATOR` by convention).
- `D`: quotient-domain blowup, derived per AIR from its constraint degree; the batch value is the max over AIRs.
- `gJ`: quotient-domain coset (size `N * D`).
- `gK`: PCS/LDE coset (size `N * B`, where `B` is the FRI blowup).
- `z`: global out-of-domain point sampled once.
- `z_next = z * omega_H`: "next row" point for max height.

When referring to LMCS, a *tree index* means a bit-reversed leaf index.

## Liftable AIR Assumption

LMCS makes shorter traces indistinguishable from explicit repetition at height
`N`. This is safe only if the AIR constraints are compatible with that lifted
view.

Informally, an AIR is "liftable" if transition constraints do not rely on the
wrap-around row (last -> first) unless that behavior is explicitly constrained.
See `docs/lifting.md` for a deeper discussion and sufficient conditions.

## Protocol Summary

### Prover (`prove`)

1. **Commit main traces** — LDE each trace on its lifted coset, bit-reverse
   rows, build LMCS tree. Send root.
2. **Sample randomness** — Squeeze auxiliary randomness from the Fiat-Shamir
   channel. Build and commit auxiliary traces.
3. **Sample challenges** — `alpha` (constraint folding) and `beta`
   (cross-trace accumulation).
4. **Evaluate constraints** — For each trace in ascending height order,
   evaluate AIR constraints on the quotient domain using SIMD-packed
   arithmetic. Produces a numerator N_j per trace (no vanishing division).
5. **Accumulate numerators** — Fold across traces:
   `acc = cyclic_extend(acc) * beta + N_j`.
6. **Divide by vanishing polynomial** — One pass on the full quotient domain,
   exploiting Z_H periodicity for batch inverse.
7. **Commit quotient** — Decompose Q into D chunks via fused iDFT + coefficient
   scaling + flatten + DFT pipeline. Commit via LMCS.
8. **Sample OOD point z** — Rejection-sampled to lie outside H and the LDE
   coset.
9. **Open via PCS** — Delegate to the internal `pcs` modules.

### Verifier (`verify`)

1. **Receive commitments** — Main, auxiliary, and quotient roots from transcript.
2. **Re-derive challenges** — Same `alpha`, `beta`, `z` via Fiat-Shamir.
3. **Verify PCS openings** — At `[z, z_next]` where `z_next = z * omega_H`.
4. **Reconstruct Q(z)** — Barycentric interpolation over the D quotient
   chunks.
5. **Evaluate constraints at OOD** — For each AIR at the lifted OOD point
   `y_j = z^{r_j}`: compute selectors, evaluate periodic polynomials,
   fold constraints with alpha, accumulate with beta.
6. **Evaluate external assertions** — Call `Statement::eval_external`
   once over the global view (challenges, aux values, log heights); each
   returned EF value must equal zero.
7. **Check identity** — `accumulated == Q(z) * Z_H(z)`.
8. **Ensure transcript is fully consumed** — Canonicality enforcement.

## Math Sketch

### Multi-Trace Lifting

Each trace j has height `n_j = n_max / r_j` where `r_j` is a power-of-two
lift ratio. The committed polynomial is `p_j(X^{r_j})`, so opening the LMCS
commitment at `z` yields `p_j(z^{r_j})`. The coset shift for trace j
is `g^{r_j}` where g is the multiplicative generator.

### Constraint Folding

For a single trace, constraints `C_0, C_1, ...` are folded via Horner
accumulation:

```
folded = (...((C_0 * alpha + C_1) * alpha + C_2)...) * alpha + C_k
```

This avoids precomputing alpha powers and does not require knowing the
constraint count ahead of time.

### Cross-Trace Accumulation

Numerators from traces of increasing height are combined:

```
acc = cyclic_extend(acc) * beta + N_j
```

where `cyclic_extend` repeats the accumulator via modular indexing
(`i & (len - 1)`) to match the next trace's quotient domain size.
This works because:

```
Z_H(x) = Z_{H^r}(x) * Phi_r(x)
```

so cyclic extension of a polynomial divisible by `Z_{H^r}` preserves
divisibility by `Z_H`.

### Vanishing Division

After accumulation, the combined numerator is divided by `Z_H(x) = x^N - 1`
once on the full quotient domain.

On the quotient coset `gJ` (where `|J| = N * D`), the values `x^N` range over a
size-`D` subgroup, so `Z_H(x)` takes only `D` distinct values. The prover can
batch-invert those `D` values once and index them by `i mod D`.

### Quotient Decomposition

The quotient polynomial Q of degree `N * D - 1` is decomposed into D chunks
`q_0, ..., q_{D-1}` of degree `N - 1`:

```
Q(X) = q_0(X^D) + X * q_1(X^D) + ... + X^{D-1} * q_{D-1}(X^D)
```

The prover commits evaluations of each `q_t` over the LDE domain. The
verifier reconstructs `Q(z)` from `q_t(z)` via barycentric
interpolation:

```
Q(z) = (sum_t w_t * q_t(z)) / (sum_t w_t)
    where w_t = omega_S^t / (u - omega_S^t),  u = (z/g)^N
```

### Virtual OOD Point

For a trace with lift ratio `r_j`, the effective OOD evaluation point is
`y_j = z^{r_j}`. The verifier evaluates selectors and periodic polynomials
at `y_j`, and the opened trace values already correspond to `p_j(y_j)`.

## Optimizations

- **SIMD constraint evaluation** — Constraints are evaluated on `PackedVal::WIDTH`
  points simultaneously. Main trace stays in base field; only auxiliary columns
  use extension field arithmetic.
- **Horner folding** — Constraint accumulation via `acc = acc * alpha + C_i`
  avoids precomputing and storing alpha powers.
- **Fused quotient pipeline** — iDFT, coefficient scaling by `(omega^t)^{-k}`,
  flatten to base field, zero-pad, forward DFT — all in one pass, no redundant
  coset operations.
- **Periodic vanishing exploit** — On the quotient coset `gJ`, `Z_H(x)` takes
  only `D` distinct values; batch inverse computes those once.
- **Zero-copy quotient domain** — `split_rows().bit_reverse_rows()` gives a
  natural-order view of committed LDE data without copying.
- **Efficient periodic columns** — Only `max_period * blowup` LDE values
  stored per periodic table; accessed via modular indexing.
- **Cyclic extension** — Cross-trace accumulation uses bitwise AND for
  modular indexing (power-of-two sizes).
- **Parallel execution** — Rayon parallelism throughout constraint evaluation
  and vanishing division (gated by `parallel` feature).

## Entry Points

| Item | Purpose |
|------|---------|
| `prover::prove` | Prove one or more AIR instances |
| `ProverStatement` | A `Statement` plus per-AIR traces and aux construction |
| `Statement` | A `MultiAir` plus the per-proof inputs (`air_inputs`, optional `aux_inputs`) |
| `MultiAir` | The circuit — AIRs (`type Air`/`fn airs`), `eval_external`, the aux-trace builder, `observe` |
| `verifier::verify` | Verify a multi-trace proof |
| `MultiAir::eval_external` | Cross-AIR external-assertions hook (default: no assertions) |
| `Statement::aux_inputs` | Auxiliary public inputs consumed only by `eval_external` (empty unless provided) |
| `StarkTranscript` | Structured parse-only transcript view; `log_trace_heights()` / `air_order()` expose the proof's heights and derived order |
| `StarkConfig` | PCS params + LMCS + DFT configuration |
| `domain::LiftedDomain` | Domain operations: selectors, vanishing, coset shifts |
| `domain::TwoAdicSubgroup` | Two-adic subgroup with generator, vanishing, membership |
| `domain::TwoAdicCoset` | Coset of a two-adic subgroup, with shift |

## Modules

| Path | Purpose |
|------|---------|
| `src/config.rs` | `StarkConfig` — wraps `PcsParams`, LMCS, and DFT |
| `src/domain.rs` | `TwoAdicSubgroup`, `TwoAdicCoset`, `LiftedDomain` — the domain hierarchy; `log_quotient_degree`, `DomainError` (incl. the `log_quotient_degree ≤ log_blowup` compat bound) |
| `src/selectors.rs` | `Selectors<T>` — generic container for row selectors |
| `src/prover/mod.rs` | `prove` — orchestration and protocol flow |
| `src/prover/commit.rs` | `Committed` — LDE, bit-reverse, LMCS tree construction |
| `src/prover/constraints/` | Constraint evaluation (SIMD) and layout discovery |
| `src/prover/periodic.rs` | `PeriodicLde` — precomputed periodic column LDEs |
| `src/prover/quotient.rs` | Quotient construction, cyclic extension, vanishing division |
| `src/verifier/mod.rs` | `verify` — orchestration and identity check |
| `src/verifier/constraints.rs` | `ConstraintFolder` — OOD constraint evaluation, quotient reconstruction |
| `src/verifier/periodic.rs` | `PeriodicPolys` — polynomial coefficients for OOD evaluation |
| `src/proof.rs` | `StarkProof`, `StarkTranscript` — proof artifact and structured transcript view |
| `src/order.rs` | public `ShapeError` plus the crate-internal instance↔proof ordering helper; `TraceOrder` construction validates the proof's log heights against the AIRs |
| `src/debug.rs` | `check_constraints` (row-by-row), structural assertion (`assert_prover_setup`) over `miden_lifted_air::debug::assert_multi_air_valid` |

## Conventions & Assumptions

- **AIR ordering** — The proof orders AIR instances deterministically by trace
  height (stable sort on `(log_trace_height, instance_index)`), materialised
  internally from the heights stored on `StarkProof`; the ordering type is
  crate-private. The caller must bind the AIR list into the Fiat-Shamir
  challenger. See the prover module-level docs.
- **Power-of-two heights** — All trace heights are powers of two.
- **Bit-reversed storage** — All evaluation matrices are in bit-reversed order.
- **Constraint degree** — Derived per AIR from symbolic analysis
  (`log_quotient_degree`); the proof uses the max over AIRs. Each AIR must
  satisfy `log_quotient_degree(air) ≤ log_blowup`.
- **Transcript ordering** — The Fiat-Shamir transcript follows a strict
  observe/squeeze protocol. Prover and verifier must process commitments and
  challenges in identical order. This is security-critical.
- **Extension field discipline** — Main trace and preprocessed data stay in
  the base field. Only auxiliary columns, challenges, alpha powers, and the
  accumulator use the extension field.
- **Periodic columns** — Column periods must be powers of two and divide the
  trace height. Columns are grouped by period for batch interpolation.

## Tests

The end-to-end test suite lives in `src/testing/`, behind the `testing` feature:

- **`test_tiny_air.rs`** — `TinyAir` exercising single-trace, multi-trace
  (same and different heights), periodic columns, and malformed transcript
  rejection.
- **`test_external_assertions.rs`** — `MultiAir::eval_external` and `aux_inputs`.
- **`test_multi_aux_alignment.rs`** — aux-trace alignment across multiple AIRs.
- **`test_per_air_degree.rs`** — per-AIR quotient degrees.

Run with:
```bash
cargo test -p miden-lifted-stark --features testing
```

## Security

Audits should start with `SECURITY.md` at the workspace root for transcript
ordering, lifting correctness, constraint identity, and critical paths.

## License

Dual-licensed under MIT and Apache-2.0 at the workspace root.
