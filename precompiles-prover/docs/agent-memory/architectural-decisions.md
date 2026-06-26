# Architectural decisions

Fixed; don't re-litigate without strong reason.

- **Natural last-row σ-closing** for column 0
  ([`../../src/logup/constraint.rs`](../../src/logup/constraint.rs)). `when_first: acc[0] = 0`;
  `when_transition: D₀·(acc_next − Σ_{i<L} acc[i]) − N₀ = 0`; `when_last: D₀·(σ − Σ_{i<L} acc[i]) −
  N₀ = 0`. σ is committed as the single permutation value; **no `inv_n` public input**. Public
  values are just the shared 4-felt transcript root. The col-0 transition/last gate costs +1
  symbolic degree vs the older *ungated σ/n-cyclic* form it replaced (which used a `+σ·inv_n`
  correction + a wrap); 0.26's per-AIR quotient coset absorbs it. `chunk` and `keccak_node` thereby
  sit at lqd 3, not 2. The `Cyclic*` type names in the adapter are legacy.
- **Multi-column fraction architecture**: col 0 is the only running sum; cols 1+ are per-row
  fraction columns. Each fraction column has its own ungated `D_i · acc[i] − N_i = 0` constraint;
  col 0 absorbs `Σᵢ acc[i]` per row in addition to its own group's `N_0/D_0`. Single σ per chiplet —
  col 0's running sum already aggregates all per-row contributions.
- **`LookupAir<LB>::eval` describes the LogUp argument via the closure-based API**:
  `builder.next_column(|col| col.group(name, |g| { g.add(...); g.batch(name, flag, |b| {
  b.insert(...) }) }))`. `LiftedAir::eval` runs Phase 1 non-LogUp constraints on `&mut AB`, then
  wraps in `CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0)` and
  dispatches to `LookupAir::eval`. The prover side is `LiftedAir::build_aux_trace` (a free
  `build_aux` the AIR delegates to → `build_logup_aux_trace`); the 0.24 `AuxBuilder` trait is gone,
  and `MultiAir::eval_external` (not `reduced_aux_values`) closes the cross-AIR `Σ σ = 0`.
- **Single global `(α, β)`** drawn after main-trace commitment. Domain separation is via
  `bus_prefix[i] = α + (i+1)·β^W`, precomputed in `Challenges` (re-exported from
  `miden_air::lookup::Challenges`). Bus IDs registered in
  [`../../src/relations.rs`](../../src/relations.rs) as a `BusId` enum.
- **LookupMessage trait bounds**: every chiplet's `*Msg` impl uses the shape `where E: Algebra<E>,
  EF: Algebra<E>` — the blanket `impl<R: PrimeCharacteristicRing> Algebra<R> for R` plus the
  `Algebra<F>: PrimeCharacteristicRing` super-bound carries everything else.
- **Tests live under `src/tests/`**, not inline `#[cfg(test)] mod tests`, to keep production source
  files audit-friendly.
- **Trace heights are powers of two**, padded with all-zero rows.
