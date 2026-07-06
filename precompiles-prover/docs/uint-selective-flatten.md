# Selective flattening — uint family only (0.26, lqd=3 kept)

**Goal.** Reduce the *eval-bound* prover cost without touching `D_max` or the
blowup. At fixed `lqd=3` / blowup 8 the only lever flattening pulls is the
per-AIR native quotient coset (the `evaluate constraints` phase). So flatten
**only the AIRs that own that phase** — the trace-area-dominant uint chiplets —
and leave everything else at its main degree.

Branch `research/uint-selective-flatten` (off `main` 959806a): UintStore /
UintAdd / UintMul flattened lqd 3 → 1 (the same self-contained LogUp
re-partition from `research/logup-flatten`); 12 other AIRs untouched. `D_max`
stays 3 (P2/sponge/ec/keccak still lqd 3), so blowup stays 8.

## Measured (release, vs `main`)

prove wall-time (s):

| bench | main (all lqd3) | **selective (uint→1)** | full-flatten (all→1, D3) |
|---|--:|--:|--:|
| **ec_msm** | 22.64 | **18.01 (−20%)** | 17.83 (−21%) |
| keccak | 2.79 | 2.78 (~0) | 2.58 |
| uint_horner | 2.28 | 2.27 (~0) | 2.13 |

ec_msm phase split (s):

| phase | main | selective | full-flatten |
|---|--:|--:|--:|
| evaluate constraints | 11.4 | **3.73** | 3.53 |
| commit main | 4.07 | 4.04 | 4.05 |
| commit aux | 2.89 | **5.70** | 5.69 |
| commit quotient | 1.76 | 1.76 | 1.77 |
| open | 1.32 | 1.37 | 1.35 |

## Reading

- **Uint is the whole story for eval-bound.** Selective (3-file diff) lands
  −20% on ec_msm vs full-flatten's −21% (13-file diff). The other 10 chiplets
  together buy only **0.2 s** more eval (3.73 → 3.53) — they're 32–128× shorter
  than the 2^18 uint traces, so they barely touch the eval bar *and* barely cost
  any aux-commit (5.70 ≈ 5.69). Same perf, far less churn, and the unflattened
  chiplets stay narrow (recursion-friendlier).
- **The cost is commit-aux**, entirely from the tall uint AIRs: +2.8 s (the
  +19 QuadFelt LogUp columns at 2^18 × blowup 8). The eval-saving (−7.7 s) wins
  comfortably *because ec_msm is eval-bound*.
- **The win is workload-specific.** keccak doesn't use uint (empty padding) →
  ~0. uint_horner is uint-heavy but small (2^16) and commit-leaning → the eval
  shrink ≈ the aux growth → ~0. The −20% appears only when uint dominates a
  tall, eval-bound trace (ec_msm). This is the expected shape: flatten pays
  exactly where eval ≫ the added aux-commit.

## Follow-ups (not done)

- **EC tier:** ec_add (8192) / ec_msm (4096) / ec_points (2048) are lqd 3 and
  own the residual ~0.2 s of ec_msm eval. Flattening them recovers it — marginal.
- **uint → lqd 2 instead of 1:** ×2 coset for ~half the added columns. Would
  shrink the +2.8 s aux-commit cost at the price of less eval-saving; net
  trade depends on the workload (lqd 1 wins for strongly eval-bound ec_msm,
  per the full-flatten data). Worth a measurement if the aux-commit / opening
  width (recursion) cost matters more than the last of the eval-saving.
- Proof size in bytes: still not wired (needs `StarkProofData` serialization).
