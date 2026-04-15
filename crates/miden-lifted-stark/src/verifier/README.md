# Lifted STARK Verifier

End-to-end verification for the lifted STARK protocol using LMCS
commitments and the lifted FRI PCS. Supports multiple traces of different
power-of-two heights via virtual lifting.

Protocol-level overview lives in `miden-lifted-stark/README.md`.

## Entry Points

| Item | Purpose |
|------|---------|
| `verify_single` | Verify a single-AIR proof |
| `verify_multi` | Verify a multi-trace proof |
| `AirInstance` | Public values + variable-length inputs for one AIR |
| `StarkProof` | Log trace heights + raw transcript data |

```text
verify_single(config, air, public_values, var_len_public_inputs, proof, challenger)
verify_multi(config, &[(air, instance), ...], proof, challenger)
```

The proof is read from the provided transcript channel. This crate does not
prescribe the *initial* challenger state used for Fiat-Shamir.

## Fiat-Shamir / statement binding

The verifier APIs take the statement out-of-band (`air` and `public_values`).
Log trace heights are carried in the `StarkProof` and observed into the
Fiat-Shamir challenger at the start of verification. The protocol assumes the
challenger has already observed all other variable statement inputs (in
particular `public_values`).

This is required to support applications that obtain public inputs out-of-band and
do not want them duplicated inside the proof.

If your application treats any of these inputs as untrusted, you must authenticate
them by binding them into the Fiat-Shamir challenger state (domain separation +
AIR/version tag + statement metadata + public inputs), in the same way on both prover
and verifier.

## Transcript boundaries

`verify_multi` rejects trailing transcript data (`TranscriptNotConsumed`). If you
bundle extra data in the same transcript, you must manage boundaries yourself.

## Multi-trace ordering

For `verify_multi`, instances must be provided in the same order the prover
used — ascending trace height order for the current prover. Log trace heights
are read from the proof and observed into the Fiat-Shamir challenger, so the
protocol identity depends on the input ordering.

## Protocol flow

0. Observe log trace heights into the challenger (from proof, not transcript).
1. Receive main trace commitment.
2. Sample aux randomness.
3. Receive aux trace commitment.
4. Sample constraint folding challenge `alpha` and cross-trace accumulator `beta`.
5. Receive quotient commitment.
6. Sample OOD point `z` (rejection-sampled outside trace domain), derive `z_next`.
7. Verify PCS openings at `[z, z_next]` for main, aux, and quotient.
8. Reconstruct `Q(z)` from the opened quotient chunks.
9. For each trace instance j, set `y_j = z^{r_j}` and evaluate folded constraints at `y_j`.
10. Accumulate across traces with `beta`.
11. Check quotient identity: `accumulated == Q(z) * (z^N - 1)`.
12. Ensure transcript is fully consumed.

## Mathematical background

This section assumes familiarity with STARK verifiers and explains how
*lifting* lets us verify mixed-height traces using a single uniform
opening point and a single quotient identity. All sizes are powers of two.

### Domains and cosets

Let:

- $N = 2^n$ be the **maximum** trace height across all traces.
- $D = 2^d$ be the **constraint degree** (quotient-domain blowup).
- $B = 2^b$ be the **PCS/FRI blowup**, with $D \le B$.
- $g$ be the fixed multiplicative shift (`F::GENERATOR`).

Define subgroups:

$$
H = \langle \omega_H \rangle,\ |H| = N
\qquad
J = \langle \omega_J \rangle,\ |J| = N\,D
\qquad
K = \langle \omega_K \rangle,\ |K| = N\,B
$$

and shifted cosets $gH, gJ, gK$.

### What "lifted traces" mean to the verifier

Suppose instance $j$ has trace height

$$
n_j = N / r_j
\qquad\text{with } r_j = 2^{\ell_j}.
$$

Let $t_j(X)$ be the degree-$<n_j$ interpolant of the trace column (over $H^{r_j}$),
and define the lifted polynomial

$$
t_j^*(X) := t_j(X^{r_j}).
$$

Key facts:

1. $\deg(t_j^*) < N$, so it fits the max-degree regime.
2. For any point $x$, $t_j^*(x) = t_j(x^{r_j})$.
3. Choosing the commitment coset shift as $g^{r_j}$ makes the evaluation domains
   line up: $(gK)^{r_j} = g^{r_j} K^{r_j}$.

#### Uniform-height view

Conceptually, each short trace is "stretched" to height $N$ by repeating it $r_j$
times. From the verifier's perspective every trace behaves like a single
height-$N$ object:

- there is one global out-of-domain point $z$,
- one global "next-row" multiplier $\omega_H$ (the generator of the max trace domain),
- and each trace instance uses a different *projection* of that point.

### How openings at $[z,\ z\cdot\omega_H]$ give per-trace local/next pairs

The verifier samples a single $z$ outside both the max trace domain $H$ and the max
LDE coset $gK$, and sets:

$$
z_{\mathrm{next}} = z \cdot \omega_H.
$$

For instance $j$, define the **virtual** evaluation point

$$
y_j := \pi_{r_j}(z) = z^{r_j}.
$$

Then:

$$
t_j^*(z) = t_j(z^{r_j}) = t_j(y_j),
$$

and for the next-row point:

$$
t_j^*(z_{\mathrm{next}})
  = t_j\big((z\cdot\omega_H)^{r_j}\big)
  = t_j\big(z^{r_j}\cdot\omega_H^{r_j}\big)
  = t_j\big(y_j\cdot\omega_{H^{r_j}}\big).
$$

Since $\omega_{H^{r_j}} = \omega_H^{r_j}$ is the generator of the smaller trace domain,
the pair opened at $[z,z_{\mathrm{next}}]$ is exactly the local/next pair needed
to evaluate AIR transition constraints for that trace.

This is why verifier code computes `y_j = z^{r_j}` and evaluates selectors/periodics
at $y_j$, while requesting PCS openings only at the global points
$[z,z_{\mathrm{next}}]$.

### Constraint folding at the lifted OOD point

For each instance $j$, the verifier:

1. Interprets the opened main/aux values as $(T_j(y_j),\ T_j(y_j\cdot\omega_{H^{r_j}}))$.

2. Computes row selectors at $y_j$ using:

$$
Z_{H^{r_j}}(y_j) = y_j^{n_j} - 1,
$$

and the unnormalized selector formulas (matching `LiftedCoset::selectors_at`):

$$
\mathrm{is\_first}(y) = \frac{Z_{H^{r_j}}(y)}{y-1},
\quad
\mathrm{is\_last}(y) = \frac{Z_{H^{r_j}}(y)}{y-\omega_{H^{r_j}}^{-1}},
\quad
\mathrm{is\_transition}(y) = y-\omega_{H^{r_j}}^{-1}.
$$

3. Evaluates periodic columns at $y_j$ (each period-$p$ column is evaluated at
   $y_j^{n_j/p}$).

4. Folds constraints with challenge $\alpha$ using Horner accumulation:

$$
\mathrm{folded}_j
  = (((c_0\cdot\alpha + c_1)\cdot\alpha + c_2)\cdots)\cdot\alpha + c_k.
$$

5. Accumulates across instances using challenge $\beta$:

$$
\mathrm{acc} \leftarrow \mathrm{acc}\cdot\beta + \mathrm{folded}_j.
$$

Because lifting is composition by $X^{r_j}$, "evaluate then lift" matches
"lift then evaluate": $N_j^*(z) = N_j(z^{r_j})$. The verifier's accumulation
matches the prover's accumulation at the max point $z$.

### Quotient reconstruction at $z$

The prover commits to a single quotient object representing $Q$ on the max quotient
domain $gJ$, sent as $D$ "chunk" polynomials $q_0,\dots,q_{D-1}$ of degree $<N$.

At verification time we open each $q_t$ at $z$ and reconstruct $Q(z)$ via the
barycentric formula in `reconstruct_quotient`:

- Let $\omega_S := \omega_J^N$ be the $D$-th root of unity.
- Let $u := (z/g)^N$.
- Define weights

$$
  w_t := \frac{\omega_S^t}{u - \omega_S^t}.
$$

Then:

$$
Q(z) = \frac{\sum_{t=0}^{D-1} w_t\,q_t(z)}{\sum_{t=0}^{D-1} w_t}.
$$

### The quotient identity

After accumulating all folded constraint evaluations, the verifier checks:

$$
\mathrm{acc} = Q(z)\cdot Z_H(z),
\qquad
Z_H(z) = z^N - 1.
$$

This is the lifted analogue of the classic STARK quotient identity. It works for
mixed-height traces because each instance's constraints were evaluated at its projected
point $y_j = z^{r_j}$.
