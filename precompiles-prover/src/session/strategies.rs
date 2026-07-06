//! Pre-packaged MSM addition-chain strategies, layered on the Session's
//! MSM levers ([`msm_intro`](Session::msm_intro) /
//! [`msm_combine`](Session::msm_combine) / [`msm_neg`](Session::msm_neg)).
//!
//! Building a good addition chain for a multi-scalar multiplication is
//! NP-hard in general, so there is no single right chain — only heuristics
//! (Straus / Shamir, wNAF, GLV, Pippenger, …). The EcMsm chiplet is
//! deliberately **strategy-agnostic**: it checks only that each `combine`
//! is sound, never *which* chain produced the claim. So these helpers are
//! optional conveniences — a caller may use one, roll their own, or mix —
//! and they live *beside* the Session (free functions over `&mut Session`)
//! rather than on it, keeping the Session's own surface DAG-level.
//!
//! Two shapes here. [`straus`] / [`joint_naf`] are **joint** strategies: one
//! interleaved double-and-add over a table of *all* the bases — good when
//! the bases are unrelated and used once. The **wNAF** path is **separate**:
//! [`wnaf_table`] precomputes one base's odd multiples into a [`WnafTable`]
//! (stage 1), and [`wnaf_scalarmul`] takes that table as input to lay `k·P`
//! (stage 2). Splitting it lets a **recurring base reuse its table** — the
//! generator `G` across an N-batch of `kᵢ·G + …` is precomputed once and
//! every instance rides it (the table's combines bus-dedup to one copy).
//!
//! Each returns the combined [`EcExprPtr`]; tie it to a claimed point with
//! [`Session::ec_msm`].

use crate::ec::msm::trace::EcExprPtr;
use crate::math::U256;
use crate::session::{EcNode, Session};

/// Build `Σ sᵢ·Pᵢ` by **Straus's algorithm** (a.k.a. Shamir's trick for
/// `k = 2`): a joint MSB→LSB double-and-add over the `2ᵏ`-entry subset-sum
/// table of the `k` bases. One doubling per column serves *all* scalars —
/// the joint win over `k` separate ladders. With `k = 1` it degenerates to
/// a plain unsigned double-and-add. Returns the combined MSM expression
/// (resolve it with [`Session::ec_msm`]).
///
/// `terms` pairs each base point — a DAG [`EcNode`], since it is a claim
/// term and so is committed at resolve — with its scalar **value** (read
/// for its bits; the scalars themselves enter the DAG only as the resolve's
/// `Uint` children). The scan length is inferred from the widest scalar.
///
/// Costs `2ᵏ − k − 1` table combines, then ~`bits` doublings and ~`bits`
/// additions (one of each per column with a set digit). Keep `k` small —
/// the table is `2ᵏ`. Panics if `terms` is empty, `k > 16`, or every scalar
/// is zero. (A zero scalar wastes its base's intro + table entries; drop
/// such terms before calling.)
pub fn straus(session: &mut Session, terms: &[(EcNode, U256)]) -> EcExprPtr {
    let k = terms.len();
    assert!(k >= 1, "an MSM needs at least one base");
    assert!(k <= 16, "Straus' 2ᵏ table is impractical past k = 16");

    // Intro each base as ⟨Pⱼ×1⟩, then fill the subset-sum table:
    // `table[mask] = Σ_{j ∈ mask} Pⱼ` (the empty mask is ∞ = `None`). A
    // multi-base mask combines its lowest base off the rest — both already
    // built (smaller masks), so the strict `operand < result` ptr order
    // holds for free.
    let intros: Vec<EcExprPtr> = terms.iter().map(|(p, _)| session.msm_intro(p)).collect();
    let scalars: Vec<U256> = terms.iter().map(|(_, s)| *s).collect();
    let bits = scalars.iter().map(U256::bit_len).max().unwrap_or(0);
    let mut table: Vec<Option<EcExprPtr>> = vec![None; 1usize << k];
    for (j, &intro) in intros.iter().enumerate() {
        table[1usize << j] = Some(intro);
    }
    for mask in 1usize..(1usize << k) {
        if mask.count_ones() > 1 {
            let lsb = mask & mask.wrapping_neg(); // isolate the lowest set bit
            let rest = mask ^ lsb;
            let combined = session.msm_combine(table[rest].unwrap(), table[lsb].unwrap());
            table[mask] = Some(combined);
        }
    }

    // Joint double-and-add, MSB→LSB. `acc` lazy-seeds at the first column
    // whose digit mask is nonzero, then each step doubles and adds the
    // selected table entry (the column's set-bases sum).
    let mut acc: Option<EcExprPtr> = None;
    for i in (0..bits).rev() {
        let mask: usize = (0..k)
            .filter(|&j| scalars[j].bit(i))
            .map(|j| 1usize << j)
            .sum();
        let sel = table[mask];
        acc = match acc {
            None => sel,
            Some(a) => {
                let doubled = session.msm_combine(a, a);
                Some(match sel {
                    Some(t) => session.msm_combine(doubled, t),
                    None => doubled,
                })
            }
        };
    }
    acc.expect("at least one scalar must be nonzero")
}

/// Build `s₀·P + s₁·Q` by a **signed** joint double-and-add: each scalar in
/// non-adjacent form (NAF, digits `{−1, 0, 1}`), interleaved over the
/// signed table `{±P, ±Q, ±(P+Q), ±(P−Q)}` whose negatives are `neg`
/// nodes. The signed digits make the columns sparser than [`straus`]'s
/// unsigned ones (~5/9 of columns nonzero vs ~3/4), trading a larger table
/// (one combine + four negs of setup) for ~¼ fewer additions on full-size
/// scalars — the same value, a different (cheaper-for-large-`k`) chain.
/// (Solinas' true JSF would tighten the joint density to ~½; this
/// per-scalar NAF is the simpler cousin.)
///
/// A 2-base strategy (the signed table is `3ᵏ`-ish): `terms` must hold
/// exactly two `(base, scalar value)` pairs. Returns the combined MSM
/// expression. Panics if `terms.len() != 2` or both scalars are zero.
pub fn joint_naf(session: &mut Session, terms: &[(EcNode, U256)]) -> EcExprPtr {
    assert_eq!(terms.len(), 2, "joint_naf is a 2-base strategy");

    // The signed joint table {±P, ±Q, ±(P+Q), ±(P−Q)} — the ± are `neg`
    // nodes, the sums `combine`s (each operand built earlier, so the strict
    // `operand < result` ptr order holds).
    let p = session.msm_intro(&terms[0].0);
    let q = session.msm_intro(&terms[1].0);
    let pq = session.msm_combine(p, q); // P + Q
    let nq = session.msm_neg(q); // −Q
    let pmq = session.msm_combine(p, nq); // P − Q
    let np = session.msm_neg(p); // −P
    let npq = session.msm_neg(pq); // −(P + Q)
    let npmq = session.msm_neg(pmq); // −(P − Q) = Q − P
    let sel = |d0: i8, d1: i8| -> Option<EcExprPtr> {
        match (d0, d1) {
            (0, 0) => None,
            (1, 0) => Some(p),
            (-1, 0) => Some(np),
            (0, 1) => Some(q),
            (0, -1) => Some(nq),
            (1, 1) => Some(pq),
            (-1, -1) => Some(npq),
            (1, -1) => Some(pmq),
            (-1, 1) => Some(npmq),
            _ => unreachable!("NAF digits are in {{-1, 0, 1}}"),
        }
    };

    let naf0 = naf(terms[0].1);
    let naf1 = naf(terms[1].1);
    let len = naf0.len().max(naf1.len());
    let digit = |d: &[i8], i: usize| -> i8 { d.get(i).copied().unwrap_or(0) };

    // Joint double-and-add, MSB→LSB; one double per column, one add per
    // column whose digit pair is nonzero.
    let mut acc: Option<EcExprPtr> = None;
    for i in (0..len).rev() {
        let entry = sel(digit(&naf0, i), digit(&naf1, i));
        acc = match acc {
            None => entry,
            Some(a) => {
                let doubled = session.msm_combine(a, a);
                Some(match entry {
                    Some(t) => session.msm_combine(doubled, t),
                    None => doubled,
                })
            }
        };
    }
    acc.expect("at least one scalar must be nonzero")
}

// --- windowed NAF: per-base scalar-mul over a precomputed table ----------

/// A base's precomputed **wNAF table** — its odd multiples `⟨P×1⟩, ⟨P×3⟩,
/// …, ⟨P×(2^{w-1}−1)⟩` as MSM expressions. Built once by [`wnaf_table`]
/// (stage 1) and taken as input by [`wnaf_scalarmul`] (stage 2). The split
/// is the point: when a base recurs — the generator `G` across an N-batch
/// of `kᵢ·G + …` — its table is laid (and bus-deduped) a **single** time and
/// every scalar-mul on it rides the same odd multiples.
pub struct WnafTable {
    /// `odds[j] = ⟨P × (2j+1)⟩`, `j ∈ 0..2^{w-2}` — i.e. `1P, 3P, 5P, …`.
    odds: Vec<EcExprPtr>,
    /// Window width (digits are odd with `|d| < 2^{w-1}`).
    w: usize,
}

/// **wNAF stage 1** — precompute `base`'s [`WnafTable`] (odd multiples up to
/// `(2^{w-1}−1)·P`): `⟨P×1⟩`, then `+2P` repeatedly. `w ∈ [2, 8]` is the
/// window — a larger `w` thins the digits (≈ `1/(w+1)` nonzero) at a
/// `2^{w-2}`-entry table. Precompute a recurring base's table **once** and
/// share the result across every [`wnaf_scalarmul`] on it.
pub fn wnaf_table(session: &mut Session, base: &EcNode, w: usize) -> WnafTable {
    assert!((2..=8).contains(&w), "wNAF window w ∈ [2, 8]");
    let p1 = session.msm_intro(base); // ⟨P×1⟩
    let two_p = session.msm_combine(p1, p1); // ⟨P×2⟩ — the odd-multiple step
    let n_odds = 1usize << (w - 2);
    let mut odds = Vec::with_capacity(n_odds);
    odds.push(p1);
    let mut cur = p1;
    for _ in 1..n_odds {
        cur = session.msm_combine(cur, two_p); // shared base ⇒ +2P → next odd
        odds.push(cur);
    }
    WnafTable { odds, w }
}

/// **wNAF stage 2** — `k·P` via windowed NAF over a precomputed
/// [`WnafTable`] (MSB→LSB double-and-add; a negative digit is `neg` of the
/// table entry, itself deduped). Returns the single-term `⟨P×k⟩`. The table
/// is **borrowed**, so the same one serves every scalar on that base. Panics
/// if `k = 0`.
pub fn wnaf_scalarmul(session: &mut Session, table: &WnafTable, k: U256) -> EcExprPtr {
    let digits = wnaf(k, table.w);
    let mut acc: Option<EcExprPtr> = None;
    for i in (0..digits.len()).rev() {
        let d = digits[i];
        // `d·P`: the table holds `|d|·P`; negate it for a negative digit.
        let entry = (d != 0).then(|| {
            let pos = table.odds[(d.unsigned_abs() as usize - 1) / 2];
            if d > 0 { pos } else { session.msm_neg(pos) }
        });
        acc = match acc {
            None => entry, // lazy-seed at the top nonzero digit
            Some(a) => {
                let doubled = session.msm_combine(a, a);
                Some(match entry {
                    Some(t) => session.msm_combine(doubled, t),
                    None => doubled,
                })
            }
        };
    }
    acc.expect("wnaf_scalarmul needs k > 0")
}

/// Build `Σ kᵢ·Pᵢ` by **separate** wNAF scalar-muls — one
/// [`wnaf_scalarmul`] per `(table, scalar)` term, then combined. It takes the
/// precomputed [`WnafTable`]s as input, so a shared base's table (the
/// generator's, built once with [`wnaf_table`]) is reused across the batch
/// rather than rebuilt per term. Returns the combined MSM expression. Panics
/// if `terms` is empty.
pub fn wnaf_msm(session: &mut Session, terms: &[(&WnafTable, U256)]) -> EcExprPtr {
    let mut acc: Option<EcExprPtr> = None;
    for &(table, k) in terms {
        let term = wnaf_scalarmul(session, table, k);
        acc = Some(match acc {
            None => term,
            Some(a) => session.msm_combine(a, term),
        });
    }
    acc.expect("an MSM needs at least one term")
}

/// Build `Σ kᵢ·Pᵢ` by **interleaved** width-`w` wNAF: a single shared
/// double-and-add ladder (MSB→LSB), each base contributing its own wNAF
/// digit's table entry at each column. Unlike [`wnaf_msm`]'s *separate*
/// ladders (`m` × the doublings — the per-base doublings that made plain wNAF
/// lose to joint Straus on the 2-base shape), the doublings here are **shared
/// across all `m` bases**, so the doubling count is just the max scalar
/// bit-length; only the *adds* scale with `m`, and at the sparse wNAF density
/// (≈ `1/(w+1)` nonzero digits) rather than Straus's ≈ `1 − 2⁻ᵐ` per column.
///
/// This is the right chain for a **small-`m`, equal-length** MSM — GLV's four
/// ~128-bit halves: ~128 shared doublings + ~`m·128/(w+1)` adds, against a
/// 2-base 256-bit joint NAF's 256 doublings + ~`256/2` adds. `w = 4` (digits
/// `{±1,±3,±5,±7}`) is the sweet spot at this width: the `1/5` density beats
/// Straus's `15/16` columns while the `2ᵂ⁻²·m`-entry tables stay small.
///
/// `terms` pairs each base with its **non-negative** scalar (GLV signs ride
/// the base via [`ec_neg`](Session::ec_neg) upstream, so the magnitudes land
/// here); each base's [`WnafTable`] is built per call. Returns the combined
/// MSM expression. Panics if `terms` is empty or every scalar is zero.
pub fn joint_wnaf(session: &mut Session, terms: &[(EcNode, U256)], w: usize) -> EcExprPtr {
    let tables: Vec<WnafTable> = terms
        .iter()
        .map(|(p, _)| wnaf_table(session, p, w))
        .collect();
    let digits: Vec<Vec<i8>> = terms.iter().map(|(_, k)| wnaf(*k, w)).collect();
    let len = digits.iter().map(Vec::len).max().unwrap_or(0);

    let mut acc: Option<EcExprPtr> = None;
    for i in (0..len).rev() {
        // One shared doubling per column (skipped while acc is still unseeded,
        // so leading all-zero columns cost nothing).
        if let Some(a) = acc {
            acc = Some(session.msm_combine(a, a));
        }
        // Then each base adds its digit's (signed) table entry at this column.
        for (table, base_digits) in tables.iter().zip(&digits) {
            let d = base_digits.get(i).copied().unwrap_or(0);
            if d != 0 {
                let pos = table.odds[(d.unsigned_abs() as usize - 1) / 2];
                let entry = if d > 0 { pos } else { session.msm_neg(pos) };
                acc = Some(match acc {
                    None => entry, // lazy-seed at the first nonzero digit
                    Some(a) => session.msm_combine(a, entry),
                });
            }
        }
    }
    acc.expect("joint_wnaf needs a nonzero scalar")
}

/// Non-adjacent form of `k` (digits LSB-first, each in `{−1, 0, 1}`, no two
/// adjacent nonzero) — ~⅓ density vs binary's ½. `d = 2 − (k mod 4)` on the
/// odd steps (`k mod 4 ∈ {1, 3} → d ∈ {1, −1}`), then `k ← (k − d)/2`.
fn naf(mut k: U256) -> Vec<i8> {
    let one = U256::from(1u64);
    let mut out = Vec::new();
    while k > U256::ZERO {
        if k.bit(0) {
            let d: i8 = if k.bit(1) { -1 } else { 1 }; // 2 − (k mod 4)
            out.push(d);
            k = if d == 1 { k - one } else { k + one };
        } else {
            out.push(0);
        }
        k >>= 1usize;
    }
    out
}

/// Width-`w` non-adjacent form of `k` (digits LSB-first): each nonzero digit
/// is **odd** with `|d| < 2^{w-1}`, separated by ≥ `w−1` zeros — density
/// ≈ `1/(w+1)`. On an odd step `d = k mods 2^w` (the signed low `w` bits),
/// then `k ← k − d` (now even); every step halves `k`. (The `w = 2` case is
/// [`naf`].) `w ≤ 8`, so each digit fits an `i8`.
fn wnaf(mut k: U256, w: usize) -> Vec<i8> {
    let half = 1u64 << (w - 1); // 2^{w-1}
    let modulus = 1u64 << w; // 2^w
    let mut out = Vec::new();
    while k > U256::ZERO {
        let d: i64 = if k.bit(0) {
            // low `w` bits of `k`, then fold into the signed window.
            let low = (0..w)
                .filter(|&j| k.bit(j))
                .fold(0u64, |a, j| a | (1u64 << j));
            let d = if low >= half {
                low as i64 - modulus as i64
            } else {
                low as i64
            };
            k = if d >= 0 {
                k - U256::from(d as u64)
            } else {
                k + U256::from((-d) as u64)
            };
            d
        } else {
            0
        };
        out.push(d as i8);
        k >>= 1usize;
    }
    out
}
