//! Direct checked import of singleton portable witnesses into one private proving session.

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};

use miden_core::{
    deferred::{
        DEFERRED_AND_FRAME, DataChunk, Digest, MAX_PRECOMPILE_ROOTS, PrecompileLimits,
        PrecompileWitness, PreparationError, PreparedNode, PreparedWitness, TRUE_DIGEST,
        fold_deferred_root,
    },
    program::domain::DeferredChunksDomain,
};
use miden_crypto::hash::eidos::EidosDomain;
use miden_precompiles::{
    CurveBinaryOp, CurveId, CurveOp, Keccak256Precompile, UintBinaryOp, UintDomain, UintOp,
    UintPrecompile, chunks_to_bytes_exact, n_chunks,
};
use miden_precompiles_air::{memory, stark_config::precompile_pcs_params};

use crate::{
    PrecompileProvingError,
    ec::{msm::trace::EcExprPtr, trace::EcPointPtr},
    math::{U256, from_limbs32, to_limbs32},
    session::{EcNode, Session, Truthy, UintNode, strategies},
    transcript::eidos::EidosDigest,
};

/// wNAF window for [`msm_from_terms`](WitnessImporter::msm_from_terms)'s joint-wNAF
/// addition chain (digits odd, `|d| < 2^{w-1}`, `2^{w-2}` odd multiples per base). A smaller window
/// suits GLV's ~128-bit halves in isolation. Reusing a base's table across the batch makes ladder
/// digit density the dominant recurring cost; `w = 5` keeps it low for both the two-base and GLV
/// four-base MSMs.
const MSM_WNAF_WINDOW: usize = 5;

/// Input positions use a zero-based witness number and one-based entry number (zero is TRUE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessLocation {
    Entry { witness: usize, entry: usize },
    Root { witness: usize },
    Batch,
}

/// Invalid portable input encountered before proof construction.
#[derive(Debug, thiserror::Error)]
pub enum SessionInputError {
    #[error("empty precompile proving request")]
    Empty,
    #[error("invalid precompile input at {location:?}: {reason}")]
    Invalid {
        location: WitnessLocation,
        reason: &'static str,
    },
    #[error("precompile witness {witness} preparation failed: {source}")]
    Preparation {
        witness: usize,
        #[source]
        source: PreparationError,
    },
    #[error(
        "precompile witness {witness} root does not match its execution root: expected \
         {expected:?}, got {actual:?}"
    )]
    RootMismatch {
        witness: usize,
        expected: Digest,
        actual: Digest,
    },
    #[error("commitment mismatch at {location:?}: expected {expected:?}, got {actual:?}")]
    Commitment {
        location: WitnessLocation,
        expected: Digest,
        actual: Digest,
    },
}

pub(crate) struct WitnessSession {
    session: Session,
    root: Truthy,
    roots: Vec<Digest>,
}

impl WitnessSession {
    /// Estimates the completed Session's peak proving memory without applying a budget.
    fn estimated_prover_memory(&self, hash_fn: crate::HashFunction) -> Option<u64> {
        let params = precompile_pcs_params();
        self.session
            .trace_heights()
            .and_then(|heights| memory::prover_peak_bytes(&heights, &params, hash_fn))
    }

    #[cfg(test)]
    pub(crate) fn finish(self) -> crate::session::SessionTraces {
        self.session.finish(self.root)
    }
}

#[derive(Clone, Copy)]
enum Imported {
    True,
    Chunks,
    Truth(Truthy),
    Uint(TranslatedUint),
    Point(TranslatedEc),
}

#[derive(Debug, Clone, Copy)]
struct TranslatedUint {
    node: UintNode,
    domain: UintDomain,
}

#[derive(Debug, Clone, Copy)]
struct TranslatedEc {
    node: EcNode,
    curve: CurveId,
}

/// The canonical definition owns its payload; translated values refer only to our Session.
struct Cached {
    definition: PreparedNode,
    value: Imported,
}

struct WitnessImporter {
    session: Session,
    cache: BTreeMap<Digest, Cached>,
    wnaf_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    glv_endo_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    roots: Vec<Digest>,
    aggregate: Option<Truthy>,
    location: WitnessLocation,
}

#[cfg(test)]
pub(crate) fn session_from_witnesses(
    witnesses: Vec<PrecompileWitness>,
) -> Result<WitnessSession, PrecompileProvingError> {
    import_witnesses(witnesses, &miden_precompiles::default_verification_precompile_limits())
}

pub(crate) fn prove(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: crate::HashFunction,
    verification_limits: &PrecompileLimits,
    expected_roots: Option<&[Digest]>,
    max_prover_memory_bytes: u64,
) -> Result<crate::PrecompileProof, PrecompileProvingError> {
    let imported = {
        let _span = tracing::info_span!("build_session").entered();
        import_witnesses_with_roots(witnesses, verification_limits, expected_roots)?
    };
    crate::check_memory_budget(imported.estimated_prover_memory(hash_fn), max_prover_memory_bytes)?;

    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        imported.session.finish(imported.root)
    };
    Ok(crate::PrecompileProof {
        proof: traces.prove_stark(hash_fn)?,
        roots: imported.roots,
    })
}

#[cfg(test)]
pub(crate) fn import_witnesses(
    witnesses: Vec<PrecompileWitness>,
    verification_limits: &PrecompileLimits,
) -> Result<WitnessSession, PrecompileProvingError> {
    import_witnesses_with_roots(witnesses, verification_limits, None)
}

pub(crate) fn import_witnesses_with_roots(
    witnesses: Vec<PrecompileWitness>,
    verification_limits: &PrecompileLimits,
    expected_roots: Option<&[Digest]>,
) -> Result<WitnessSession, PrecompileProvingError> {
    if witnesses.is_empty() {
        return Err(SessionInputError::Empty.into());
    }
    if witnesses.len() > MAX_PRECOMPILE_ROOTS {
        return Err(PrecompileProvingError::BatchTooLarge {
            witnesses: witnesses.len(),
            max: MAX_PRECOMPILE_ROOTS,
        });
    }
    if expected_roots.is_some_and(|roots| roots.len() != witnesses.len()) {
        return Err(SessionInputError::Invalid {
            location: WitnessLocation::Batch,
            reason: "expected root count does not match witness count",
        }
        .into());
    }

    // Consume and admit every input independently, including repetitions. Root binding also
    // precedes Session creation: a late cheap rejection must win over any semantic import error.
    let registry = Arc::new(miden_precompiles::registry());
    let prepared = witnesses
        .into_iter()
        .enumerate()
        .map(|(witness, input)| {
            let prepared = input
                .prepare(Arc::clone(&registry), verification_limits)
                .map_err(|source| SessionInputError::Preparation { witness, source })?;
            if let Some(roots) = expected_roots {
                let expected = roots[witness];
                let actual = prepared.root();
                if actual != expected {
                    return Err(SessionInputError::RootMismatch { witness, expected, actual });
                }
            }
            Ok(prepared)
        })
        .collect::<Result<Vec<_>, SessionInputError>>()?;

    let mut importer = WitnessImporter::new();
    for witness in prepared {
        importer = importer.import(witness)?;
    }
    Ok(importer.finish()?)
}

impl WitnessImporter {
    fn new() -> Self {
        Self {
            session: Session::new(),
            cache: BTreeMap::new(),
            wnaf_tables: BTreeMap::new(),
            glv_endo_tables: BTreeMap::new(),
            roots: Vec::new(),
            aggregate: None,
            location: WitnessLocation::Batch,
        }
    }

    /// Evaluate and record together. An error consumes and drops the partially mutated Session.
    fn import(mut self, witness: PreparedWitness) -> Result<Self, SessionInputError> {
        let witness_index = self.roots.len();
        let root = witness.root();
        for (entry_index, prepared) in witness.into_nodes().enumerate() {
            self.location = WitnessLocation::Entry {
                witness: witness_index,
                entry: entry_index + 1,
            };
            let digest = prepared.digest();
            if let Some(previous) = self.cache.get(&digest) {
                if previous.definition.node() != prepared.node() {
                    return Err(self.invalid("conflicting definition for a shared commitment"));
                }
                // Reuse the computation; later operand uses still create their own bindings.
                continue;
            }
            let value = self.entry(&prepared)?;
            let hash = match value {
                Imported::True | Imported::Chunks => None,
                Imported::Truth(node) => Some(node.hash()),
                Imported::Uint(value) => Some(value.node.hash()),
                Imported::Point(value) => Some(value.node.hash()),
            };
            if let Some(actual) = hash {
                self.check_commitment(digest, actual)?;
            }
            self.cache.insert(digest, Cached { definition: prepared, value });
        }
        self.location = WitnessLocation::Root { witness: witness_index };
        let Imported::Truth(claim) = self.get(root) else {
            return Err(self.invalid("root is not a true assertion"));
        };
        if !self.session.is_recorded_truth(claim) {
            return Err(self.invalid("bare external assertion cannot be a precompile root"));
        }
        self.aggregate = Some(match self.aggregate {
            None => claim,
            Some(previous) => self.session.assert_and(previous, claim),
        });
        self.roots.push(root);
        Ok(self)
    }

    fn finish(mut self) -> Result<WitnessSession, SessionInputError> {
        let root = self.aggregate.expect("the batch is nonempty and every witness was imported");
        self.location = WitnessLocation::Batch;
        self.check_commitment(
            self.roots
                .iter()
                .copied()
                .reduce(fold_deferred_root)
                .expect("every imported witness contributes a root"),
            root.hash(),
        )?;
        Ok(WitnessSession {
            session: self.session,
            root,
            roots: self.roots,
        })
    }

    fn invalid(&self, reason: &'static str) -> SessionInputError {
        SessionInputError::Invalid { location: self.location, reason }
    }

    fn check_commitment(
        &self,
        expected: Digest,
        actual: EidosDigest,
    ) -> Result<(), SessionInputError> {
        if actual == EidosDigest::from(expected) {
            Ok(())
        } else {
            Err(SessionInputError::Commitment {
                location: self.location,
                expected,
                actual: Digest::new(actual.as_array()),
            })
        }
    }
    fn get(&self, digest: Digest) -> Imported {
        if digest == TRUE_DIGEST {
            return Imported::True;
        }
        self.cache.get(&digest).expect("prepared nodes are imported child-first").value
    }

    fn truth(&mut self, digest: Digest) -> Result<Truthy, SessionInputError> {
        match self.get(digest) {
            Imported::True => Ok(self.session.zero()),
            Imported::Truth(value) => Ok(value),
            _ => Err(self.invalid("expected assertion operand")),
        }
    }

    fn uint(&self, digest: Digest) -> Result<TranslatedUint, SessionInputError> {
        match self.get(digest) {
            Imported::Uint(value) => Ok(value),
            _ => Err(self.invalid("expected uint operand")),
        }
    }

    fn point(&self, digest: Digest) -> Result<TranslatedEc, SessionInputError> {
        match self.get(digest) {
            Imported::Point(value) => Ok(value),
            _ => Err(self.invalid("expected curve operand")),
        }
    }

    fn chunks(&self, digest: Digest) -> Result<&[DataChunk], SessionInputError> {
        match self.cache.get(&digest) {
            Some(Cached { definition, value: Imported::Chunks }) => {
                Ok(definition.node().payload().as_data().expect("prepared CHUNKS have data"))
            },
            _ => Err(self.invalid("expected chunks operand")),
        }
    }

    /// Preparation with the built-in registry establishes frames, shapes and references. Operand
    /// types, value encodings and assertion truth still require evaluation here.
    fn entry(&mut self, prepared: &PreparedNode) -> Result<Imported, SessionInputError> {
        let entry = prepared.node();
        let frame = entry.frame().expect("prepared nodes are not TRUE");
        let join = || entry.payload().as_join().expect("prepared operation has join shape");
        if frame.domain() == DeferredChunksDomain::TAG {
            return Ok(Imported::Chunks);
        }
        if frame == DEFERRED_AND_FRAME {
            let (lhs, rhs) = join();
            let lhs = self.truth(lhs)?;
            let rhs = self.truth(rhs)?;
            return Ok(Imported::Truth(self.session.assert_and(lhs, rhs)));
        }
        if let Some(n_bytes) = Keccak256Precompile::decode_assert_frame(frame)
            .expect("preparation validates hash frames")
        {
            let (input, expected) = join();
            let n_bytes = n_bytes as usize;
            let input = chunks_to_bytes_exact(
                self.chunks(input)?,
                n_chunks(n_bytes as u32).get() as usize,
                n_bytes,
            )
            .map_err(|_| self.invalid("malformed hash input chunks"))?;
            let expected = chunks_to_bytes_exact(self.chunks(expected)?, 1, 32)
                .map_err(|_| self.invalid("malformed expected hash chunks"))?;
            let (actual, claim) = self.session.keccak(&input);
            if !actual
                .to_u32s()
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .eq(expected.iter().copied())
            {
                return Err(self.invalid("false Keccak assertion"));
            }
            return Ok(Imported::Truth(claim));
        }
        if let Some(op) = UintOp::decode_frame(frame).expect("preparation validates uint frames") {
            return match op {
                UintOp::Value(domain) => {
                    let limbs = UintPrecompile::decode_value_node(entry, domain)
                        .map_err(|_| self.invalid("invalid uint value for its domain"))?;
                    Ok(Imported::Uint(TranslatedUint {
                        node: self.session.uint_leaf(from_limbs32(&limbs), domain.bound_ptr()),
                        domain,
                    }))
                },
                UintOp::Binary(op) => {
                    let (a, b) = join();
                    let a = self.uint(a)?;
                    let b = self.uint(b)?;
                    if a.domain != b.domain {
                        return Err(self.invalid("uint operands have different domains"));
                    }
                    let node = match op {
                        UintBinaryOp::Add => self.session.uint_add(&a.node, &b.node),
                        UintBinaryOp::Sub => self.session.uint_sub(&a.node, &b.node),
                        UintBinaryOp::Mul => self.session.uint_mul(&a.node, &b.node),
                    };
                    Ok(Imported::Uint(TranslatedUint { node, domain: a.domain }))
                },
                UintOp::Eq => {
                    let (a, b) = join();
                    let a = self.uint(a)?;
                    let b = self.uint(b)?;
                    if a.domain != b.domain {
                        return Err(self.invalid("uint equality has different domains"));
                    }
                    if a.node.ptr != b.node.ptr {
                        return Err(self.invalid("false uint equality"));
                    }
                    Ok(Imported::Truth(self.session.uint_is(&a.node, &b.node)))
                },
            };
        }
        if let Some(op) = CurveOp::decode_frame(frame).expect("preparation validates curve frames")
        {
            return match op {
                CurveOp::Value(curve) => {
                    let (x, y) = join();
                    let node = match (x == TRUE_DIGEST, y == TRUE_DIGEST) {
                        (true, true) => self.session.ec_pai(curve.group_ptr()),
                        (true, false) | (false, true) => {
                            return Err(self.invalid("incomplete infinity coordinates"));
                        },
                        (false, false) => {
                            let x = self.uint(x)?;
                            let y = self.uint(y)?;
                            if x.domain != curve.base_domain() || y.domain != curve.base_domain() {
                                return Err(self.invalid("curve coordinates use the wrong domain"));
                            }
                            curve
                                .point_from_affine(
                                    to_limbs32(self.session.uint_value(&x.node)),
                                    to_limbs32(self.session.uint_value(&y.node)),
                                )
                                .map_err(|_| self.invalid("point is not on the selected curve"))?;
                            self.session.ec_create(curve.group_ptr(), &x.node, &y.node)
                        },
                    };
                    Ok(Imported::Point(TranslatedEc { node, curve }))
                },
                CurveOp::Binary(op) => {
                    let (a, b) = join();
                    let a = self.point(a)?;
                    let b = self.point(b)?;
                    if a.curve != b.curve {
                        return Err(self.invalid("point operands have different curves"));
                    }
                    let node = match op {
                        CurveBinaryOp::Add => self.session.ec_add(&a.node, &b.node),
                        CurveBinaryOp::Sub => self.session.ec_sub(&a.node, &b.node),
                    };
                    Ok(Imported::Point(TranslatedEc { node, curve: a.curve }))
                },
                CurveOp::Eq => {
                    let (a, b) = join();
                    let a = self.point(a)?;
                    let b = self.point(b)?;
                    if a.curve != b.curve {
                        return Err(self.invalid("point equality has different curves"));
                    }
                    if a.node.point != b.node.point {
                        return Err(self.invalid("false point equality"));
                    }
                    Ok(Imported::Truth(self.session.ec_is(&a.node, &b.node)))
                },
                CurveOp::Msm(_) => {
                    let pairs =
                        entry.payload().as_pair_list().expect("prepared MSM has pair-list shape");
                    let (first, _) = pairs[0];
                    let curve = self.point(first)?.curve;
                    let mut terms = Vec::with_capacity(pairs.len());
                    for (point, scalar) in pairs {
                        let point = self.point(point)?;
                        let scalar = self.uint(scalar)?;
                        if point.curve != curve {
                            return Err(self.invalid("MSM mixes curves"));
                        }
                        if scalar.domain != curve.scalar_domain() {
                            return Err(self.invalid("MSM scalar uses the wrong domain"));
                        }
                        if self.session.is_pai(&point.node) {
                            return Err(self.invalid("MSM identity bases are unsupported"));
                        }
                        terms.push((point, scalar));
                    }
                    let node = self.msm_from_terms(curve, terms);
                    Ok(Imported::Point(TranslatedEc { node, curve }))
                },
            };
        }
        unreachable!("preparation uses the built-in registry")
    }
    fn msm_from_terms(
        &mut self,
        curve: CurveId,
        terms: Vec<(TranslatedEc, TranslatedUint)>,
    ) -> EcNode {
        // The entry decoder checked the nonempty pair list and every operand before lowering.

        // Zero scalars are always fine (0·P = 𝒪); repeated canonical bases —
        // including two structurally different point nodes that resolve to
        // the same canonical point — are fine too. Both need the
        // term-preserving fallback below rather than the fast joint ladder:
        // a zero scalar has no wNAF digit expansion to interleave (the
        // ladder's `intro`-only leaves are always nonzero), and a repeated
        // base would otherwise auto-merge two distinct claim terms onto one
        // chiplet row. When every declared base is distinct and every
        // scalar nonzero, the fast path already produces one row per
        // declared term (auto-merge never fires across distinct bases), so
        // it stays the default.
        let mut bases = BTreeSet::new();
        let fast_path_eligible = terms.iter().all(|(point, scalar)| {
            self.session.uint_value(&scalar.node) != U256::ZERO && bases.insert(point.node.point)
        });

        // Preparation charged every declared term, conservatively covering either lowering.
        self.session
            .constrain_scalar_bound(&terms[0].0.node, curve.scalar_domain().bound_ptr());
        let expr = if fast_path_eligible {
            self.msm_joint_expr(curve, &terms)
        } else {
            self.msm_term_preserving_expr(curve, &terms)
        };

        let claim_terms = terms
            .iter()
            .map(|(point, scalar)| (point.node, scalar.node))
            .collect::<Vec<_>>();
        self.session.ec_msm(expr, &claim_terms)
    }

    /// The joint/interleaved addition chain for a PairList whose declared
    /// bases are pairwise distinct and every scalar nonzero. `joint_wnaf`'s
    /// per-column term-row cost is O(n log n), using a balanced reduction rather than
    /// repeatedly copying a growing prefix. The per-witness MSM policy bounds its term count.
    ///
    /// GLV curves split each term's scalar in half (`glv_joint_wnaf_with_tables`),
    /// trading ~half the ladder height for twice the virtual bases —
    /// `msm_combine`'s shared-base merge folds each pair's plain/endo
    /// legs back onto the caller's original term, so the claim is
    /// unaffected either way. Both tables are cached per `(point,
    /// window)` the same way the plain path's are (a recurring base —
    /// the ECDSA generator across a batch of signatures — lays each
    /// table once); sign rides the digit selection inside
    /// `glv_joint_wnaf_with_tables`, not the table's seed, so a shared
    /// base's tables serve every claim's GLV split regardless of sign.
    fn msm_joint_expr(
        &mut self,
        curve: CurveId,
        terms: &[(TranslatedEc, TranslatedUint)],
    ) -> EcExprPtr {
        let expr_terms = terms
            .iter()
            .map(|(point, scalar)| (point.node, self.session.uint_value(&scalar.node)))
            .collect::<Vec<_>>();
        if curve.endomorphism().is_some() {
            for (base, _) in &expr_terms {
                self.ensure_wnaf_table(base, MSM_WNAF_WINDOW);
                self.ensure_wnaf_table_endo(base, MSM_WNAF_WINDOW);
            }
            let table_terms: Vec<(&strategies::WnafTable, Option<&strategies::WnafTable>, U256)> =
                expr_terms
                    .iter()
                    .map(|(base, scalar)| {
                        let plain = self.wnaf_tables.get(&(base.point, MSM_WNAF_WINDOW)).unwrap();
                        let endo =
                            self.glv_endo_tables.get(&(base.point, MSM_WNAF_WINDOW)).unwrap();
                        (plain, Some(endo), *scalar)
                    })
                    .collect();
            strategies::glv_joint_wnaf_with_tables(&mut self.session, &table_terms)
        } else {
            for (base, _) in &expr_terms {
                self.ensure_wnaf_table(base, MSM_WNAF_WINDOW);
            }
            let table_terms: Vec<(&strategies::WnafTable, U256)> = expr_terms
                .iter()
                .map(|(base, scalar)| {
                    (self.wnaf_tables.get(&(base.point, MSM_WNAF_WINDOW)).unwrap(), *scalar)
                })
                .collect();
            strategies::joint_wnaf_with_tables(&mut self.session, &table_terms)
        }
    }

    /// The one-term-at-a-time fallback for a PairList with a zero scalar or
    /// a repeated canonical base. Every term is built into its own leaf
    /// expression, then folded pairwise in a balanced binary tree via
    /// `msm_combine_terms_preserving`, which keeps every declared term
    /// distinct instead of interleaving bases through `joint_wnaf`.
    ///
    /// `msm_combine_terms_preserving` copies both operands' terms into new
    /// rows on every call, so its cost is proportional to the sum of its two
    /// operands' term counts. A left-to-right fold pays for the whole
    /// growing prefix at every step (`1 + 2 + ... + n = O(n^2)` rows for `n`
    /// leaves); the balanced tree here does `O(n)` row work per level across
    /// `O(log n)` levels instead.
    fn msm_term_preserving_expr(
        &mut self,
        curve: CurveId,
        terms: &[(TranslatedEc, TranslatedUint)],
    ) -> EcExprPtr {
        let mut level: Vec<EcExprPtr> = terms
            .iter()
            .map(|(point, scalar)| self.msm_term_preserving_leaf(curve, point, scalar))
            .collect();

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut pairs = level.into_iter();
            while let Some(a) = pairs.next() {
                next.push(match pairs.next() {
                    Some(b) => self.session.msm_combine_terms_preserving(a, b),
                    None => a,
                });
            }
            level = next;
        }
        level.into_iter().next().expect("msm_from_terms guarantees a nonempty PairList")
    }

    /// Builds one term-preserving-fallback leaf: `msm_intro_zero` for a zero
    /// scalar, otherwise a plain or GLV wNAF ladder over the single term.
    fn msm_term_preserving_leaf(
        &mut self,
        curve: CurveId,
        point: &TranslatedEc,
        scalar: &TranslatedUint,
    ) -> EcExprPtr {
        let scalar_value = self.session.uint_value(&scalar.node);
        if scalar_value == U256::ZERO {
            self.session.msm_intro_zero(&point.node)
        } else if curve.endomorphism().is_some() {
            self.ensure_wnaf_table(&point.node, MSM_WNAF_WINDOW);
            self.ensure_wnaf_table_endo(&point.node, MSM_WNAF_WINDOW);
            let plain = self.wnaf_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            let endo = self.glv_endo_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            strategies::glv_joint_wnaf_with_tables(
                &mut self.session,
                &[(plain, Some(endo), scalar_value)],
            )
        } else {
            self.ensure_wnaf_table(&point.node, MSM_WNAF_WINDOW);
            let table = self.wnaf_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            strategies::wnaf_scalarmul(&mut self.session, table, scalar_value)
        }
    }

    /// Ensures `base`'s [`WnafTable`](strategies::WnafTable) at window `w` is
    /// in [`Self::wnaf_tables`], building it once via
    /// [`wnaf_table`](strategies::wnaf_table) on the first request and
    /// reusing it for every later claim that rides the same base.
    fn ensure_wnaf_table(&mut self, base: &EcNode, w: usize) {
        if let Entry::Vacant(entry) = self.wnaf_tables.entry((base.point, w)) {
            entry.insert(strategies::wnaf_table(&mut self.session, base, w));
        }
    }

    /// [`Self::ensure_wnaf_table`]'s GLV endomorphism-leg twin: ensures
    /// `base`'s endomorphism [`WnafTable`](strategies::WnafTable) at window
    /// `w` is in [`Self::glv_endo_tables`], building it once via
    /// [`wnaf_table_endo`](strategies::wnaf_table_endo).
    fn ensure_wnaf_table_endo(&mut self, base: &EcNode, w: usize) {
        if let Entry::Vacant(entry) = self.glv_endo_tables.entry((base.point, w)) {
            entry.insert(strategies::wnaf_table_endo(&mut self.session, base, w));
        }
    }
}
