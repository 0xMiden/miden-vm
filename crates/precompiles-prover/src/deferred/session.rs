//! Direct checked import of singleton portable witnesses into one private proving session.

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    vec,
    vec::Vec,
};

use miden_core::deferred::{
    DataChunk, Digest, MAX_DEFERRED_ELEMENTS, MAX_PRECOMPILE_ROOTS, Node, PrecompileWitness,
    PrecompileWitnessEntry, TRUE_DIGEST, Tag, fold_deferred_root,
};
use miden_precompiles::{
    CurveBinaryOp, CurveId, CurveOp, Keccak256Precompile, UintBinaryOp, UintDomain, UintOp,
    chunks_to_bytes_exact, n_chunks,
};

use crate::{
    ec::{msm::trace::EcExprPtr, trace::EcPointPtr},
    math::{U256, from_limbs32, to_limbs32},
    session::{EcNode, Session, Truthy, UintNode, strategies},
    transcript::poseidon2::P2Digest,
};

const MSM_WNAF_WINDOW: usize = 5;
const MAX_TERM_PRESERVING_TERMS: usize = 4096;
const MAX_TOTAL_TERM_PRESERVING_TERMS: usize = 16 * MAX_TERM_PRESERVING_TERMS;

/// The input ceiling uses the runtime's field-element accounting across the entire batch,
/// including repeated inputs. Each pair costs eight elements, so it also bounds total MSM terms
/// by MAX_DEFERRED_ELEMENTS / 8. Scalars are fixed at 256 bits; balanced reductions in the joint
/// ladder and fallback bound term-row work by O(n log n) per scalar bit, and sorted exact-multiset
/// validation takes O(n log n). The fallback's existing per-claim and per-session ceilings remain
/// in force.
///
/// Each chunk element encodes four bytes. Hash input demand is bounded separately by that same
/// payload capacity, since many distinct hash claims can reference one large chunk payload.
/// Every declared hash length is charged before sharing, including cache hits. These are input
/// dimensions, not estimates of trace rows or new weights for arithmetic operations.
#[derive(Clone, Copy)]
pub(crate) struct ImportLimits {
    pub(crate) elements: usize,
    pub(crate) hash_bytes: usize,
    pub(crate) roots: usize,
    pub(crate) fallback_terms_per_node: usize,
    pub(crate) fallback_terms: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            elements: MAX_DEFERRED_ELEMENTS,
            hash_bytes: MAX_DEFERRED_ELEMENTS * size_of::<u32>(),
            roots: MAX_PRECOMPILE_ROOTS,
            fallback_terms_per_node: MAX_TERM_PRESERVING_TERMS,
            fallback_terms: MAX_TOTAL_TERM_PRESERVING_TERMS,
        }
    }
}

/// Input positions use a zero-based witness number and one-based entry number (zero is TRUE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessLocation {
    Entry { witness: usize, entry: usize },
    Root { witness: usize },
    Batch,
}

/// Invalid portable input encountered before proof construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionInputError {
    #[error("empty precompile proving request")]
    Empty,
    #[error("invalid precompile input at {location:?}: {reason}")]
    Invalid {
        location: WitnessLocation,
        reason: &'static str,
    },
    #[error("precompile limit exhausted at {location:?}: {resource}")]
    Limit {
        location: WitnessLocation,
        resource: &'static str,
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
    #[cfg(test)]
    pub(crate) fn finish(self) -> crate::session::SessionTraces {
        self.session.finish(self.root)
    }
}

#[derive(Clone, Copy)]
enum Imported<'a> {
    True,
    Chunks(&'a [DataChunk]),
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

/// Cache entries borrow the original input, without cloning payloads or constructing a new graph.
struct Cached<'a> {
    definition: &'a PrecompileWitnessEntry,
    digests: &'a [Digest],
    value: Imported<'a>,
}

struct WitnessImporter {
    session: Session,
    wnaf_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    glv_endo_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    term_preserving_terms_left: usize,
    limits: ImportLimits,
    location: WitnessLocation,
}

#[cfg(test)]
pub(crate) fn session_from_witnesses(
    witnesses: Vec<PrecompileWitness>,
) -> Result<WitnessSession, SessionInputError> {
    import_witnesses(witnesses, ImportLimits::default())
}

pub(crate) fn prove(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: crate::HashFunction,
) -> Result<crate::PrecompileProof, crate::PrecompileProvingError> {
    let imported = {
        let _span = tracing::info_span!("build_session").entered();
        import_witnesses(witnesses, ImportLimits::default())?
    };
    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        imported.session.finish(imported.root)
    };
    Ok(crate::PrecompileProof {
        proof: traces.prove_stark(hash_fn)?,
        roots: imported.roots,
    })
}

pub(crate) fn import_witnesses(
    witnesses: Vec<PrecompileWitness>,
    limits: ImportLimits,
) -> Result<WitnessSession, SessionInputError> {
    if witnesses.is_empty() {
        return Err(SessionInputError::Empty);
    }
    if witnesses.len() > limits.roots {
        return Err(SessionInputError::Limit {
            location: WitnessLocation::Batch,
            resource: "constituent roots",
        });
    }

    // Reserve input/scan work before allocating a Session. Index tables remain local to each
    // singleton; retaining their commitments lets cache hits compare definitions across inputs.
    let mut elements_left = limits.elements;
    let mut hash_bytes_left = limits.hash_bytes;
    let mut index_tables = Vec::with_capacity(witnesses.len());
    for (witness_index, witness) in witnesses.iter().enumerate() {
        let location = WitnessLocation::Root { witness: witness_index };
        // Root metadata is bounded by limits.roots, including every repeated occurrence.
        // All but the first occurrence also adds a framework AND node.
        if witness_index != 0 {
            reserve(
                &mut elements_left,
                Tag::AND.as_word().len() + Node::PACKED_BYTES_PER_CHUNK / size_of::<u32>(),
                location,
                "aggregate folds",
            )?;
        }
        let mut digests = vec![TRUE_DIGEST];
        for (entry_index, entry) in witness.entries().iter().enumerate() {
            let location = WitnessLocation::Entry {
                witness: witness_index,
                entry: entry_index + 1,
            };
            let payloads = match entry {
                PrecompileWitnessEntry::Data { chunks, .. } => chunks.len(),
                PrecompileWitnessEntry::Join { .. } => 1,
                PrecompileWitnessEntry::PairList { pairs, .. } => pairs.len(),
            };
            let elements = payloads
                .checked_mul(Node::PACKED_BYTES_PER_CHUNK / size_of::<u32>())
                .and_then(|n| n.checked_add(Tag::AND.as_word().len()))
                .ok_or(SessionInputError::Limit { location, resource: "input elements" })?;
            reserve(&mut elements_left, elements, location, "input elements")?;
            if let Some(n_bytes) = Keccak256Precompile::decode_assert_tag(entry.tag())
                .map_err(|_| SessionInputError::Invalid { location, reason: "invalid hash tag" })?
            {
                reserve(&mut hash_bytes_left, n_bytes as usize, location, "hash input bytes")?;
            }
            digests.push(entry.digest(&digests).map_err(|_| SessionInputError::Invalid {
                location,
                reason: "invalid structural commitment",
            })?);
        }
        if digests.last().copied() != Some(witness.root()) {
            return Err(SessionInputError::Invalid {
                location,
                reason: "root commitment mismatch",
            });
        }
        index_tables.push(digests);
    }

    let mut import = WitnessImporter {
        session: Session::new(),
        wnaf_tables: BTreeMap::new(),
        glv_endo_tables: BTreeMap::new(),
        term_preserving_terms_left: limits.fallback_terms,
        limits,
        location: WitnessLocation::Batch,
    };
    let mut cache: BTreeMap<Digest, Cached<'_>> = BTreeMap::new();
    let mut roots = Vec::with_capacity(witnesses.len());
    let mut aggregate = None;
    for (witness_index, (witness, digests)) in witnesses.iter().zip(&index_tables).enumerate() {
        let mut entries = Vec::with_capacity(digests.len());
        entries.push(Imported::True);
        for (entry_index, entry) in witness.entries().iter().enumerate() {
            import.location = WitnessLocation::Entry {
                witness: witness_index,
                entry: entry_index + 1,
            };
            let digest = digests[entry_index + 1];
            let value = if let Some(previous) = cache.get(&digest) {
                if !same_definition(entry, digests, previous.definition, previous.digests) {
                    return Err(import.invalid("conflicting definition for a shared commitment"));
                }
                // This exact definition and each of its child commitments were already checked.
                // Reuse the computation; its later operand uses still count as distinct bindings.
                previous.value
            } else {
                let value = import.entry(entry, &entries)?;
                let hash = match value {
                    Imported::True | Imported::Chunks(_) => None,
                    Imported::Truth(node) => Some(node.hash()),
                    Imported::Uint(value) => Some(value.node.hash()),
                    Imported::Point(value) => Some(value.node.hash()),
                };
                if let Some(actual) = hash {
                    import.check_commitment(digest, actual)?;
                }
                cache.insert(digest, Cached { definition: entry, digests, value });
                value
            };
            entries.push(value);
        }
        import.location = WitnessLocation::Root { witness: witness_index };
        let Some(Imported::Truth(claim)) = entries.last().copied() else {
            return Err(import.invalid("root is not a true assertion"));
        };
        if !import.session.is_recorded_truth(claim) {
            return Err(import.invalid("bare external assertion cannot be a precompile root"));
        }
        import.check_commitment(witness.root(), claim.hash())?;
        aggregate = Some(match aggregate {
            None => claim,
            Some(previous) => import.session.assert_and(previous, claim),
        });
        roots.push(witness.root());
    }
    let root = aggregate.ok_or(SessionInputError::Empty)?;
    import.location = WitnessLocation::Batch;
    import.check_commitment(
        roots
            .iter()
            .copied()
            .reduce(fold_deferred_root)
            .ok_or(SessionInputError::Empty)?,
        root.hash(),
    )?;
    Ok(WitnessSession { session: import.session, root, roots })
}

fn reserve(
    remaining: &mut usize,
    amount: usize,
    location: WitnessLocation,
    resource: &'static str,
) -> Result<(), SessionInputError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(SessionInputError::Limit { location, resource })?;
    Ok(())
}

fn same_definition(
    a: &PrecompileWitnessEntry,
    a_digests: &[Digest],
    b: &PrecompileWitnessEntry,
    b_digests: &[Digest],
) -> bool {
    if a.tag() != b.tag() {
        return false;
    }
    match (a, b) {
        (
            PrecompileWitnessEntry::Data { chunks: a, .. },
            PrecompileWitnessEntry::Data { chunks: b, .. },
        ) => a == b,
        (
            PrecompileWitnessEntry::Join { lhs: a, rhs: b, .. },
            PrecompileWitnessEntry::Join { lhs: c, rhs: d, .. },
        ) => {
            a_digests[*a as usize] == b_digests[*c as usize]
                && a_digests[*b as usize] == b_digests[*d as usize]
        },
        (
            PrecompileWitnessEntry::PairList { pairs: a, .. },
            PrecompileWitnessEntry::PairList { pairs: b, .. },
        ) => {
            a.len() == b.len()
                && a.iter().zip(b).all(|((a, b), (c, d))| {
                    a_digests[*a as usize] == b_digests[*c as usize]
                        && a_digests[*b as usize] == b_digests[*d as usize]
                })
        },
        _ => false,
    }
}

impl WitnessImporter {
    fn invalid(&self, reason: &'static str) -> SessionInputError {
        SessionInputError::Invalid { location: self.location, reason }
    }

    fn check_commitment(
        &self,
        expected: Digest,
        actual: P2Digest,
    ) -> Result<(), SessionInputError> {
        if actual == P2Digest::from(expected) {
            Ok(())
        } else {
            Err(SessionInputError::Commitment {
                location: self.location,
                expected,
                actual: Digest::new(actual.as_array()),
            })
        }
    }
    fn get<'a>(
        &self,
        entries: &[Imported<'a>],
        index: u32,
    ) -> Result<Imported<'a>, SessionInputError> {
        entries
            .get(index as usize)
            .copied()
            .ok_or_else(|| self.invalid("invalid child index"))
    }
    fn truth(&mut self, entries: &[Imported<'_>], index: u32) -> Result<Truthy, SessionInputError> {
        match self.get(entries, index)? {
            Imported::True => Ok(self.session.zero()),
            Imported::Truth(value) => Ok(value),
            _ => Err(self.invalid("expected assertion operand")),
        }
    }
    fn uint(
        &self,
        entries: &[Imported<'_>],
        index: u32,
    ) -> Result<TranslatedUint, SessionInputError> {
        match self.get(entries, index)? {
            Imported::Uint(value) => Ok(value),
            _ => Err(self.invalid("expected uint operand")),
        }
    }
    fn point(
        &self,
        entries: &[Imported<'_>],
        index: u32,
    ) -> Result<TranslatedEc, SessionInputError> {
        match self.get(entries, index)? {
            Imported::Point(value) => Ok(value),
            _ => Err(self.invalid("expected curve operand")),
        }
    }
    fn chunks<'a>(
        &self,
        entries: &[Imported<'a>],
        index: u32,
    ) -> Result<&'a [DataChunk], SessionInputError> {
        match self.get(entries, index)? {
            Imported::Chunks(value) => Ok(value),
            _ => Err(self.invalid("expected chunks operand")),
        }
    }
    fn join(&self, entry: &PrecompileWitnessEntry) -> Result<(u32, u32), SessionInputError> {
        match entry {
            PrecompileWitnessEntry::Join { lhs, rhs, .. } => Ok((*lhs, *rhs)),
            _ => Err(self.invalid("operation requires two children")),
        }
    }
    fn entry<'a>(
        &mut self,
        entry: &'a PrecompileWitnessEntry,
        entries: &[Imported<'a>],
    ) -> Result<Imported<'a>, SessionInputError> {
        let tag = entry.tag();
        if tag == Tag::CHUNKS {
            return match entry {
                PrecompileWitnessEntry::Data { chunks, .. } => Ok(Imported::Chunks(chunks)),
                _ => Err(self.invalid("chunks require data payload")),
            };
        }
        if tag == Tag::AND {
            let (lhs, rhs) = self.join(entry)?;
            let lhs = self.truth(entries, lhs)?;
            let rhs = self.truth(entries, rhs)?;
            return Ok(Imported::Truth(self.session.assert_and(lhs, rhs)));
        }
        if let Some(n_bytes) = Keccak256Precompile::decode_assert_tag(tag)
            .map_err(|_| self.invalid("invalid hash tag"))?
        {
            let (input, expected) = self.join(entry)?;
            let n_bytes = n_bytes as usize;
            let input = chunks_to_bytes_exact(
                self.chunks(entries, input)?,
                n_chunks(n_bytes as u32).get() as usize,
                n_bytes,
            )
            .map_err(|_| self.invalid("malformed hash input chunks"))?;
            let expected = chunks_to_bytes_exact(self.chunks(entries, expected)?, 1, 32)
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
        if let Some(op) =
            UintOp::decode_tag(tag).map_err(|_| self.invalid("invalid uint tag or domain"))?
        {
            return match op {
                UintOp::Value(domain) => {
                    let PrecompileWitnessEntry::Data { chunks, .. } = entry else {
                        return Err(self.invalid("uint value requires data"));
                    };
                    let [chunk] = chunks.as_slice() else {
                        return Err(self.invalid("uint value requires one chunk"));
                    };
                    let mut limbs = [0u32; 8];
                    for (limb, felt) in limbs.iter_mut().zip(chunk) {
                        *limb = u32::try_from(felt.as_canonical_u64())
                            .map_err(|_| self.invalid("uint limb exceeds u32"))?;
                    }
                    if !domain.is_canonical(&limbs) {
                        return Err(self.invalid("uint value exceeds its domain"));
                    }
                    Ok(Imported::Uint(TranslatedUint {
                        node: self.session.uint_leaf(from_limbs32(&limbs), domain.bound_ptr()),
                        domain,
                    }))
                },
                UintOp::Binary(op) => {
                    let (a, b) = self.join(entry)?;
                    let a = self.uint(entries, a)?;
                    let b = self.uint(entries, b)?;
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
                    let (a, b) = self.join(entry)?;
                    let a = self.uint(entries, a)?;
                    let b = self.uint(entries, b)?;
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
        if let Some(op) = CurveOp::decode_tag(tag).map_err(|_| self.invalid("invalid curve tag"))? {
            return match op {
                CurveOp::Value(curve) => {
                    let (x, y) = self.join(entry)?;
                    let node = match (x == 0, y == 0) {
                        (true, true) => self.session.ec_pai(curve.group_ptr()),
                        (true, false) | (false, true) => {
                            return Err(self.invalid("incomplete infinity coordinates"));
                        },
                        (false, false) => {
                            let x = self.uint(entries, x)?;
                            let y = self.uint(entries, y)?;
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
                    let (a, b) = self.join(entry)?;
                    let a = self.point(entries, a)?;
                    let b = self.point(entries, b)?;
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
                    let (a, b) = self.join(entry)?;
                    let a = self.point(entries, a)?;
                    let b = self.point(entries, b)?;
                    if a.curve != b.curve {
                        return Err(self.invalid("point equality has different curves"));
                    }
                    if a.node.point != b.node.point {
                        return Err(self.invalid("false point equality"));
                    }
                    Ok(Imported::Truth(self.session.ec_is(&a.node, &b.node)))
                },
                CurveOp::Msm => {
                    let PrecompileWitnessEntry::PairList { pairs, .. } = entry else {
                        return Err(self.invalid("MSM requires a pair list"));
                    };
                    let &(first, _) = pairs.first().ok_or_else(|| self.invalid("empty MSM"))?;
                    let curve = self.point(entries, first)?.curve;
                    let mut terms = Vec::with_capacity(pairs.len());
                    for &(point, scalar) in pairs {
                        let point = self.point(entries, point)?;
                        let scalar = self.uint(entries, scalar)?;
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
                    let node = self.msm_from_terms(curve, terms)?;
                    Ok(Imported::Point(TranslatedEc { node, curve }))
                },
            };
        }
        Err(self.invalid("unsupported precompile operation"))
    }
    fn msm_from_terms(
        &mut self,
        curve: CurveId,
        terms: Vec<(TranslatedEc, TranslatedUint)>,
    ) -> Result<EcNode, SessionInputError> {
        // The entry decoder checked the nonempty pair list and every operand before lowering.
        self.session
            .constrain_scalar_bound(&terms[0].0.node, curve.scalar_domain().bound_ptr());

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

        let expr = if fast_path_eligible {
            self.msm_joint_expr(curve, &terms)
        } else {
            if terms.len() > self.limits.fallback_terms_per_node {
                return Err(SessionInputError::Limit {
                    location: self.location,
                    resource: "a PairList requiring the term-preserving fallback (a zero scalar \
                             or a repeated canonical base) exceeds the maximum supported term \
                             count",
                });
            }
            reserve(
                &mut self.term_preserving_terms_left,
                terms.len(),
                self.location,
                "this session's aggregate term-preserving fallback budget, summed \
                 across every PairList requiring it, is exhausted",
            )?;
            self.msm_term_preserving_expr(curve, &terms)
        };

        let claim_terms = terms
            .iter()
            .map(|(point, scalar)| (point.node, scalar.node))
            .collect::<Vec<_>>();
        Ok(self.session.ec_msm(expr, &claim_terms))
    }

    /// The joint/interleaved addition chain for a PairList whose declared
    /// bases are pairwise distinct and every scalar nonzero. `joint_wnaf`'s
    /// per-column term-row cost is O(n log n), using a balanced reduction rather than
    /// repeatedly copying a growing prefix. The batch input budget bounds its term count.
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
