use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    vec::Vec,
};

use miden_core::deferred::{DataChunk, DeferredState, Digest, Node, TRUE_DIGEST, Tag};
use miden_precompiles::{
    CurveId, CurveNodeRef, CurvePrecompile, HashAssertNode, Keccak256Precompile, UintDomain,
    UintNodeRef, UintPrecompile, chunks_to_bytes_exact, n_chunks,
};

use crate::{
    ec::{msm::trace::EcExprPtr, trace::EcPointPtr},
    math::{U256, from_limbs32},
    session::{EcNode, Session, Truthy, UintNode, strategies},
    transcript::poseidon2::P2Digest,
};

/// wNAF window for [`translate_ec_msm`](DeferredSessionBuilder::translate_ec_msm)'s joint-wNAF
/// addition chain (digits odd, `|d| < 2^{w-1}`, `2^{w-2}` odd multiples per base). A smaller window
/// suits GLV's ~128-bit halves in isolation, but `translate_ec_msm` now caches a repeating base's
/// table across the whole batch ([`Self::wnaf_tables`](DeferredSessionBuilder::wnaf_tables)), which
/// makes the one-time table-build cost a wash and leaves the ladder's per-signature digit density
/// as the dominant recurring cost — `w = 5` keeps that density low for both the classic 2-base MSM
/// and GLV's 4-base one.
const MSM_WNAF_WINDOW: usize = 5;

/// Cap on the term count a PairList may carry into
/// [`msm_term_preserving_expr`](DeferredSessionBuilder::msm_term_preserving_expr) (the fallback
/// for a zero scalar or a repeated canonical base). Even with a balanced fold the fallback's row
/// cost grows as `O(n log n)`, unlike the fast joint ladder's `O(n)`; this bounds that cost before
/// any fallback rows are built.
const MAX_TERM_PRESERVING_TERMS: usize = 4096;

/// Cap on the *sum* of fallback term counts across every PairList this session lowers.
/// [`MAX_TERM_PRESERVING_TERMS`] only bounds one claim at a time — many claims each near that cap
/// still stack up (a lowering-only PairList doesn't know about sibling claims), so this tracks a
/// running total and rejects a new claim before it grows the aggregate past this bound. A generous
/// multiple of the per-claim cap: legitimate batches (e.g. many small ECDSA-style fallback claims)
/// stay well under it, while an attacker can no longer bypass the per-claim bound by splitting one
/// oversized ask into many claims.
const MAX_TOTAL_TERM_PRESERVING_TERMS: usize = 16 * MAX_TERM_PRESERVING_TERMS;

pub(crate) struct DeferredSession {
    pub(crate) session: Session,
    pub(crate) root: Truthy,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeferredSessionError {
    #[error("missing deferred node {0:?}")]
    MissingNode(Digest),

    #[error("deferred node {digest:?} is not lowerable as {expected}")]
    TypeMismatch { digest: Digest, expected: &'static str },

    #[error("malformed deferred node {0:?}")]
    MalformedNode(Digest),

    #[error("unsupported deferred MSM node {digest:?}: {reason}")]
    UnsupportedMsm { digest: Digest, reason: &'static str },

    #[error("translated root mismatch: expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: P2Digest, actual: P2Digest },
}

pub(crate) fn session_from_deferred_state(
    state: &DeferredState,
) -> Result<DeferredSession, DeferredSessionError> {
    let mut builder = DeferredSessionBuilder {
        state,
        session: Session::new(),
        wnaf_tables: BTreeMap::new(),
        glv_endo_tables: BTreeMap::new(),
        term_preserving_terms_used: 0,
    };

    let root = builder.translate_truthy(state.root())?;
    let expected = P2Digest::from(state.root());
    let actual = root.hash();
    if actual != expected {
        return Err(DeferredSessionError::RootMismatch { expected, actual });
    }

    Ok(DeferredSession { session: builder.session, root })
}

// TODO: Add translator-level value caches if repeated traversal becomes measurable. Truthy
// handles must remain uncached because they are linear session handles consumed by folds.
struct DeferredSessionBuilder<'a> {
    state: &'a DeferredState,
    session: Session,
    /// A base's plain [`WnafTable`](strategies::WnafTable) (`⟨P×1⟩`), by
    /// `(point, window)` — so a base recurring across many MSM claims in this
    /// pass (the ECDSA generator across a batch of signatures) lays its
    /// table once and every claim that rides it reuses the same one.
    wnaf_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    /// A base's GLV endomorphism [`WnafTable`](strategies::WnafTable)
    /// (`⟨P×λ⟩`), cached the same way as [`Self::wnaf_tables`] — both tables
    /// are built positive-only (see [`strategies::wnaf_table_endo`]), so a
    /// recurring base's tables are shared across every claim on it
    /// regardless of each claim's GLV split signs.
    glv_endo_tables: BTreeMap<(EcPointPtr, usize), strategies::WnafTable>,
    /// Running total of term-preserving-fallback terms lowered so far this session, checked
    /// against [`MAX_TOTAL_TERM_PRESERVING_TERMS`] before each new claim's fallback rows are
    /// built.
    term_preserving_terms_used: usize,
}

#[derive(Debug, Clone, Copy)]
struct TranslatedUint {
    node: UintNode,
    value: U256,
    domain: UintDomain,
}

#[derive(Debug, Clone, Copy)]
struct TranslatedEc {
    node: EcNode,
    curve: CurveId,
}

impl<'a> DeferredSessionBuilder<'a> {
    fn translate_truthy(&mut self, digest: Digest) -> Result<Truthy, DeferredSessionError> {
        self.require_truthy_metadata(digest)?;

        if digest == TRUE_DIGEST {
            return Ok(self.session.zero());
        }

        let tag = self.node_tag(digest)?;
        if tag == Tag::AND {
            let (lhs, rhs) = self.join_payload(digest)?;
            let lhs = self.translate_truthy(lhs)?;
            let rhs = self.translate_truthy(rhs)?;
            let node = self.session.assert_and(lhs, rhs);
            debug_assert_eq!(node.hash(), P2Digest::from(digest));
            return Ok(node);
        }

        if let Some(assertion) = Keccak256Precompile::decode_assert_node(self.node(digest)?)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?
        {
            return self.translate_keccak_assertion(digest, assertion);
        }

        match UintPrecompile::decode_node(self.node(digest)?)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?
        {
            Some(UintNodeRef::Eq { lhs, rhs }) => {
                let lhs = self.translate_uint(lhs)?;
                let rhs = self.translate_uint(rhs)?;
                let node = self.session.uint_is(&lhs.node, &rhs.node);
                debug_assert_eq!(node.hash(), P2Digest::from(digest));
                return Ok(node);
            },
            Some(_) => {
                return Err(DeferredSessionError::TypeMismatch {
                    digest,
                    expected: "truthy deferred node",
                });
            },
            None => {},
        }

        match CurvePrecompile::decode_node(self.node(digest)?)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?
        {
            Some(CurveNodeRef::Eq { lhs, rhs }) => {
                let lhs = self.translate_ec(lhs)?;
                let rhs = self.translate_ec(rhs)?;
                let node = self.session.ec_is(&lhs.node, &rhs.node);
                debug_assert_eq!(node.hash(), P2Digest::from(digest));
                Ok(node)
            },
            Some(_) | None => {
                Err(DeferredSessionError::TypeMismatch { digest, expected: "truthy deferred node" })
            },
        }
    }

    fn translate_uint(&mut self, digest: Digest) -> Result<TranslatedUint, DeferredSessionError> {
        let (value, domain) = self.canonical_uint_metadata(digest)?;
        let decoded = UintPrecompile::decode_node(self.node(digest)?)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?;

        let node = match decoded {
            Some(UintNodeRef::Value { domain: structural_domain, limbs }) => {
                if structural_domain != domain {
                    return Err(DeferredSessionError::MalformedNode(digest));
                }
                debug_assert_eq!(from_limbs32(&limbs), value);
                self.session.uint_leaf(value, domain.bound_ptr())
            },
            Some(UintNodeRef::Add { lhs, rhs }) => {
                let lhs = self.translate_uint(lhs)?;
                let rhs = self.translate_uint(rhs)?;
                debug_assert_eq!(lhs.domain, rhs.domain);
                self.session.uint_add(&lhs.node, &rhs.node)
            },
            Some(UintNodeRef::Sub { lhs, rhs }) => {
                let lhs = self.translate_uint(lhs)?;
                let rhs = self.translate_uint(rhs)?;
                debug_assert_eq!(lhs.domain, rhs.domain);
                self.session.uint_sub(&lhs.node, &rhs.node)
            },
            Some(UintNodeRef::Mul { lhs, rhs }) => {
                let lhs = self.translate_uint(lhs)?;
                let rhs = self.translate_uint(rhs)?;
                debug_assert_eq!(lhs.domain, rhs.domain);
                self.session.uint_mul(&lhs.node, &rhs.node)
            },
            Some(UintNodeRef::Eq { .. }) | None => {
                return Err(DeferredSessionError::TypeMismatch { digest, expected: "uint value" });
            },
        };

        debug_assert_eq!(node.hash(), P2Digest::from(digest));
        Ok(TranslatedUint { node, value, domain })
    }

    fn translate_ec(&mut self, digest: Digest) -> Result<TranslatedEc, DeferredSessionError> {
        let curve = self.canonical_ec_metadata(digest)?;
        let decoded = CurvePrecompile::decode_node(self.node(digest)?)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?;

        let node = match decoded {
            Some(CurveNodeRef::Value { curve: structural_curve, x, y }) => {
                if structural_curve != curve {
                    return Err(DeferredSessionError::MalformedNode(digest));
                }

                match (x == TRUE_DIGEST, y == TRUE_DIGEST) {
                    (true, true) => self.session.ec_pai(curve.group_ptr()),
                    (true, false) | (false, true) => {
                        return Err(DeferredSessionError::MalformedNode(digest));
                    },
                    (false, false) => {
                        let x = self.translate_uint(x)?;
                        let y = self.translate_uint(y)?;
                        debug_assert_eq!(x.domain, curve.base_domain());
                        debug_assert_eq!(y.domain, curve.base_domain());
                        self.session.ec_create(curve.group_ptr(), &x.node, &y.node)
                    },
                }
            },
            Some(CurveNodeRef::Add { lhs, rhs }) => {
                let lhs = self.translate_ec(lhs)?;
                let rhs = self.translate_ec(rhs)?;
                debug_assert_eq!(lhs.curve, rhs.curve);
                self.session.ec_add(&lhs.node, &rhs.node)
            },
            Some(CurveNodeRef::Sub { lhs, rhs }) => {
                let lhs = self.translate_ec(lhs)?;
                let rhs = self.translate_ec(rhs)?;
                debug_assert_eq!(lhs.curve, rhs.curve);
                self.session.ec_sub(&lhs.node, &rhs.node)
            },
            Some(CurveNodeRef::Msm { pairs }) => self.translate_ec_msm(digest, curve, pairs)?,
            Some(CurveNodeRef::Eq { .. }) | None => {
                return Err(DeferredSessionError::TypeMismatch { digest, expected: "curve value" });
            },
        };

        debug_assert_eq!(node.hash(), P2Digest::from(digest));
        Ok(TranslatedEc { node, curve })
    }

    fn translate_keccak_assertion(
        &mut self,
        digest: Digest,
        assertion: HashAssertNode,
    ) -> Result<Truthy, DeferredSessionError> {
        let n_bytes = usize::try_from(assertion.n_bytes)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?;
        let input = self.decode_chunks_to_bytes(digest, assertion.preimage_digest, n_bytes)?;
        let expected = self.decode_keccak_digest_bytes(digest, assertion.expected_digest)?;

        let (actual, claim) = self.session.keccak(&input);
        let actual = actual.to_u32s().into_iter().flat_map(u32::to_le_bytes).collect::<Vec<_>>();
        debug_assert_eq!(expected, actual);
        debug_assert_eq!(claim.hash(), P2Digest::from(digest));
        Ok(claim)
    }

    fn translate_ec_msm(
        &mut self,
        digest: Digest,
        curve: CurveId,
        pairs: Vec<(Digest, Digest)>,
    ) -> Result<EcNode, DeferredSessionError> {
        // A nonempty PairList carries the curve context every term below
        // relies on; an empty one has none, so it stays invalid.
        if pairs.is_empty() {
            return Err(DeferredSessionError::UnsupportedMsm {
                digest,
                reason: "an empty PairList has no curve context",
            });
        }

        let mut terms = Vec::with_capacity(pairs.len());
        for (point_digest, scalar_digest) in pairs {
            let point = self.translate_ec(point_digest)?;
            let scalar = self.translate_uint(scalar_digest)?;
            debug_assert_eq!(point.curve, curve);
            debug_assert_eq!(scalar.domain, curve.scalar_domain());
            if self.session.is_pai(&point.node) {
                return Err(DeferredSessionError::UnsupportedMsm {
                    digest,
                    reason: "an identity (point-at-infinity) base is not supported",
                });
            }
            terms.push((point, scalar));
        }

        if let Some((point, _)) = terms.first() {
            self.session
                .constrain_scalar_bound(&point.node, curve.scalar_domain().bound_ptr());
        }

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
        let fast_path_eligible = terms
            .iter()
            .all(|(point, scalar)| scalar.value != U256::ZERO && bases.insert(point.node.point));

        let expr = if fast_path_eligible {
            self.msm_joint_expr(curve, &terms)
        } else {
            if terms.len() > MAX_TERM_PRESERVING_TERMS {
                return Err(DeferredSessionError::UnsupportedMsm {
                    digest,
                    reason: "a PairList requiring the term-preserving fallback (a zero scalar \
                             or a repeated canonical base) exceeds the maximum supported term \
                             count",
                });
            }
            let total = self.term_preserving_terms_used.saturating_add(terms.len());
            if total > MAX_TOTAL_TERM_PRESERVING_TERMS {
                return Err(DeferredSessionError::UnsupportedMsm {
                    digest,
                    reason: "this session's aggregate term-preserving fallback budget, summed \
                             across every PairList requiring it, is exhausted",
                });
            }
            self.term_preserving_terms_used = total;
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
    /// per-column cost is linear in the term count (unlike Straus's `2^k`
    /// subset-sum table), so an arbitrary-arity pair-list never needs a
    /// term-count cap here.
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
            .map(|(point, scalar)| (point.node, scalar.value))
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
        level
            .into_iter()
            .next()
            .expect("translate_ec_msm guarantees a nonempty PairList")
    }

    /// Builds one term-preserving-fallback leaf: `msm_intro_zero` for a zero
    /// scalar, otherwise a plain or GLV wNAF ladder over the single term.
    fn msm_term_preserving_leaf(
        &mut self,
        curve: CurveId,
        point: &TranslatedEc,
        scalar: &TranslatedUint,
    ) -> EcExprPtr {
        if scalar.value == U256::ZERO {
            self.session.msm_intro_zero(&point.node)
        } else if curve.endomorphism().is_some() {
            self.ensure_wnaf_table(&point.node, MSM_WNAF_WINDOW);
            self.ensure_wnaf_table_endo(&point.node, MSM_WNAF_WINDOW);
            let plain = self.wnaf_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            let endo = self.glv_endo_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            strategies::glv_joint_wnaf_with_tables(
                &mut self.session,
                &[(plain, Some(endo), scalar.value)],
            )
        } else {
            self.ensure_wnaf_table(&point.node, MSM_WNAF_WINDOW);
            let table = self.wnaf_tables.get(&(point.node.point, MSM_WNAF_WINDOW)).unwrap();
            strategies::wnaf_scalarmul(&mut self.session, table, scalar.value)
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

    fn require_truthy_metadata(&self, digest: Digest) -> Result<(), DeferredSessionError> {
        let (canonical_digest, canonical_node) = self
            .state
            .require_canonical_node(digest)
            .map_err(|_| DeferredSessionError::MissingNode(digest))?;
        if canonical_digest != TRUE_DIGEST || !canonical_node.is_true() {
            return Err(DeferredSessionError::TypeMismatch {
                digest,
                expected: "truthy deferred node",
            });
        }
        Ok(())
    }

    fn canonical_uint_metadata(
        &self,
        digest: Digest,
    ) -> Result<(U256, UintDomain), DeferredSessionError> {
        let (_, canonical_node) = self
            .state
            .require_canonical_node(digest)
            .map_err(|_| DeferredSessionError::MissingNode(digest))?;
        match UintPrecompile::decode_node(canonical_node)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?
        {
            Some(UintNodeRef::Value { domain, limbs }) => Ok((from_limbs32(&limbs), domain)),
            Some(_) | None => {
                Err(DeferredSessionError::TypeMismatch { digest, expected: "uint value" })
            },
        }
    }

    fn canonical_ec_metadata(&self, digest: Digest) -> Result<CurveId, DeferredSessionError> {
        let (_, canonical_node) = self
            .state
            .require_canonical_node(digest)
            .map_err(|_| DeferredSessionError::MissingNode(digest))?;
        match CurvePrecompile::decode_node(canonical_node)
            .map_err(|_| DeferredSessionError::MalformedNode(digest))?
        {
            Some(CurveNodeRef::Value { curve, .. }) => Ok(curve),
            Some(_) | None => {
                Err(DeferredSessionError::TypeMismatch { digest, expected: "curve value" })
            },
        }
    }

    fn node(&self, digest: Digest) -> Result<&'a Node, DeferredSessionError> {
        self.state.get_node(&digest).ok_or(DeferredSessionError::MissingNode(digest))
    }

    fn node_tag(&self, digest: Digest) -> Result<Tag, DeferredSessionError> {
        Ok(self.node(digest)?.tag())
    }

    fn join_payload(&self, digest: Digest) -> Result<(Digest, Digest), DeferredSessionError> {
        self.node(digest)?
            .payload()
            .as_join()
            .map_err(|_| DeferredSessionError::MalformedNode(digest))
    }

    fn chunks_payload(
        &self,
        parent: Digest,
        child: Digest,
    ) -> Result<&'a [DataChunk], DeferredSessionError> {
        let node = self.node(child)?;
        if node.tag() != Tag::CHUNKS {
            return Err(DeferredSessionError::MalformedNode(parent));
        }
        node.payload()
            .as_data()
            .map_err(|_| DeferredSessionError::MalformedNode(parent))
    }

    fn decode_chunks_to_bytes(
        &self,
        parent: Digest,
        child: Digest,
        n_bytes: usize,
    ) -> Result<Vec<u8>, DeferredSessionError> {
        let chunks = self.chunks_payload(parent, child)?;
        let n_bytes_u32 =
            u32::try_from(n_bytes).map_err(|_| DeferredSessionError::MalformedNode(parent))?;
        chunks_to_bytes_exact(chunks, n_chunks(n_bytes_u32).get() as usize, n_bytes)
            .map_err(|_| DeferredSessionError::MalformedNode(parent))
    }

    fn decode_keccak_digest_bytes(
        &self,
        parent: Digest,
        child: Digest,
    ) -> Result<Vec<u8>, DeferredSessionError> {
        let chunks = self.chunks_payload(parent, child)?;
        chunks_to_bytes_exact(chunks, 1, 32)
            .map_err(|_| DeferredSessionError::MalformedNode(parent))
    }
}
