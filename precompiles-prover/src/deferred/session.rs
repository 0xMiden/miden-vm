use alloc::{collections::BTreeSet, vec::Vec};

use miden_core::deferred::{DataChunk, DeferredState, Digest, Node, TRUE_DIGEST, Tag};
use miden_precompiles::{
    CurveId, CurveNodeRef, CurvePrecompile, HashAssertNode, Keccak256Precompile, UintDomain,
    UintNodeRef, UintPrecompile, chunks_to_bytes_exact, n_chunks,
};

use crate::{
    math::{U256, from_limbs32},
    session::{EcNode, Session, Truthy, UintNode, strategies},
    transcript::poseidon2::P2Digest,
};

/// wNAF window for [`translate_ec_msm`](DeferredSessionBuilder::translate_ec_msm)'s
/// joint-wNAF addition chain. `w = 5` (digits odd, `|d| < 2^{w-1}`, `2^{w-2}`
/// odd multiples per base) matches the width already used for full-width
/// (~256-bit) scalars elsewhere in this crate (`examples/ec_msm_ecdsa.rs`'s
/// `WNAF_W`) — GLV's `w = 4` sweet spot is tuned for its ~128-bit halves, not
/// the full-width scalars a raw MSM claim carries.
const MSM_WNAF_WINDOW: usize = 5;

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

    #[error("deferred MSM node {digest:?} has no nonzero scalar")]
    UnsupportedMsmAllZeroScalars { digest: Digest },
}

pub(crate) fn session_from_deferred_state(
    state: &DeferredState,
) -> Result<DeferredSession, DeferredSessionError> {
    let mut builder = DeferredSessionBuilder { state, session: Session::new() };

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
        let mut terms = Vec::with_capacity(pairs.len());
        for (point_digest, scalar_digest) in pairs {
            let point = self.translate_ec(point_digest)?;
            let scalar = self.translate_uint(scalar_digest)?;
            debug_assert_eq!(point.curve, curve);
            debug_assert_eq!(scalar.domain, curve.scalar_domain());
            terms.push((point, scalar));
        }

        if terms.iter().all(|(_, scalar)| scalar.value == U256::ZERO) {
            return Err(DeferredSessionError::UnsupportedMsmAllZeroScalars { digest });
        }

        let mut bases = BTreeSet::new();
        for (point, scalar) in &terms {
            if !bases.insert(point.node.point) {
                return Err(DeferredSessionError::UnsupportedMsm {
                    digest,
                    reason: "duplicate canonical bases are not supported",
                });
            }
            if scalar.value == U256::ZERO {
                return Err(DeferredSessionError::UnsupportedMsm {
                    digest,
                    reason: "zero-scalar terms are not supported",
                });
            }
        }

        if let Some((point, _)) = terms.first() {
            self.session
                .constrain_scalar_bound(&point.node, curve.scalar_domain().bound_ptr());
        }

        let expr_terms = terms
            .iter()
            .map(|(point, scalar)| (point.node, scalar.value))
            .collect::<Vec<_>>();
        // `joint_wnaf`'s per-column cost is linear in the term count (unlike
        // Straus's 2^k subset-sum table), so an arbitrary-arity pair-list
        // never needs a term-count cap here.
        let expr = strategies::joint_wnaf(&mut self.session, &expr_terms, MSM_WNAF_WINDOW);

        let claim_terms = terms
            .iter()
            .map(|(point, scalar)| (point.node, scalar.node))
            .collect::<Vec<_>>();
        Ok(self.session.ec_msm(expr, &claim_terms))
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
