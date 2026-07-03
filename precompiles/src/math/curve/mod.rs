//! Fixed-curve precompile backed by fixed uint coordinate domains.
//!
//! This crate API is internal to `miden-precompiles`; it is not a public curve library and does not
//! promise stable external encodings or trait APIs.
//!
//! This precompile owns concrete curve configurations and exposes a small generic operation surface
//! over point-valued deferred nodes:
//!
//! - `VALUE`: canonical point value, represented as a join payload `[x_digest, y_digest]`; the
//!   identity point is the single canonical value `[TRUE_DIGEST, TRUE_DIGEST]`.
//! - `ADD` / `SUB`: point addition and subtraction.
//! - `MSM`: multi-scalar multiplication over one or more structural `(scalar_digest, point_digest)`
//!   pairs.
//! - `EQ`: trapping equality predicate that evaluates to `Node::TRUE` only when both operands
//!   reduce to the same canonical point.
//!
//! Affine coordinates are canonical uint values in the curve's base-field domain. Concrete MASM
//! support modules are generated separately and are currently internal implementation detail.
//!
//! ## Trust contract
//!
//! Curve `VALUE` nodes are the validation boundary. Raw affine coordinates and raw payload digests
//! are untrusted until this precompile evaluates them into a canonical curve `VALUE` node.
//! Registration/evaluation through `DeferredState::register` and `evaluate_digest` routes curve
//! nodes through this precompile, so once a digest reduces to a canonical curve `VALUE` node its
//! decoded `CurvePoint` is trusted by the internal arithmetic below.
//!
//! The canonical identity payload is `[TRUE_DIGEST, TRUE_DIGEST]`. Curve implementations must
//! preserve this single identity representation when building canonical `VALUE` nodes.
//!
//! Arithmetic methods (`add`, `neg`, `sub`, `mul_scalar`) are internal trusted operations over
//! canonical valid points and scalars. Deferred multiplication is exposed only through `MSM`.
//! These methods may use debug assertions to document invariants in debug builds, but release
//! builds do not revalidate curve membership before applying formulas.
//!
//! This precompile does not provide compressed point encodings, subgroup checks, signature
//! semantics, or public API stability guarantees beyond this internal precompile contract.

mod ed25519_sw;
mod secp256k1;
mod secp256r1;
mod short_weierstrass;

use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, TRUE_DIGEST, Tag,
    },
};
use miden_precompiles_codegen::{CodegenCurveId, CurvePrecompileDescriptor};

use self::{ed25519_sw::Ed25519Sw, secp256k1::Secp256k1, secp256r1::Secp256r1};
use crate::math::uint::{Limbs, UintDomain, UintPrecompile, UintSpec};

/// Curve-generic point value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurvePoint {
    /// The identity point.
    Identity,
    /// Affine coordinates represented as canonical little-endian base-field limbs.
    Affine { x: Limbs, y: Limbs },
}

/// Spec for one fixed curve.
///
/// This trait intentionally describes only the affine encoding and group operations needed by the
/// precompile dispatcher. It is curve-model-generic, not short-Weierstrass-specific;
/// curve-model-specific equations, coefficients, and formulas live behind narrower extension traits
/// such as [`ShortWeierstrassSpec`].
///
/// Trust contract:
///
/// - [`Self::point_from_affine`] and [`Self::canonical_point`] are checked boundary helpers. They
///   validate and canonicalize raw affine coordinates before a [`CurvePoint`] becomes trusted.
/// - [`Self::add`], [`Self::neg`], [`Self::sub`], and [`Self::mul_scalar`] are trusted internal
///   operations. Their point inputs must already be canonical valid points obtained from checked
///   boundaries, canonical curve `VALUE` nodes, or previous curve operations.
/// - Violating these preconditions is not memory-unsafe, but formulas may return invalid or
///   nonsensical arithmetic results, or fail with `InvalidPayload`.
pub trait CurveSpec: Sized + 'static {
    /// Stable local curve selector carried in curve precompile tags.
    const ID: Felt;

    /// Base field used by affine point coordinates.
    type BaseField: UintSpec;

    /// Scalar field associated with this curve.
    type ScalarField: UintSpec;

    /// Conventional generator x-coordinate, little-endian u32 limbs.
    const GENERATOR_X: Limbs;

    /// Conventional generator y-coordinate, little-endian u32 limbs.
    const GENERATOR_Y: Limbs;

    /// Returns this curve's conventional generator point.
    fn generator() -> CurvePoint {
        Self::point_from_affine(Self::GENERATOR_X, Self::GENERATOR_Y)
            .expect("curve generator coordinates must be valid")
    }

    /// Checked boundary helper that constructs this curve's canonical point from affine
    /// coordinates.
    ///
    /// This is where raw affine limbs become a trusted [`CurvePoint`]. Implementations must
    /// validate that `x` and `y` are canonical base-field elements and satisfy the curve
    /// equation. They should also canonicalize any model-specific identity representation to
    /// [`CurvePoint::Identity`] before the point is re-encoded as a graph `VALUE` node.
    fn point_from_affine(x: Limbs, y: Limbs) -> Result<CurvePoint, PrecompileError>;

    /// Checked boundary helper that returns the canonical representation of `point`.
    ///
    /// Affine inputs are revalidated through [`Self::point_from_affine`]; identity is accepted as
    /// the already-canonical identity. Arithmetic methods below assume their inputs already
    /// came from checked graph nodes or previous curve operations.
    fn canonical_point(point: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        match point {
            CurvePoint::Identity => Ok(CurvePoint::Identity),
            CurvePoint::Affine { x, y } => Self::point_from_affine(x, y),
        }
    }

    /// Returns whether `point` is a valid point on this curve.
    fn is_on_curve(point: &CurvePoint) -> bool {
        Self::canonical_point(*point).is_ok()
    }

    /// Trusted internal operation that adds two canonical valid points on this curve.
    ///
    /// Preconditions: both operands must have come from [`Self::point_from_affine`],
    /// [`Self::canonical_point`], a canonical curve `VALUE` node, or previous curve operations.
    /// Release builds do not revalidate arbitrary coordinates before applying the curve formula.
    /// Violating this contract is not memory-unsafe, but may produce invalid or nonsensical
    /// results, or fail with `InvalidPayload`.
    fn add(lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError>;

    /// Trusted internal operation that negates a canonical valid point on this curve.
    ///
    /// Precondition: `point` must have come from [`Self::point_from_affine`],
    /// [`Self::canonical_point`], a canonical curve `VALUE` node, or previous curve operations.
    /// Release builds do not revalidate arbitrary coordinates before applying the curve formula.
    /// Violating this contract is not memory-unsafe, but may produce invalid or nonsensical
    /// results, or fail with `InvalidPayload`.
    fn neg(point: CurvePoint) -> Result<CurvePoint, PrecompileError>;

    /// Trusted internal operation that subtracts two canonical valid points on this curve.
    ///
    /// Preconditions are the same as [`Self::add`] and [`Self::neg`]: operands must already be
    /// canonical valid points from checked boundaries, canonical curve `VALUE` nodes, or previous
    /// curve operations. Violating this contract is not memory-unsafe, but may produce invalid or
    /// nonsensical results, or fail with `InvalidPayload`.
    fn sub(lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        let rhs = Self::neg(rhs)?;
        Self::add(lhs, rhs)
    }

    /// Trusted internal operation that multiplies a canonical valid point by a canonical scalar.
    ///
    /// Precondition: `point` must already be a canonical valid point from a checked boundary,
    /// canonical curve `VALUE` node, or previous curve operation. `scalar` must be canonical in
    /// this curve's scalar field. Violating the point precondition is not memory-unsafe, but may
    /// produce invalid or nonsensical results, or fail with `InvalidPayload`.
    fn mul_scalar(point: CurvePoint, scalar: Limbs) -> Result<CurvePoint, PrecompileError> {
        debug_assert!(Self::is_on_curve(&point));
        debug_assert!(Self::ScalarField::is_canonical(&scalar));

        let Some(highest_limb) = scalar.iter().rposition(|&limb| limb != 0) else {
            return Ok(CurvePoint::Identity);
        };
        let highest_bit =
            highest_limb * 32 + (u32::BITS - 1 - scalar[highest_limb].leading_zeros()) as usize;

        let mut acc = CurvePoint::Identity;
        let mut base = point;

        for bit_index in 0..=highest_bit {
            let limb = scalar[bit_index / 32];
            if ((limb >> (bit_index % 32)) & 1) == 1 {
                acc = Self::add(acc, base)?;
            }
            if bit_index != highest_bit {
                base = Self::add(base, base)?;
            }
        }

        Ok(acc)
    }
}

/// Short-Weierstrass-specific parameters for curves of the form `y^2 = x^3 + A*x + B`.
pub trait ShortWeierstrassSpec: CurveSpec {
    /// Short-Weierstrass coefficient `A`.
    const A: Limbs;

    /// Short-Weierstrass coefficient `B`.
    const B: Limbs;
}

/// Fixed curves supported by the native curve precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveId {
    Secp256k1,
    Secp256r1,
    Ed25519Sw,
}

impl CurveId {
    /// All fixed curves in deterministic precompile initialization order.
    pub const ALL: [Self; 3] = [Self::Secp256k1, Self::Secp256r1, Self::Ed25519Sw];

    /// Returns the supported curve for a tag-local id.
    pub fn from_id(id: Felt) -> Option<Self> {
        match id {
            id if id == <Secp256k1 as CurveSpec>::ID => Some(Self::Secp256k1),
            id if id == <Secp256r1 as CurveSpec>::ID => Some(Self::Secp256r1),
            id if id == <Ed25519Sw as CurveSpec>::ID => Some(Self::Ed25519Sw),
            _ => None,
        }
    }

    /// Returns the stable local curve selector used in curve tags.
    pub fn id(self) -> Felt {
        match self {
            Self::Secp256k1 => miden_precompiles_codegen::SECP256K1_ID,
            Self::Secp256r1 => miden_precompiles_codegen::SECP256R1_ID,
            Self::Ed25519Sw => miden_precompiles_codegen::ED25519_SW_ID,
        }
    }

    fn codegen_id(self) -> CodegenCurveId {
        match self {
            Self::Secp256k1 => CodegenCurveId::Secp256k1,
            Self::Secp256r1 => CodegenCurveId::Secp256r1,
            Self::Ed25519Sw => CodegenCurveId::Ed25519Sw,
        }
    }

    /// Returns the base-field domain used by affine point coordinates.
    pub const fn base_domain(self) -> UintDomain {
        match self {
            Self::Secp256k1 => UintDomain::K1Base,
            Self::Secp256r1 => UintDomain::R1Base,
            Self::Ed25519Sw => UintDomain::Ed25519Base,
        }
    }

    /// Returns this curve's scalar-field domain.
    pub const fn scalar_domain(self) -> UintDomain {
        match self {
            Self::Secp256k1 => UintDomain::K1Scalar,
            Self::Secp256r1 => UintDomain::R1Scalar,
            Self::Ed25519Sw => UintDomain::Ed25519Scalar,
        }
    }

    /// Returns this curve's conventional generator point.
    pub fn generator(self) -> CurvePoint {
        match self {
            Self::Secp256k1 => Secp256k1::generator(),
            Self::Secp256r1 => Secp256r1::generator(),
            Self::Ed25519Sw => Ed25519Sw::generator(),
        }
    }

    /// Checked boundary dispatcher that constructs this curve's canonical point for affine
    /// coordinates.
    pub fn point_from_affine(self, x: Limbs, y: Limbs) -> Result<CurvePoint, PrecompileError> {
        match self {
            Self::Secp256k1 => Secp256k1::point_from_affine(x, y),
            Self::Secp256r1 => Secp256r1::point_from_affine(x, y),
            Self::Ed25519Sw => Ed25519Sw::point_from_affine(x, y),
        }
    }

    /// Returns whether `point` is a valid point on this curve.
    pub fn is_on_curve(self, point: &CurvePoint) -> bool {
        match self {
            Self::Secp256k1 => Secp256k1::is_on_curve(point),
            Self::Secp256r1 => Secp256r1::is_on_curve(point),
            Self::Ed25519Sw => Ed25519Sw::is_on_curve(point),
        }
    }

    /// Trusted dispatcher that adds two canonical valid points on this curve.
    pub fn add(self, lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        match self {
            Self::Secp256k1 => Secp256k1::add(lhs, rhs),
            Self::Secp256r1 => Secp256r1::add(lhs, rhs),
            Self::Ed25519Sw => Ed25519Sw::add(lhs, rhs),
        }
    }

    /// Trusted dispatcher that negates a canonical valid point on this curve.
    pub fn neg(self, point: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        match self {
            Self::Secp256k1 => Secp256k1::neg(point),
            Self::Secp256r1 => Secp256r1::neg(point),
            Self::Ed25519Sw => Ed25519Sw::neg(point),
        }
    }

    /// Trusted dispatcher that subtracts two canonical valid points on this curve.
    pub fn sub(self, lhs: CurvePoint, rhs: CurvePoint) -> Result<CurvePoint, PrecompileError> {
        match self {
            Self::Secp256k1 => Secp256k1::sub(lhs, rhs),
            Self::Secp256r1 => Secp256r1::sub(lhs, rhs),
            Self::Ed25519Sw => Ed25519Sw::sub(lhs, rhs),
        }
    }

    /// Trusted dispatcher that multiplies a canonical valid point by a canonical scalar-field
    /// value.
    pub fn mul_scalar(
        self,
        point: CurvePoint,
        scalar: Limbs,
    ) -> Result<CurvePoint, PrecompileError> {
        match self {
            Self::Secp256k1 => Secp256k1::mul_scalar(point, scalar),
            Self::Secp256r1 => Secp256r1::mul_scalar(point, scalar),
            Self::Ed25519Sw => Ed25519Sw::mul_scalar(point, scalar),
        }
    }
}

/// Recognized curve binary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurveBinaryOp {
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurveOp {
    Value(CurveId),
    Binary(CurveBinaryOp),
    Eq,
    Msm { curve: CurveId, n: NonZeroU32 },
}

impl CurveOp {
    fn decode(args: [Felt; 3]) -> Option<Self> {
        match args[0].as_canonical_u64() {
            CurvePrecompile::VALUE_OP_ID if args[2] == ZERO => {
                Some(Self::Value(CurveId::from_id(args[1])?))
            },
            CurvePrecompile::ADD_OP_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(Self::Binary(CurveBinaryOp::Add))
            },
            CurvePrecompile::SUB_OP_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(Self::Binary(CurveBinaryOp::Sub))
            },
            CurvePrecompile::EQ_OP_ID if args[1] == ZERO && args[2] == ZERO => Some(Self::Eq),
            CurvePrecompile::MSM_OP_ID => {
                let curve = CurveId::from_id(args[1])?;
                let n = u32::try_from(args[2].as_canonical_u64()).ok().and_then(NonZeroU32::new)?;
                Some(Self::Msm { curve, n })
            },
            _ => None,
        }
    }

    fn node_type(self) -> NodeType {
        match self {
            Self::Value(_) | Self::Binary(_) | Self::Eq => NodeType::Join,
            Self::Msm { .. } => NodeType::PairList,
        }
    }
}

enum CurveNode {
    Value {
        curve: CurveId,
        lhs: Digest,
        rhs: Digest,
    },
    BinaryOp {
        op: CurveBinaryOp,
        lhs: Digest,
        rhs: Digest,
    },
    Eq {
        lhs: Digest,
        rhs: Digest,
    },
    Msm {
        curve: CurveId,
        pairs: Vec<(Digest, Digest)>,
    },
}

impl CurveNode {
    fn parse(op: CurveOp, payload: &Payload) -> Result<Self, PrecompileError> {
        Ok(match op {
            CurveOp::Value(curve) => {
                let (lhs, rhs) = payload.as_join()?;
                Self::Value { curve, lhs, rhs }
            },
            CurveOp::Binary(op) => {
                let (lhs, rhs) = payload.as_join()?;
                Self::BinaryOp { op, lhs, rhs }
            },
            CurveOp::Eq => {
                let (lhs, rhs) = payload.as_join()?;
                Self::Eq { lhs, rhs }
            },
            CurveOp::Msm { curve, n } => {
                let pairs = payload.as_pair_list()?;
                if pairs.len() != n.get() as usize {
                    return Err(DeferredError::InvalidPayload.into());
                }
                Self::Msm { curve, pairs }
            },
        })
    }
}

/// Precompile for point operations over the fixed supported curves.
#[derive(Clone, Copy, Debug, Default)]
pub struct CurvePrecompile;

impl CurvePrecompile {
    /// Stable precompile name used to derive this precompile's tag id.
    pub const NAME: &'static str = CurvePrecompileDescriptor::NAME;

    /// Operation discriminants owned by this precompile.
    pub const VALUE_OP_ID: u64 = CurvePrecompileDescriptor::VALUE_OP_ID;
    pub const ADD_OP_ID: u64 = CurvePrecompileDescriptor::ADD_OP_ID;
    pub const SUB_OP_ID: u64 = CurvePrecompileDescriptor::SUB_OP_ID;
    pub const EQ_OP_ID: u64 = CurvePrecompileDescriptor::EQ_OP_ID;
    pub const MSM_OP_ID: u64 = CurvePrecompileDescriptor::MSM_OP_ID;

    /// Stable precompile id derived from [`Self::NAME`].
    pub fn id() -> Felt {
        CurvePrecompileDescriptor::id()
    }

    /// Builds a canonical curve `VALUE` tag for `curve`.
    pub fn value_tag(curve: CurveId) -> Tag {
        CurvePrecompileDescriptor::value_tag(curve.codegen_id())
    }

    /// Builds a canonical curve operation tag for curve-agnostic join operations.
    pub fn op_tag(op_id: u64) -> Tag {
        CurvePrecompileDescriptor::op_tag(op_id)
    }

    /// Builds a canonical curve MSM tag for `curve` and non-zero pair count `n`.
    pub fn msm_tag(curve: CurveId, n: NonZeroU32) -> Tag {
        CurvePrecompileDescriptor::msm_tag(curve.codegen_id(), n)
    }

    /// Builds a point VALUE node from a point value.
    pub fn value_node(curve: CurveId, point: CurvePoint) -> Node {
        match point {
            CurvePoint::Identity => Self::identity_node(curve),
            CurvePoint::Affine { x, y } => Self::affine_node_from_digests(
                curve,
                UintPrecompile::value_node(curve.base_domain(), x).digest(),
                UintPrecompile::value_node(curve.base_domain(), y).digest(),
            ),
        }
    }

    /// Builds the canonical identity point value node for `curve`.
    pub fn identity_node(curve: CurveId) -> Node {
        CurvePrecompileDescriptor::identity_node(curve.codegen_id())
    }

    /// Builds the canonical generator value node for `curve`.
    pub fn generator_node(curve: CurveId) -> Node {
        Self::value_node(curve, curve.generator())
    }

    /// Builds an affine point VALUE node from coordinate digests.
    pub fn affine_node_from_digests(curve: CurveId, x: Digest, y: Digest) -> Node {
        Node::join(Self::value_tag(curve), x, y).expect("curve value tag is precompile-owned")
    }

    fn extend_init_nodes_with_point(nodes: &mut Vec<Node>, curve: CurveId, point: CurvePoint) {
        if let CurvePoint::Affine { x, y } = point {
            let x = UintPrecompile::value_node(curve.base_domain(), x);
            let y = UintPrecompile::value_node(curve.base_domain(), y);
            nodes.push(x.clone());
            nodes.push(y.clone());
            nodes.push(Self::affine_node_from_digests(curve, x.digest(), y.digest()));
        }
    }

    /// Builds the canonical curve `VALUE` node for a trusted point.
    ///
    /// This is used after a checked boundary or trusted arithmetic operation has produced a
    /// canonical [`CurvePoint`]. Affine coordinates are registered as canonical base-field uint
    /// `VALUE` nodes in the deferred context; identity always uses `[TRUE_DIGEST, TRUE_DIGEST]`.
    fn canonical_value_node(
        curve: CurveId,
        point: CurvePoint,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        match point {
            CurvePoint::Identity => Ok(Self::identity_node(curve)),
            CurvePoint::Affine { x, y } => {
                let x = context.register(UintPrecompile::value_node(curve.base_domain(), x))?;
                let y = context.register(UintPrecompile::value_node(curve.base_domain(), y))?;
                Ok(Self::affine_node_from_digests(curve, x, y))
            },
        }
    }

    fn evaluate_msm_term(
        curve: CurveId,
        scalar: Digest,
        point: Digest,
        context: &mut DeferredContext<'_>,
    ) -> Result<(Limbs, CurvePoint), PrecompileError> {
        let (scalar_digest, point_digest) = context.evaluate_digest_pair(scalar, point)?;
        let scalar_node = context.get_node(&scalar_digest).ok_or(PrecompileError::MissingNode)?;
        let point_node = context.get_node(&point_digest).ok_or(PrecompileError::MissingNode)?;

        let scalar = UintPrecompile::limbs_from_value_node(scalar_node, curve.scalar_domain())?;
        let (point_curve, point) = Self::point_from_value_node(point_node, context)?;
        if point_curve != curve {
            return Err(DeferredError::InvalidPayload.into());
        }
        Ok((scalar, point))
    }

    fn evaluate_msm(
        curve: CurveId,
        pairs: &[(Digest, Digest)],
        context: &mut DeferredContext<'_>,
    ) -> Result<CurvePoint, PrecompileError> {
        let mut acc = CurvePoint::Identity;
        for &(scalar, point) in pairs {
            let (scalar, point) = Self::evaluate_msm_term(curve, scalar, point, context)?;
            let term = curve.mul_scalar(point, scalar)?;
            acc = curve.add(acc, term)?;
        }
        Ok(acc)
    }

    fn evaluate_point_pair(
        context: &mut DeferredContext<'_>,
        lhs: Digest,
        rhs: Digest,
    ) -> Result<(CurveId, CurvePoint, CurvePoint), PrecompileError> {
        let (lhs, rhs) = context.evaluate_digest_pair(lhs, rhs)?;
        let (lhs_curve, lhs) = {
            let lhs = context.get_node(&lhs).ok_or(PrecompileError::MissingNode)?;
            Self::point_from_value_node(lhs, context)?
        };
        let (rhs_curve, rhs) = {
            let rhs = context.get_node(&rhs).ok_or(PrecompileError::MissingNode)?;
            Self::point_from_value_node(rhs, context)?
        };

        if lhs_curve != rhs_curve {
            return Err(DeferredError::InvalidPayload.into());
        }

        Ok((lhs_curve, lhs, rhs))
    }

    /// Decodes an already-evaluated canonical curve `VALUE` node and infers its curve.
    fn point_from_value_node(
        node: &Node,
        context: &DeferredContext<'_>,
    ) -> Result<(CurveId, CurvePoint), PrecompileError> {
        let Some(CurveOp::Value(curve)) = CurveOp::decode(node.tag().args()) else {
            return Err(DeferredError::InvalidPayload.into());
        };
        let point = Self::point_of_canonical_node(curve, node, context)?;
        Ok((curve, point))
    }

    /// Decodes an already-evaluated canonical curve `VALUE` node.
    ///
    /// The caller must have reached `node` through deferred evaluation for this curve. This helper
    /// still checks the expected curve `VALUE` tag and join structure before taking the trusted
    /// canonical payload path.
    fn point_of_canonical_node(
        curve: CurveId,
        node: &Node,
        context: &DeferredContext<'_>,
    ) -> Result<CurvePoint, PrecompileError> {
        let payload = node.payload_for_tag(Self::value_tag(curve))?;
        let (x_digest, y_digest) = payload.as_join()?;
        Self::point_from_canonical_value_payload(curve, x_digest, y_digest, context)
    }

    /// Checked decoder for a curve `VALUE` payload from the raw affine boundary.
    ///
    /// Used while evaluating a `VALUE` node after coordinate digests have themselves been
    /// evaluated. It rejects mixed identity payloads, decodes both coordinates as base-field
    /// uint `VALUE` nodes, and calls [`CurveId::point_from_affine`] to validate curve
    /// membership and canonicalize model-specific affine identities.
    fn point_from_checked_value_payload(
        curve: CurveId,
        x_digest: Digest,
        y_digest: Digest,
        context: &DeferredContext<'_>,
    ) -> Result<CurvePoint, PrecompileError> {
        match (x_digest == TRUE_DIGEST, y_digest == TRUE_DIGEST) {
            (true, true) => Ok(CurvePoint::Identity),
            (true, false) | (false, true) => Err(DeferredError::InvalidPayload.into()),
            (false, false) => {
                let x_node = context.get_node(&x_digest).ok_or(PrecompileError::MissingNode)?;
                let y_node = context.get_node(&y_digest).ok_or(PrecompileError::MissingNode)?;
                let x = UintPrecompile::limbs_from_value_node(x_node, curve.base_domain())?;
                let y = UintPrecompile::limbs_from_value_node(y_node, curve.base_domain())?;
                curve.point_from_affine(x, y)
            },
        }
    }

    /// Trusted decoder for a payload of an already-canonical curve `VALUE` node.
    ///
    /// Canonical curve `VALUE` nodes are produced by this precompile, so release builds rely on the
    /// prior checked boundary instead of revalidating curve membership here. Structural checks
    /// remain: mixed identity payloads are rejected and affine coordinate digests must decode
    /// as base-field uint `VALUE` nodes. Debug builds assert curve membership for invariant
    /// checking.
    fn point_from_canonical_value_payload(
        curve: CurveId,
        x_digest: Digest,
        y_digest: Digest,
        context: &DeferredContext<'_>,
    ) -> Result<CurvePoint, PrecompileError> {
        match (x_digest == TRUE_DIGEST, y_digest == TRUE_DIGEST) {
            (true, true) => Ok(CurvePoint::Identity),
            (true, false) | (false, true) => Err(DeferredError::InvalidPayload.into()),
            (false, false) => {
                let x_node = context.get_node(&x_digest).ok_or(PrecompileError::MissingNode)?;
                let y_node = context.get_node(&y_digest).ok_or(PrecompileError::MissingNode)?;
                let x = UintPrecompile::limbs_from_value_node(x_node, curve.base_domain())?;
                let y = UintPrecompile::limbs_from_value_node(y_node, curve.base_domain())?;
                let point = CurvePoint::Affine { x, y };
                debug_assert!(curve.is_on_curve(&point));
                Ok(point)
            },
        }
    }
}

impl Precompile for CurvePrecompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn init(&self) -> Vec<Node> {
        let mut nodes = Vec::with_capacity(CurveId::ALL.len() * 4);
        for curve in CurveId::ALL {
            nodes.push(Self::identity_node(curve));
            Self::extend_init_nodes_with_point(&mut nodes, curve, curve.generator());
        }
        nodes
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let op = CurveOp::decode(args)?;
        Some(op.node_type())
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let op = CurveOp::decode(args).ok_or(PrecompileError::InvalidNode)?;

        match CurveNode::parse(op, payload)? {
            CurveNode::Value { curve, lhs, rhs } => {
                match (lhs == TRUE_DIGEST, rhs == TRUE_DIGEST) {
                    (true, true) => Ok(Self::identity_node(curve)),
                    (true, false) | (false, true) => Err(DeferredError::InvalidPayload.into()),
                    (false, false) => {
                        let (x_digest, y_digest) = context.evaluate_digest_pair(lhs, rhs)?;
                        let point = Self::point_from_checked_value_payload(
                            curve, x_digest, y_digest, context,
                        )?;
                        Self::canonical_value_node(curve, point, context)
                    },
                }
            },
            CurveNode::BinaryOp { op, lhs, rhs } => {
                let (curve, lhs, rhs) = Self::evaluate_point_pair(context, lhs, rhs)?;
                let value = match op {
                    CurveBinaryOp::Add => curve.add(lhs, rhs)?,
                    CurveBinaryOp::Sub => curve.sub(lhs, rhs)?,
                };
                Self::canonical_value_node(curve, value, context)
            },
            CurveNode::Eq { lhs, rhs } => {
                let (_, lhs, rhs) = Self::evaluate_point_pair(context, lhs, rhs)?;
                if lhs == rhs {
                    Ok(Node::TRUE)
                } else {
                    Err(PrecompileError::AssertionFailed)
                }
            },
            CurveNode::Msm { curve, pairs } => {
                let value = Self::evaluate_msm(curve, &pairs, context)?;
                Self::canonical_value_node(curve, value, context)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec};

    use miden_core::deferred::DeferredState;

    use super::*;
    use crate::math::{k1_scalar::K1Scalar, uint::UintPrecompile};

    fn state() -> DeferredState {
        DeferredState::new(Arc::new(crate::registry()), usize::MAX)
            .expect("precompile init must succeed")
    }

    fn evaluate(state: &mut DeferredState, node: Node) -> Result<Node, PrecompileError> {
        let digest = state.register(node)?;
        let canonical = state.evaluate_digest(digest)?;
        state.get_node(&canonical).cloned().ok_or(PrecompileError::InvalidNode)
    }

    fn assert_invalid_payload(result: Result<Node, PrecompileError>) {
        let Err(error) = result else {
            panic!("expected invalid payload");
        };
        assert!(
            matches!(error.root(), PrecompileError::Other(DeferredError::InvalidPayload)),
            "expected invalid payload, got {error:?}",
        );
    }

    fn affine_limbs(point: CurvePoint) -> (Limbs, Limbs) {
        match point {
            CurvePoint::Affine { x, y } => (x, y),
            CurvePoint::Identity => panic!("expected affine point"),
        }
    }

    #[test]
    fn decode_uses_curve_for_value_and_msm_tags() {
        let precompile = CurvePrecompile;
        let curve_id = CurveId::Secp256k1.id();

        assert_eq!(
            precompile.decode(CurvePrecompile::value_tag(CurveId::Secp256k1).args()),
            Some(NodeType::Join)
        );
        assert_eq!(
            precompile.decode(CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID).args()),
            Some(NodeType::Join)
        );
        assert_eq!(
            precompile.decode(CurvePrecompile::msm_tag(CurveId::Secp256k1, NonZeroU32::MIN).args()),
            Some(NodeType::PairList)
        );
        assert_eq!(
            precompile.decode(
                CurvePrecompile::msm_tag(CurveId::Secp256k1, NonZeroU32::new(2).unwrap()).args()
            ),
            Some(NodeType::PairList)
        );

        let mut add_with_curve = CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID).args();
        add_with_curve[1] = curve_id;
        assert_eq!(precompile.decode(add_with_curve), None);

        // Old native MUL128 (`[op=4, 0, 0]`) and MUL_SCALAR (`[op=5, 0, 0]`) tag shapes are
        // rejected.
        assert_eq!(precompile.decode(CurvePrecompile::op_tag(4).args()), None);
        assert_eq!(precompile.decode(CurvePrecompile::op_tag(5).args()), None);
        assert_eq!(
            precompile.decode([Felt::from_u32(CurvePrecompile::MSM_OP_ID as u32), curve_id, ZERO]),
            None
        );
        assert_eq!(precompile.decode([Felt::from_u32(0), Felt::new_unchecked(99), ZERO]), None);
        assert_eq!(precompile.decode([Felt::from_u32(0), curve_id, Felt::from_u32(1)]), None);
    }

    #[test]
    fn same_curve_add_succeeds() {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let generator = CurvePrecompile::generator_node(curve);
        let identity = CurvePrecompile::identity_node(curve);
        let node = Node::join(
            CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID),
            generator.digest(),
            identity.digest(),
        )
        .expect("tag is curve-owned");

        assert_eq!(evaluate(&mut state, node).unwrap(), generator);
    }

    #[test]
    fn mixed_curve_add_fails() {
        let mut state = state();
        let lhs = CurvePrecompile::generator_node(CurveId::Secp256k1);
        let rhs = CurvePrecompile::identity_node(CurveId::Secp256r1);
        let node = Node::join(
            CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID),
            lhs.digest(),
            rhs.digest(),
        )
        .expect("tag is curve-owned");

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn msm_one_pair_evaluates_scalar_and_point_operands() {
        let mut state = state();
        let curve = CurveId::Secp256r1;
        let generator = CurvePrecompile::generator_node(curve);
        let scalar = UintPrecompile::value_node(curve.scalar_domain(), [2, 0, 0, 0, 0, 0, 0, 0]);
        state.register(scalar.clone()).expect("scalar must register");
        let node = Node::try_pair_list(
            CurvePrecompile::msm_tag(curve, NonZeroU32::MIN),
            vec![(scalar.digest(), generator.digest())],
        )
        .expect("tag is curve-owned");
        let expected = CurvePrecompile::value_node(
            curve,
            curve
                .mul_scalar(curve.generator(), [2, 0, 0, 0, 0, 0, 0, 0])
                .expect("valid mul_scalar"),
        );

        assert_eq!(evaluate(&mut state, node).unwrap(), expected);
    }

    #[test]
    fn msm_accumulates_multiple_pairs() {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let generator = CurvePrecompile::generator_node(curve);
        let scalar_2 = UintPrecompile::value_node(curve.scalar_domain(), [2, 0, 0, 0, 0, 0, 0, 0]);
        let scalar_3 = UintPrecompile::value_node(curve.scalar_domain(), [3, 0, 0, 0, 0, 0, 0, 0]);
        state.register(scalar_2.clone()).expect("scalar must register");
        state.register(scalar_3.clone()).expect("scalar must register");
        let node = Node::try_pair_list(
            CurvePrecompile::msm_tag(curve, NonZeroU32::new(2).unwrap()),
            vec![(scalar_2.digest(), generator.digest()), (scalar_3.digest(), generator.digest())],
        )
        .expect("tag is curve-owned");
        let two_g = curve
            .mul_scalar(curve.generator(), [2, 0, 0, 0, 0, 0, 0, 0])
            .expect("valid scalar multiplication");
        let three_g = curve
            .mul_scalar(curve.generator(), [3, 0, 0, 0, 0, 0, 0, 0])
            .expect("valid scalar multiplication");
        let expected = CurvePrecompile::value_node(
            curve,
            curve.add(two_g, three_g).expect("valid point addition"),
        );

        assert_eq!(evaluate(&mut state, node).unwrap(), expected);
    }

    #[test]
    fn msm_rejects_pair_count_mismatch() {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let generator = CurvePrecompile::generator_node(curve);
        let scalar = UintPrecompile::value_node(curve.scalar_domain(), [2, 0, 0, 0, 0, 0, 0, 0]);
        state.register(scalar.clone()).expect("scalar must register");
        let node = Node::try_pair_list(
            CurvePrecompile::msm_tag(curve, NonZeroU32::new(2).unwrap()),
            vec![(scalar.digest(), generator.digest())],
        )
        .expect("tag is curve-owned");

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn msm_rejects_wrong_scalar_domain() {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let generator = CurvePrecompile::generator_node(curve);
        let scalar = UintPrecompile::value_node(curve.base_domain(), [2, 0, 0, 0, 0, 0, 0, 0]);
        state.register(scalar.clone()).expect("scalar must register");
        let node = Node::try_pair_list(
            CurvePrecompile::msm_tag(curve, NonZeroU32::MIN),
            vec![(scalar.digest(), generator.digest())],
        )
        .expect("tag is curve-owned");

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn msm_rejects_wrong_point_curve() {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let scalar = UintPrecompile::value_node(curve.scalar_domain(), [2, 0, 0, 0, 0, 0, 0, 0]);
        let point = CurvePrecompile::generator_node(CurveId::Secp256r1);
        state.register(scalar.clone()).expect("scalar must register");
        let node = Node::try_pair_list(
            CurvePrecompile::msm_tag(curve, NonZeroU32::MIN),
            vec![(scalar.digest(), point.digest())],
        )
        .expect("tag is curve-owned");

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn mixed_true_payload_is_invalid() {
        let identity = CurvePrecompile::identity_node(CurveId::Secp256k1);
        let node = CurvePrecompile::affine_node_from_digests(
            CurveId::Secp256k1,
            TRUE_DIGEST,
            identity.digest(),
        );
        let mut state = state();

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn affine_value_rejects_scalar_field_coordinate_nodes() {
        let curve = CurveId::Secp256k1;
        let x = UintPrecompile::value_node(UintDomain::K1Scalar, Secp256k1::GENERATOR_X);
        let y = UintPrecompile::value_node(UintDomain::K1Scalar, Secp256k1::GENERATOR_Y);
        let point = CurvePrecompile::affine_node_from_digests(curve, x.digest(), y.digest());
        let mut state = state();
        state.register(x).expect("x coordinate must register");
        state.register(y).expect("y coordinate must register");

        assert_invalid_payload(evaluate(&mut state, point));
    }

    #[test]
    fn invalid_affine_point_rejects() {
        let curve = CurveId::Secp256k1;
        let x = UintPrecompile::value_node(curve.base_domain(), [1, 0, 0, 0, 0, 0, 0, 0]);
        let y = UintPrecompile::value_node(curve.base_domain(), [1, 0, 0, 0, 0, 0, 0, 0]);
        let point = CurvePrecompile::affine_node_from_digests(curve, x.digest(), y.digest());
        let mut state = state();
        state.register(x).expect("x coordinate must register");
        state.register(y).expect("y coordinate must register");

        assert_invalid_payload(evaluate(&mut state, point));
    }

    #[test]
    fn mul_scalar_two_generator_matches_hardcoded_known_answers() {
        const K1_2G_X: Limbs = [
            0x5c70_9ee5,
            0xabac_09b9,
            0x8cef_3ca7,
            0x5c77_8e4b,
            0x95c0_7cd8,
            0x3045_406e,
            0x41ed_7d6d,
            0xc604_7f94,
        ];
        const K1_2G_Y: Limbs = [
            0x50cf_e52a,
            0x2364_31a9,
            0x3266_d0e1,
            0xf7f6_3265,
            0x466c_eaee,
            0xa3c5_8419,
            0xa63d_c339,
            0x1ae1_68fe,
        ];
        const R1_2G_X: Limbs = [
            0x4766_9978,
            0xa60b_48fc,
            0x77f2_1b35,
            0xc089_69e2,
            0x04b5_1ac3,
            0x8a52_3803,
            0x8d03_4f7e,
            0x7cf2_7b18,
        ];
        const R1_2G_Y: Limbs = [
            0x2278_73d1,
            0x9e04_b79d,
            0x3ce9_8229,
            0xba7d_ade6,
            0x9f74_30db,
            0x293d_9ac6,
            0xdb8e_d040,
            0x0777_5510,
        ];

        for (curve, expected) in [
            (CurveId::Secp256k1, (K1_2G_X, K1_2G_Y)),
            (CurveId::Secp256r1, (R1_2G_X, R1_2G_Y)),
        ] {
            let (x, y) = affine_limbs(
                curve.mul_scalar(curve.generator(), [2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            );
            assert_eq!((x, y), expected);
        }
    }

    #[test]
    fn ed25519_sw_identity_canonicalizes() {
        let curve = CurveId::Ed25519Sw;
        let generator = curve.generator();
        let neg_generator = curve.neg(generator).expect("valid negation");

        assert_eq!(curve.add(generator, CurvePoint::Identity).unwrap(), generator);
        assert_eq!(curve.add(generator, neg_generator).unwrap(), CurvePoint::Identity);

        let mut state = state();
        let generator = CurvePrecompile::generator_node(curve);
        let identity = CurvePrecompile::identity_node(curve);
        let node = Node::join(
            CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID),
            generator.digest(),
            identity.digest(),
        )
        .expect("tag is curve-owned");

        assert_eq!(evaluate(&mut state, identity.clone()).unwrap(), identity);
        assert_eq!(evaluate(&mut state, node).unwrap(), generator);
    }

    #[test]
    fn fixed_curve_ids_and_generators_validate() {
        for curve in CurveId::ALL {
            assert_eq!(CurveId::from_id(curve.id()), Some(curve));
            assert!(curve.is_on_curve(&curve.generator()));
            assert!(curve.scalar_domain().is_prime_field());
        }
        assert_eq!(CurveId::from_id(Felt::new_unchecked(99)), None);
        assert!(!K1Scalar::is_canonical(&K1Scalar::MODULUS));
    }
}
