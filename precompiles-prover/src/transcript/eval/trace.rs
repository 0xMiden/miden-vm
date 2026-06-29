//! Trace generation for the uint-aware transcript eval chiplet.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use miden_core::{Felt, field::QuadFelt};
use miden_precompiles::UintDomain;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::{
        EcRequire,
        trace::{EcGroupPtr, EcPointPtr, EcStoreRequires},
    },
    logup::build_logup_aux_trace,
    math::to_limbs32,
    relations::ProvideMult,
    transcript::{
        eval::{
            COL_A_PTR, COL_ABSORB_CAP_BEGIN, COL_ACT, COL_B_PTR, COL_BOUND_PTR, COL_CURVE_B,
            COL_GROUP_PTR, COL_H_BEGIN, COL_IS_ADD, COL_IS_AND, COL_IS_EC_CREATE, COL_IS_EC_OP,
            COL_IS_EC_PAI, COL_IS_FIELD_TAG, COL_IS_IS, COL_IS_MUL, COL_IS_NEG, COL_IS_PINNED,
            COL_IS_SUB, COL_IS_UINT_LEAF, COL_IS_UINT_OP, COL_IS_ZERO, COL_LHS_BEGIN, COL_OUT_MULT,
            COL_PARAM_A, COL_PERM_SEQ_ID, COL_PIN_PTR, COL_PTR, COL_RHS_BEGIN, COL_SBOUND_PTR,
            NUM_HASH, NUM_MAIN_COLS, TranscriptEvalAir,
        },
        nodes::{EcOpId, UintOpId},
        poseidon2::{
            P2Cap, P2Digest,
            trace::{PermSeqId, Poseidon2Requires},
        },
    },
    uint::{
        UintRequire,
        trace::{UintPtr, UintStoreRequires},
    },
};

#[derive(Debug)]
pub struct Truthy {
    id: u32,
    hash: P2Digest,
}

impl Truthy {
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

#[derive(Debug)]
pub struct PinnedUint {
    id: u32,
    hash: P2Digest,
}

impl PinnedUint {
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

#[derive(Debug)]
pub enum TranscriptRoot {
    Truthy(Truthy),
    PinnedUint(PinnedUint),
}

impl TranscriptRoot {
    fn id(&self) -> u32 {
        match self {
            Self::Truthy(root) => root.id,
            Self::PinnedUint(root) => root.id,
        }
    }

    pub fn hash(&self) -> P2Digest {
        match self {
            Self::Truthy(root) => root.hash,
            Self::PinnedUint(root) => root.hash,
        }
    }
}

impl From<Truthy> for TranscriptRoot {
    fn from(root: Truthy) -> Self {
        Self::Truthy(root)
    }
}

impl From<PinnedUint> for TranscriptRoot {
    fn from(root: PinnedUint) -> Self {
        Self::PinnedUint(root)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UintNode {
    id: u32,
    hash: P2Digest,
    ptr: UintPtr,
    bound_ptr: UintPtr,
}

impl UintNode {
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EcNode {
    id: u32,
    hash: P2Digest,
    point: EcPointPtr,
}

impl EcNode {
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

#[derive(Debug)]
struct EvalNode {
    id: u32,
    absorbed: Option<Absorbed>,
    kind: NodeKind,
}

#[derive(Debug, Clone, Copy)]
struct Absorbed {
    hash: P2Digest,
    perm_seq_id: PermSeqId,
}

#[derive(Debug)]
enum NodeKind {
    Zero,
    And {
        lhs: P2Digest,
        rhs: P2Digest,
    },
    FieldTag {
        bound_ptr: u32,
        tag: P2Cap,
        lo: [Felt; NUM_HASH],
        hi: [Felt; NUM_HASH],
    },
    UintLeaf {
        ptr: u32,
        bound_ptr: u32,
        field_tag: P2Digest,
        is_pinned: bool,
        lo: [Felt; NUM_HASH],
        hi: [Felt; NUM_HASH],
    },
    UintOp {
        op: UintOpId,
        lhs: P2Digest,
        rhs: P2Digest,
        a_ptr: u32,
        b_ptr: u32,
        r_ptr: u32,
        bound_ptr: u32,
        field_tag: P2Digest,
    },
    EcCreate {
        x_hash: P2Digest,
        y_hash: P2Digest,
        a_ptr: u32,
        b_ptr: u32,
        x_ptr: u32,
        y_ptr: u32,
        group_ptr: u32,
        point_ptr: u32,
        bound_ptr: u32,
        field_tag: P2Digest,
        is_pai: bool,
    },
    EcBinOp {
        op: EcOpId,
        lhs: P2Digest,
        rhs: P2Digest,
        p_ptr: u32,
        q_ptr: u32,
        r_ptr: u32,
        group_ptr: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UintKey {
    Leaf(UintPtr),
    Op(UintOpId, UintPtr, P2Digest, P2Digest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EcKey {
    Create(u32, u32, P2Digest, P2Digest),
    Op(EcOpId, P2Digest, P2Digest),
}

#[derive(Debug, Default)]
pub struct TranscriptEvalRequires {
    next_id: u32,
    live: BTreeSet<u32>,
    node_consumers: BTreeMap<u32, ProvideMult>,
    nodes: Vec<EvalNode>,
    uint_dedup: HashMap<UintKey, UintNode>,
    ec_dedup: HashMap<EcKey, EcNode>,
    fields: HashMap<UintPtr, FieldDomain>,
    field_consumers: BTreeMap<u32, ProvideMult>,
}

#[derive(Debug, Clone, Copy)]
struct FieldDomain {
    tag: P2Cap,
}

impl TranscriptEvalRequires {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&mut self, hash: P2Digest) -> Truthy {
        self.fresh(hash)
    }

    pub fn zero(&mut self) -> Truthy {
        let t = self.fresh(P2Digest::default());
        self.nodes.push(EvalNode {
            id: t.id,
            absorbed: None,
            kind: NodeKind::Zero,
        });
        t
    }

    pub fn record_and(&mut self, a: Truthy, b: Truthy, p2: &mut Poseidon2Requires) -> Truthy {
        let (lhs, rhs) = (a.hash, b.hash);
        self.consume(a);
        self.consume(b);
        let absorption = p2.require_one_shot(P2Cap::and(), lhs.as_array(), rhs.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let out = self.fresh(hash);
        self.nodes.push(EvalNode {
            id: out.id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::And { lhs, rhs },
        });
        out
    }

    pub fn pin_uint(
        &mut self,
        ptr: UintPtr,
        bound_ptr: UintPtr,
        value: [u32; 8],
        store: &mut UintStoreRequires,
        p2: &mut Poseidon2Requires,
    ) -> PinnedUint {
        let field = self.ensure_field(bound_ptr, store, p2);
        self.consume_field(bound_ptr);
        store.require_uintval(ptr);
        let (id, hash) = self.push_uint_leaf(ptr, bound_ptr, field, true, value, p2);
        PinnedUint { id, hash }
    }

    pub fn uint_leaf(
        &mut self,
        ptr: UintPtr,
        bound_ptr: UintPtr,
        value: [u32; 8],
        store: &mut UintStoreRequires,
        p2: &mut Poseidon2Requires,
    ) -> UintNode {
        if let Some(&node) = self.uint_dedup.get(&UintKey::Leaf(ptr)) {
            return node;
        }
        let field = self.ensure_field(bound_ptr, store, p2);
        self.consume_field(bound_ptr);
        store.require_uintval(ptr);
        let (id, hash) = self.push_uint_leaf(ptr, bound_ptr, field, false, value, p2);
        self.node_consumers.insert(id, 0);
        let node = UintNode { id, hash, ptr, bound_ptr };
        self.uint_dedup.insert(UintKey::Leaf(ptr), node);
        node
    }

    pub fn uint_op(
        &mut self,
        op: UintOpId,
        a: &UintNode,
        b: Option<&UintNode>,
        mut uints: UintRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> UintNode {
        assert!(
            b.is_none() == matches!(op, UintOpId::Neg),
            "Neg is unary; Add/Sub/Mul are binary",
        );
        assert!(!matches!(op, UintOpId::Neg), "Neg has no canonical uint deferred node");
        assert!(!matches!(op, UintOpId::Is), "Is goes through record_is");
        if let Some(b) = b {
            assert_eq!(a.bound_ptr, b.bound_ptr, "op operands must share a modulus");
        }
        let rhs = b.map(|b| b.hash).unwrap_or_default();
        let key = UintKey::Op(op, a.bound_ptr, a.hash, rhs);
        if let Some(&node) = self.uint_dedup.get(&key) {
            return node;
        }

        let r_ptr = match op {
            UintOpId::Add => uints.add(a.ptr, b.expect("binary").ptr),
            UintOpId::Sub => uints.sub(a.ptr, b.expect("binary").ptr),
            UintOpId::Mul => uints.mac(1, a.ptr, b.expect("binary").ptr, 0, a.bound_ptr),
            UintOpId::Neg => uints.neg(a.ptr),
            UintOpId::Is => unreachable!("Is goes through record_is"),
        };

        let bound_ptr = a.bound_ptr;
        let field = self
            .fields
            .get(&bound_ptr)
            .copied()
            .expect("uint op operand field was not registered");
        self.consume_field(bound_ptr);
        self.consume_uint(a);
        if let Some(b) = b {
            self.consume_uint(b);
        }
        let absorption = p2.require_one_shot(P2Cap::uint_op(op), a.hash.as_array(), rhs.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::UintOp {
                op,
                lhs: a.hash,
                rhs,
                a_ptr: a.ptr.addr(),
                b_ptr: b.map_or(0, |b| b.ptr.addr()),
                r_ptr: r_ptr.addr(),
                bound_ptr: bound_ptr.addr(),
                field_tag: P2Digest(field.tag.as_array()),
            },
        });
        self.node_consumers.insert(id, 0);
        let node = UintNode { id, hash, ptr: r_ptr, bound_ptr };
        self.uint_dedup.insert(key, node);
        node
    }

    pub fn record_is(&mut self, a: &UintNode, b: &UintNode, p2: &mut Poseidon2Requires) -> Truthy {
        assert_eq!(a.bound_ptr, b.bound_ptr, "Is operands must share a modulus");
        assert_eq!(a.ptr, b.ptr, "Is operands are unequal (distinct interned ptrs) - unprovable",);
        let field = self
            .fields
            .get(&a.bound_ptr)
            .copied()
            .expect("Is operand field was not registered");
        self.consume_field(a.bound_ptr);
        self.consume_uint(a);
        self.consume_uint(b);
        let absorption =
            p2.require_one_shot(P2Cap::uint_op(UintOpId::Is), a.hash.as_array(), b.hash.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let out = self.fresh(hash);
        self.nodes.push(EvalNode {
            id: out.id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::UintOp {
                op: UintOpId::Is,
                lhs: a.hash,
                rhs: b.hash,
                a_ptr: a.ptr.addr(),
                b_ptr: b.ptr.addr(),
                r_ptr: 0,
                bound_ptr: a.bound_ptr.addr(),
                field_tag: P2Digest(field.tag.as_array()),
            },
        });
        out
    }

    pub fn ensure_field_domain(
        &mut self,
        bound_ptr: UintPtr,
        store: &mut UintStoreRequires,
        p2: &mut Poseidon2Requires,
    ) {
        let _ = self.ensure_field(bound_ptr, store, p2);
    }

    pub fn ec_create(
        &mut self,
        a_ptr: u32,
        b_ptr: u32,
        x: &UintNode,
        y: &UintNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        assert_eq!(x.bound_ptr, y.bound_ptr, "coordinates must share a modulus");
        let key = EcKey::Create(a_ptr, b_ptr, x.hash, y.hash);
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let field = self
            .fields
            .get(&x.bound_ptr)
            .copied()
            .expect("coordinate field was not registered");
        self.consume_field(x.bound_ptr);
        let (group, point) = ec.point_on_curve(
            UintPtr::from_addr(a_ptr),
            UintPtr::from_addr(b_ptr),
            x.bound_ptr,
            x.ptr,
            y.ptr,
        );
        self.consume_uint(x);
        self.consume_uint(y);
        let absorption = p2.require_one_shot(
            P2Cap::ec_create(a_ptr, b_ptr),
            x.hash.as_array(),
            y.hash.as_array(),
        );
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcCreate {
                x_hash: x.hash,
                y_hash: y.hash,
                a_ptr,
                b_ptr,
                x_ptr: x.ptr.addr(),
                y_ptr: y.ptr.addr(),
                group_ptr: group.addr(),
                point_ptr: point.addr(),
                bound_ptr: x.bound_ptr.addr(),
                field_tag: P2Digest(field.tag.as_array()),
                is_pai: false,
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point };
        self.ec_dedup.insert(key, node);
        node
    }

    pub fn ec_pai(
        &mut self,
        a_ptr: u32,
        b_ptr: u32,
        bound_ptr: u32,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        let key = EcKey::Create(a_ptr, b_ptr, P2Digest::default(), P2Digest::default());
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let bound = UintPtr::from_addr(bound_ptr);
        let field = self.fields.get(&bound).copied().expect("PAI field was not registered");
        self.consume_field(bound);
        let (group, pai) =
            ec.pai_on_curve(UintPtr::from_addr(a_ptr), UintPtr::from_addr(b_ptr), bound);
        let absorption = p2.require_one_shot(
            P2Cap::ec_create(a_ptr, b_ptr),
            P2Digest::default().as_array(),
            P2Digest::default().as_array(),
        );
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcCreate {
                x_hash: P2Digest::default(),
                y_hash: P2Digest::default(),
                a_ptr,
                b_ptr,
                x_ptr: 0,
                y_ptr: 0,
                group_ptr: group.addr(),
                point_ptr: pai.addr(),
                bound_ptr,
                field_tag: P2Digest(field.tag.as_array()),
                is_pai: true,
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point: pai };
        self.ec_dedup.insert(key, node);
        node
    }

    pub fn ec_add(
        &mut self,
        p: &EcNode,
        q: &EcNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        self.ec_op(EcOpId::Add, p, Some(q), &mut ec, p2)
    }

    pub fn ec_sub(
        &mut self,
        p: &EcNode,
        q: &EcNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        self.ec_op(EcOpId::Sub, p, Some(q), &mut ec, p2)
    }

    pub fn ec_neg(
        &mut self,
        p: &EcNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        self.ec_op(EcOpId::Neg, p, None, &mut ec, p2)
    }

    pub fn ec_is(&mut self, p: &EcNode, q: &EcNode, p2: &mut Poseidon2Requires) -> Truthy {
        assert_eq!(p.point, q.point, "Is operands are unequal points - unprovable");
        self.consume_ec(p);
        self.consume_ec(q);
        let absorption =
            p2.require_one_shot(P2Cap::ec_op(EcOpId::Is), p.hash.as_array(), q.hash.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let out = self.fresh(hash);
        self.nodes.push(EvalNode {
            id: out.id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcBinOp {
                op: EcOpId::Is,
                lhs: p.hash,
                rhs: q.hash,
                p_ptr: p.point.addr(),
                q_ptr: q.point.addr(),
                r_ptr: 0,
                group_ptr: 0,
            },
        });
        out
    }

    fn ec_op(
        &mut self,
        op: EcOpId,
        p: &EcNode,
        q: Option<&EcNode>,
        ec: &mut EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        assert!(q.is_none() == matches!(op, EcOpId::Neg), "Neg is unary; Add/Sub are binary");
        assert!(!matches!(op, EcOpId::Is), "Is goes through ec_is");
        let rhs = q.map(|q| q.hash).unwrap_or_default();
        let key = EcKey::Op(op, p.hash, rhs);
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }

        let group = ec.group_of(p.point);
        let (r, q_ptr) = match op {
            EcOpId::Add => (ec.add(p.point, q.expect("binary").point, 1), q.unwrap().point),
            EcOpId::Sub => (ec.sub(p.point, q.expect("binary").point, 1), q.unwrap().point),
            EcOpId::Neg => {
                let (_, r, pai) = ec.neg(p.point, 1);
                (r, pai)
            },
            EcOpId::Is => unreachable!("Is goes through ec_is"),
        };
        self.consume_ec(p);
        if let Some(q) = q {
            self.consume_ec(q);
        }
        let absorption = p2.require_one_shot(P2Cap::ec_op(op), p.hash.as_array(), rhs.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcBinOp {
                op,
                lhs: p.hash,
                rhs,
                p_ptr: p.point.addr(),
                q_ptr: q_ptr.addr(),
                r_ptr: r.addr(),
                group_ptr: group.addr(),
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point: r };
        self.ec_dedup.insert(key, node);
        node
    }

    pub fn assert_no_stray_values(&self) {
        if let Some((id, _)) = self.node_consumers.iter().find(|&(_, &count)| count == 0) {
            panic!("stray field-element value node (id {id})");
        }
    }

    fn ensure_field(
        &mut self,
        bound_ptr: UintPtr,
        store: &mut UintStoreRequires,
        _p2: &mut Poseidon2Requires,
    ) -> FieldDomain {
        if let Some(&field) = self.fields.get(&bound_ptr) {
            return field;
        }

        let bound = store.uint(bound_ptr).value;
        let bound_limbs = to_limbs32(bound);
        let lo: [Felt; NUM_HASH] = core::array::from_fn(|i| Felt::from(bound_limbs[i]));
        let hi: [Felt; NUM_HASH] = core::array::from_fn(|i| Felt::from(bound_limbs[NUM_HASH + i]));
        store.require_uintval(bound_ptr);
        let domain = UintDomain::ALL
            .into_iter()
            .find(|domain| domain != &UintDomain::U256 && domain.minus_one() == bound_limbs)
            .expect("uint transcript roots require a canonical UintDomain bound");
        let tag = P2Cap::uint_value(domain);
        let field = FieldDomain { tag };
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: None,
            kind: NodeKind::FieldTag { bound_ptr: bound_ptr.addr(), tag, lo, hi },
        });
        self.fields.insert(bound_ptr, field);
        field
    }

    fn consume_field(&mut self, bound_ptr: UintPtr) {
        *self.field_consumers.entry(bound_ptr.addr()).or_insert(0) += 1;
    }

    fn push_uint_leaf(
        &mut self,
        ptr: UintPtr,
        bound_ptr: UintPtr,
        field: FieldDomain,
        is_pinned: bool,
        value: [u32; 8],
        p2: &mut Poseidon2Requires,
    ) -> (u32, P2Digest) {
        let lo: [Felt; NUM_HASH] = core::array::from_fn(|i| Felt::from(value[i]));
        let hi: [Felt; NUM_HASH] = core::array::from_fn(|i| Felt::from(value[NUM_HASH + i]));
        let absorption = p2.require_one_shot(field.tag, lo, hi);
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::UintLeaf {
                ptr: ptr.addr(),
                bound_ptr: bound_ptr.addr(),
                field_tag: P2Digest(field.tag.as_array()),
                is_pinned,
                lo,
                hi,
            },
        });
        (id, hash)
    }

    fn consume_uint(&mut self, node: &UintNode) {
        *self
            .node_consumers
            .get_mut(&node.id)
            .expect("UintNode consumed under a foreign requires") += 1;
    }

    fn consume_ec(&mut self, node: &EcNode) {
        *self
            .node_consumers
            .get_mut(&node.id)
            .expect("EcNode consumed under a foreign requires") += 1;
    }

    fn fresh(&mut self, hash: P2Digest) -> Truthy {
        let id = self.next_id;
        self.next_id += 1;
        self.live.insert(id);
        Truthy { id, hash }
    }

    fn consume(&mut self, t: Truthy) {
        assert!(self.live.remove(&t.id), "Truthy consumed twice");
    }
}

pub fn generate_trace(
    requires: TranscriptEvalRequires,
    root: impl Into<TranscriptRoot>,
    ec_store: &EcStoreRequires,
) -> RowMajorMatrix<Felt> {
    let root = root.into();
    let root_id = root.id();
    let public_root = root.hash();

    match root {
        TranscriptRoot::Truthy(_) => assert!(
            requires.live.len() == 1 && requires.live.contains(&root_id),
            "transcript has stray unasserted claims or root is not live: {} live",
            requires.live.len(),
        ),
        TranscriptRoot::PinnedUint(_) => assert!(
            requires.live.is_empty(),
            "pinned uint root cannot leave stray unasserted claims: {} live",
            requires.live.len(),
        ),
    }

    let root_node = requires
        .nodes
        .iter()
        .find(|n| n.id == root_id)
        .expect("root must be a recorded node (zero leaf, AND, pinned uint leaf, or Is node)");
    let non_root = |n: &&EvalNode| n.id != root_id;
    assert!(
        requires
            .nodes
            .iter()
            .filter(non_root)
            .all(|n| !matches!(n.kind, NodeKind::UintLeaf { is_pinned: true, .. })),
        "pinned uint claims are root-only",
    );
    let zero_mult: ProvideMult = requires
        .nodes
        .iter()
        .filter(non_root)
        .filter(|n| matches!(n.kind, NodeKind::Zero))
        .map(|_| 1u32)
        .sum();
    let rows: Vec<(&EvalNode, u32)> = requires
        .nodes
        .iter()
        .filter(non_root)
        .filter_map(|n| {
            let out_mult = match &n.kind {
                NodeKind::Zero => return None,
                NodeKind::FieldTag { bound_ptr, .. } => {
                    requires.field_consumers.get(bound_ptr).copied().unwrap_or(0)
                },
                NodeKind::And { .. }
                | NodeKind::UintLeaf { is_pinned: true, .. }
                | NodeKind::UintOp { op: UintOpId::Is, .. }
                | NodeKind::EcBinOp { op: EcOpId::Is, .. } => 1,
                NodeKind::UintLeaf { .. }
                | NodeKind::UintOp { .. }
                | NodeKind::EcCreate { .. }
                | NodeKind::EcBinOp { .. } => requires.node_consumers[&n.id],
            };
            Some((n, out_mult))
        })
        .collect();

    let n_rows = 1 + rows.len() + usize::from(zero_mult > 0);
    let height = n_rows.next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    push_node_row(&mut trace, root_node, 0, ec_store);
    for (node, out_mult) in rows {
        push_node_row(&mut trace, node, out_mult, ec_store);
    }
    if zero_mult > 0 {
        push_node_row(
            &mut trace,
            &EvalNode {
                id: 0,
                absorbed: None,
                kind: NodeKind::Zero,
            },
            zero_mult,
            ec_store,
        );
    }

    trace.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    debug_assert_eq!(public_root, root_hash(&trace), "row 0's hash must pin public_root");
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

fn uint_op_col(op: UintOpId) -> usize {
    match op {
        UintOpId::Add => COL_IS_ADD,
        UintOpId::Sub => COL_IS_SUB,
        UintOpId::Mul => COL_IS_MUL,
        UintOpId::Neg => COL_IS_NEG,
        UintOpId::Is => COL_IS_IS,
    }
}

fn ec_op_col(op: EcOpId) -> usize {
    match op {
        EcOpId::Add => COL_IS_ADD,
        EcOpId::Sub => COL_IS_SUB,
        EcOpId::Neg => COL_IS_NEG,
        EcOpId::Is => COL_IS_IS,
    }
}

fn write_children(row: &mut [Felt; NUM_MAIN_COLS], lhs: &P2Digest, rhs: &P2Digest) {
    row[COL_LHS_BEGIN..COL_LHS_BEGIN + NUM_HASH].copy_from_slice(&lhs.as_array());
    row[COL_RHS_BEGIN..COL_RHS_BEGIN + NUM_HASH].copy_from_slice(&rhs.as_array());
}

fn push_node_row(
    trace: &mut Vec<Felt>,
    node: &EvalNode,
    out_mult: ProvideMult,
    ec_store: &EcStoreRequires,
) {
    let mut row = [Felt::ZERO; NUM_MAIN_COLS];
    row[COL_ACT] = Felt::ONE;
    row[COL_OUT_MULT] = Felt::from(out_mult);

    match &node.kind {
        NodeKind::Zero => {
            debug_assert!(node.absorbed.is_none());
            row[COL_IS_ZERO] = Felt::ONE;
        },
        NodeKind::FieldTag { bound_ptr, tag, lo, hi } => {
            debug_assert!(node.absorbed.is_none());
            row[COL_LHS_BEGIN..COL_LHS_BEGIN + NUM_HASH].copy_from_slice(lo);
            row[COL_RHS_BEGIN..COL_RHS_BEGIN + NUM_HASH].copy_from_slice(hi);
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&tag.as_array());
            row[COL_IS_FIELD_TAG] = Felt::ONE;
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
        },
        NodeKind::And { lhs, rhs } => {
            let absorbed = node.absorbed.expect("AND nodes drive Poseidon2");
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
            write_children(&mut row, lhs, rhs);
            row[COL_IS_AND] = Felt::ONE;
        },
        NodeKind::UintLeaf {
            ptr,
            bound_ptr,
            field_tag,
            is_pinned,
            lo,
            hi,
        } => {
            let absorbed = node.absorbed.expect("uint leaf nodes drive Poseidon2");
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
            row[COL_LHS_BEGIN..COL_LHS_BEGIN + NUM_HASH].copy_from_slice(lo);
            row[COL_RHS_BEGIN..COL_RHS_BEGIN + NUM_HASH].copy_from_slice(hi);
            row[COL_ABSORB_CAP_BEGIN..COL_ABSORB_CAP_BEGIN + NUM_HASH]
                .copy_from_slice(&field_tag.as_array());
            row[COL_IS_UINT_LEAF] = Felt::ONE;
            row[COL_IS_PINNED] = Felt::from(*is_pinned as u8);
            row[COL_PTR] = Felt::from(*ptr);
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
            row[COL_PIN_PTR] = Felt::from(if *is_pinned { *ptr } else { 0 });
        },
        NodeKind::UintOp {
            op,
            lhs,
            rhs,
            a_ptr,
            b_ptr,
            r_ptr,
            bound_ptr,
            field_tag,
        } => {
            let absorbed = node.absorbed.expect("uint op nodes drive Poseidon2");
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
            write_children(&mut row, lhs, rhs);
            row[COL_IS_UINT_OP] = Felt::ONE;
            row[uint_op_col(*op)] = Felt::ONE;
            row[COL_PTR] = Felt::from(*r_ptr);
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
            row[COL_A_PTR] = Felt::from(*a_ptr);
            row[COL_B_PTR] = Felt::from(*b_ptr);
            row[COL_PARAM_A] = Felt::from(*op as u8);
            row[COL_ABSORB_CAP_BEGIN..COL_ABSORB_CAP_BEGIN + NUM_HASH]
                .copy_from_slice(&field_tag.as_array());
        },
        NodeKind::EcCreate {
            x_hash,
            y_hash,
            a_ptr,
            b_ptr,
            x_ptr,
            y_ptr,
            group_ptr,
            point_ptr,
            bound_ptr,
            field_tag,
            is_pai,
        } => {
            let absorbed = node.absorbed.expect("EC create nodes drive Poseidon2");
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
            write_children(&mut row, x_hash, y_hash);
            row[if *is_pai { COL_IS_EC_PAI } else { COL_IS_EC_CREATE }] = Felt::ONE;
            row[COL_PTR] = Felt::from(*point_ptr);
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
            row[COL_A_PTR] = Felt::from(*x_ptr);
            row[COL_B_PTR] = Felt::from(*y_ptr);
            row[COL_PARAM_A] = Felt::from(*a_ptr);
            row[COL_GROUP_PTR] = Felt::from(*group_ptr);
            row[COL_CURVE_B] = Felt::from(*b_ptr);
            row[COL_SBOUND_PTR] =
                Felt::from(ec_store.group_sbound(EcGroupPtr::from_addr(*group_ptr)).addr());
            row[COL_ABSORB_CAP_BEGIN..COL_ABSORB_CAP_BEGIN + NUM_HASH]
                .copy_from_slice(&field_tag.as_array());
        },
        NodeKind::EcBinOp {
            op,
            lhs,
            rhs,
            p_ptr,
            q_ptr,
            r_ptr,
            group_ptr,
        } => {
            let absorbed = node.absorbed.expect("EC op nodes drive Poseidon2");
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
            write_children(&mut row, lhs, rhs);
            row[COL_IS_EC_OP] = Felt::ONE;
            row[ec_op_col(*op)] = Felt::ONE;
            row[COL_PTR] = Felt::from(*r_ptr);
            row[COL_A_PTR] = Felt::from(*p_ptr);
            row[COL_B_PTR] = Felt::from(*q_ptr);
            row[COL_PARAM_A] = Felt::from(*op as u8);
            row[COL_GROUP_PTR] = Felt::from(*group_ptr);
        },
    }

    trace.extend(row);
}

fn root_hash(trace: &[Felt]) -> P2Digest {
    let mut hash = [Felt::ZERO; NUM_HASH];
    hash.copy_from_slice(&trace[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH]);
    P2Digest(hash)
}

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&TranscriptEvalAir, main, challenges)
}
