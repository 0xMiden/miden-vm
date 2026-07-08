//! Trace generation for the transcript eval chiplet.
//!
//! The transcript is built **explicitly** from [`Truthy`] and
//! [`UintNode`] handles. A `Truthy` stands for a `Binding(hash, True)`
//! claim — issued for a binding a downstream chip provides
//! ([`issue`](TranscriptEvalRequires::issue), e.g. the keccak chip's
//! `Binding(H_keccak, True)`), as a `ZERO_HASH` leaf
//! ([`zero`](TranscriptEvalRequires::zero)), for an explicit uint pin
//! claim, or by the `Is` predicate. A `UintNode` stands for a
//! `Binding(hash, Uint, ptr, bound_ptr)` value — a transient uint leaf
//! or an arithmetic op's result — consumed any number of times by
//! further ops. [`record_and`](TranscriptEvalRequires::record_and) folds
//! two `Truthy`s into an AND node `Hash(lhs || rhs || VM Tag::AND)`;
//! [`uint_op`](TranscriptEvalRequires::uint_op) /
//! [`record_is`](TranscriptEvalRequires::record_is) record the uint-op
//! nodes, while EC create rows commit the selected `group_ptr` in the curve
//! VALUE cap. Each recording entry drives its own Poseidon2 absorption —
//! and the uint entries their store / relation demand — through the
//! `&mut` requires it takes, the keccak-node pattern.
//!
//! Value nodes **intern by preimage**: a leaf keys on its (canonical)
//! ptr, an op on `(op, child hashes)` — the structural DAG identity, so
//! a re-requested node returns the existing shared-use handle (sharing
//! rides `out_mult`) and lays no fresh row, perm, or relation op. Two
//! nodes with one ptr but different hashes (a leaf and an op result
//! that collide in value) stay distinct claims — that ptr-equality
//! across hash-distinct nodes is exactly what `Is` proves.
//!
//! `Truthy` handles are **move-only and tracked**: each is consumed
//! exactly once (by `record_and`, or as the [`generate_trace`] root).
//! Reuse is a compile error; a handle issued but never consumed is a
//! stray claim `generate_trace` panics on — an unasserted keccak handle
//! would otherwise be a silent `Binding` bus imbalance (its provider's
//! `out_mult` with no matching eval consume). `UintNode`s are **counted**
//! instead: each op-use bumps the node's consumer count, which becomes
//! its row's `out_mult`; a value node with no consumer is likewise a
//! stray claim (a dead DAG branch proves nothing) and panics.
//!
//! Row order is free (both children flow over the bus, not a local
//! thread), so the root sits at row 0 — the AIR pins row 0's hash to
//! `public_root` — with `out_mult = 0` (no parent, it absorbs the
//! `Binding` σ). Every non-root `True`-binding node is consumed once
//! (`out_mult = 1`); value nodes carry their consumer count. `ZERO_HASH`
//! leaves all share **one** row (`Binding(0, True)` is a single
//! provider): `out_mult` = the number of non-root zero leaves.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use miden_core::{
    Felt,
    deferred::{Digest, fold_deferred_root},
    field::QuadFelt,
    utils::RowMajorMatrix,
};
use miden_precompiles::CurvePrecompile;

use crate::{
    ec::{
        EcRequire,
        trace::{EcGroupPtr, EcPointPtr},
    },
    logup::build_logup_aux_trace,
    relations::ProvideMult,
    transcript::{
        eval::{
            COL_A_PTR, COL_ACT, COL_B_PTR, COL_BOUND_PTR, COL_EC_CONTEXT_GROUP_PTR,
            COL_EC_CREATE_COORD_BOUND_PTR, COL_EC_CREATE_GROUP_PTR, COL_EC_CREATE_POINT_PTR,
            COL_EC_CREATE_X_PTR, COL_EC_CREATE_Y_PTR, COL_H_BEGIN, COL_H_END, COL_IS_ADD,
            COL_IS_AND, COL_IS_EC_CREATE, COL_IS_EC_MSM, COL_IS_EC_OP, COL_IS_EC_PAI, COL_IS_IS,
            COL_IS_MSM_LAST, COL_IS_MUL, COL_IS_PINNED, COL_IS_SUB, COL_IS_UINT_LEAF,
            COL_IS_UINT_OP, COL_IS_ZERO, COL_LHS_BEGIN, COL_LHS_END, COL_MSM_EXPR, COL_MSM_IDX,
            COL_MSM_IS_HEAD, COL_OUT_MULT, COL_PERM_SEQ_ID, COL_PIN_CLAIM_BOUND_PTR,
            COL_PIN_CLAIM_PIN_PTR, COL_PTR, COL_RHS_BEGIN, COL_RHS_END, COL_TAG_ARG0,
            COL_UINT_VALUE_BOUND_PTR, DIGEST_WIDTH, NUM_MAIN_COLS, TranscriptEvalAir,
        },
        nodes::{EcOpId, UintOpId},
        poseidon2::{
            P2Cap, P2Digest,
            math::STATE_WIDTH,
            trace::{PermSeqId, Poseidon2Requires, apply_permutation},
        },
    },
    uint::{
        UintRequire,
        trace::{UintPtr, UintStoreRequires},
    },
};

/// A handle to a `Binding(hash, True)` claim, issued by the eval requires.
///
/// Move-only (no `Copy`/`Clone`): a handle is consumed exactly once — by
/// [`TranscriptEvalRequires::record_and`] or as the [`generate_trace`]
/// root. Reuse is a compile error; a handle issued but never consumed is
/// caught as a stray claim at `generate_trace`.
#[derive(Debug)]
pub struct Truthy {
    id: u32,
    hash: P2Digest,
}

impl Truthy {
    /// The 4-felt binding hash this handle claims is `True`.
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

/// A handle to a `Binding(hash, Uint, ptr, bound_ptr)` value — a
/// transient uint leaf or an arithmetic op's result. Shared-use: ops take
/// `&UintNode` and each use bumps the node's consumer count (= its
/// `out_mult`). The store handle is deliberately crate-private — at the
/// DAG level a value is its hash; ptrs are bus-level witness glue.
#[derive(Debug, Clone, Copy)]
pub struct UintNode {
    pub(crate) id: u32,
    pub(crate) hash: P2Digest,
    pub(crate) ptr: UintPtr,
    pub(crate) bound_ptr: UintPtr,
}

impl UintNode {
    /// The 4-felt hash of the node this value-binding hangs off.
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

/// A handle to a `Binding(hash, Group, point_ptr)` value — a curve point
/// created by `EcCreate` or produced by an `EcBinOp`. Shared-use like
/// [`UintNode`]: ops take `&EcNode` and each use bumps the node's consumer
/// count. The point handle is crate-private — at the DAG level a point is
/// its hash; for point VALUE nodes the group selector and coordinates are
/// committed in that hash, while the point ptr is bus glue.
#[derive(Debug, Clone, Copy)]
pub struct EcNode {
    pub(crate) id: u32,
    pub(crate) hash: P2Digest,
    pub(crate) point: EcPointPtr,
}

impl EcNode {
    /// The 4-felt hash of the node this Group value-binding hangs off.
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

/// One recorded eval node — a zero leaf, AND, uint leaf, or uint op
/// (keccak handles get no row here: their `True` is provided by the
/// keccak chip itself and only consumed by an AND).
#[derive(Debug)]
struct EvalNode {
    id: u32,
    /// The Poseidon2 absorption this node commits — its digest (the row's
    /// `h[4]` columns) and the head perm-cycle handle the cap pins. `None`
    /// only for the constant [`NodeKind::Zero`] leaf, which runs no
    /// absorption (`hash = ZERO_HASH`, perm 0).
    absorbed: Option<Absorbed>,
    kind: NodeKind,
}

/// The hash data hoisted out of the [`NodeKind`] arms: a node's committed
/// digest plus the Poseidon2 perm-cycle handle whose cap the eval row
/// pins. Carried once on [`EvalNode`] rather than repeated per variant.
#[derive(Debug, Clone, Copy)]
struct Absorbed {
    hash: P2Digest,
    perm_seq_id: PermSeqId,
}

/// One absorb row of an [`NodeKind::EcMsm`] run — term `(Pᵢ, sᵢ)` folded
/// into one multi-block Poseidon2 absorption. `perm_seq_id` is the span head
/// plus this term's position. `digest` is this cycle's rate0 output for the
/// row's `h`; only the run's tail digest is consumed as the claim hash.
#[derive(Debug, Clone, Copy)]
struct MsmAbsorb {
    base_hash: P2Digest,
    scalar_hash: P2Digest,
    base_ptr: u32,
    scalar_ptr: u32,
    perm_seq_id: u32,
    digest: P2Digest,
}

/// The structural payload of an eval node — children ptrs / coords / op id,
/// with the committed digest + perm handle factored up to [`EvalNode`].
#[derive(Debug)]
enum NodeKind {
    /// `ZERO_HASH` leaf — `is_zero = 1`, `hash = 0`, no children.
    Zero,
    /// AND node folding two children's bindings into the node hash.
    And { lhs: P2Digest, rhs: P2Digest },
    /// Uint leaf / explicit pin claim — hashes a stored uint's 8×u32 value (`lo` ‖ `hi`,
    /// its two 4×32 halves pulled over `UintVal`). Runtime leaves use the VM uint value cap
    /// `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]` and bind
    /// `Binding(hash, Uint, ptr, bound_ptr)`. Explicit pin claims use
    /// `(UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0)` with `pin_ptr = ptr` and bind
    /// `Binding(hash, True)`.
    UintLeaf {
        ptr: u32,
        bound_ptr: u32,
        is_pinned: bool,
        lo: [Felt; DIGEST_WIDTH],
        hi: [Felt; DIGEST_WIDTH],
    },
    /// Uint op — hashes its two child hashes under the VM uint op cap
    /// `[UintPrecompile::id(), op_id, 0, 0]`, consumes the children's `Uint`
    /// bindings (`a_ptr` / `b_ptr` / `bound_ptr`) plus one `UintAdd` / `UintMul`
    /// relation tuple, and binds `(hash, Uint, r_ptr, bound_ptr)` — or
    /// `(hash, True)` for [`UintOpId::Is`]. `Is` carries `b_ptr = a_ptr` and
    /// `r_ptr = 0`.
    UintOp {
        op: UintOpId,
        lhs: P2Digest,
        rhs: P2Digest,
        a_ptr: u32,
        b_ptr: u32,
        r_ptr: u32,
        bound_ptr: u32,
    },
    /// EcCreate — hashes two uint-coord child hashes `(x, y)` under the VM curve
    /// VALUE cap `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`, consumes
    /// the finite coords' `Uint` bindings plus one `EcPoint` membership tuple,
    /// and binds `(hash, Group, point_ptr)`. PAI mode has no coord children.
    EcCreate {
        x_hash: P2Digest,
        y_hash: P2Digest,
        x_ptr: u32,
        y_ptr: u32,
        group_ptr: u32,
        point_ptr: u32,
        bound_ptr: u32,
        /// ∞ mode: `point_ptr` is the group's PAI row, no coord children
        /// (`x_hash = y_hash = 0`, `x_ptr = y_ptr = 0`), `is_ec_pai`
        /// flag instead of `is_ec_create`.
        is_pai: bool,
    },
    /// EcBinOp — hashes two point child hashes under the VM curve op cap
    /// `[CurvePrecompile::id(), op, 0, 0]`. `Add` consumes `EcGroupAdd(group, p, q, r)`, `Sub`
    /// consumes the rearranged `EcGroupAdd(group, r, q, p)`, and both bind
    /// `(hash, Group, r_ptr)`; `Is` consumes no relation (shared
    /// `p_ptr = q_ptr`) and binds `(hash, True)` (`r_ptr = group_ptr = 0`).
    EcBinOp {
        op: EcOpId,
        lhs: P2Digest,
        rhs: P2Digest,
        p_ptr: u32,
        q_ptr: u32,
        r_ptr: u32,
        group_ptr: u32,
    },
    /// EcMsm — the claim `R = Σ sᵢ·Pᵢ`, laid as a **run** of absorb rows
    /// (one per `absorbs` entry, the last the boundary) backed by one
    /// Poseidon2 absorption span. Each row consumes the term's child
    /// `Group`/`Uint` bindings + `MsmClaimTerm`; only the boundary consumes
    /// the tail digest via `MsmExpr(expr, group, val, k)` and binds
    /// `(h_claim, Group, val)`.
    EcMsm {
        absorbs: Vec<MsmAbsorb>,
        expr: u32,
        group: u32,
        val: u32,
        bound: u32,
    },
}

/// Interning key for a uint value node ([`UintNode`]): a transient `Leaf`
/// by its (canonical) ptr, an `Op` by `(op, lhs hash, rhs hash)` — the
/// structural DAG identity, so a re-request collapses onto the existing row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum UintKey {
    Leaf(UintPtr),
    Op(UintOpId, P2Digest, P2Digest),
}

/// Interning key for an EC value node ([`EcNode`]): a `Create` by its
/// `group_ptr` + coord hashes (the group rides the cap not the children, so
/// identical coords on distinct groups stay distinct; ∞ uses the zero coord
/// hashes), an `Op` by `(op, P hash, Q hash)`, an `Msm` claim by its
/// `expr_ptr` (one node per expression; its hash chains the whole term run).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum EcKey {
    Create(u32, P2Digest, P2Digest),
    Op(EcOpId, P2Digest, P2Digest),
    Msm(u32),
}

/// `*Requires`-pattern accumulator for the eval chip, built from explicit
/// [`Truthy`] / [`UintNode`] handles. [`generate_trace`] lays its trace.
#[derive(Debug, Default)]
pub struct TranscriptEvalRequires {
    /// Monotonic handle-id allocator (shared by both handle kinds).
    next_id: u32,
    /// Issued-but-unconsumed `Truthy` ids. Holds only the root at trace-gen.
    live: BTreeSet<u32>,
    /// Per-value-node consumer counts (= the row's `out_mult`), bumped by
    /// each op-use. A node still at 0 at trace-gen is a stray claim.
    node_consumers: BTreeMap<u32, ProvideMult>,
    /// Zero leaves + AND / uint-leaf / uint-op nodes, in record order.
    nodes: Vec<EvalNode>,
    /// Uint value-node interning (leaf + op), keyed by [`UintKey`] —
    /// mirroring keccak's input-keyed dedup (a re-requested node collapses
    /// onto one row; sharing rides `out_mult`).
    uint_dedup: BTreeMap<UintKey, UintNode>,
    /// EC value-node interning (create + binop + MSM claim), keyed by
    /// [`EcKey`].
    ec_dedup: BTreeMap<EcKey, EcNode>,
}

impl TranscriptEvalRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a handle for a `Binding(hash, True)` a downstream chip
    /// provides (the keccak chip today; future Field/Group `Eq` arms). No
    /// eval row — the provider lays the bus provide; the eval chip only
    /// consumes it when the handle is folded.
    pub fn issue(&mut self, hash: P2Digest) -> Truthy {
        self.fresh(hash)
    }

    /// Issue a `ZERO_HASH` leaf handle. All non-root zero leaves merge into
    /// one row at trace-gen, so calling this per zero child is free.
    pub fn zero(&mut self) -> Truthy {
        let t = self.fresh(P2Digest::default());
        self.nodes.push(EvalNode {
            id: t.id,
            absorbed: None,
            kind: NodeKind::Zero,
        });
        t
    }

    /// Record an AND node folding `a` and `b` (both consumed) into
    /// `Binding(hash, True)`, driving the Poseidon2 absorption of
    /// `a.hash || b.hash || VM Tag::AND` itself. Returns the result
    /// handle.
    pub fn record_and(&mut self, a: Truthy, b: Truthy, p2: &mut Poseidon2Requires) -> Truthy {
        let (lhs, rhs) = (a.hash, b.hash);
        self.consume(a);
        self.consume(b);
        let absorption = p2.require_one_shot(P2Cap::and(), lhs.as_array(), rhs.as_array());
        let _ = p2.require_digest(absorption.digest);
        debug_assert_eq!(
            absorption.digest,
            P2Digest::from(fold_deferred_root(
                Digest::new(lhs.as_array()),
                Digest::new(rhs.as_array()),
            )),
        );
        let hash = absorption.digest;
        let out = self.fresh(hash);
        self.nodes.push(EvalNode {
            id: out.id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::And { lhs, rhs },
        });
        out
    }

    /// Record a uint value row (shared by [`uint_leaf`](Self::uint_leaf) and
    /// [`pin_uint`](Self::pin_uint)): drive the Poseidon2 absorption of `lo ‖ hi` under either
    /// the runtime uint-leaf cap or the explicit pin-claim cap, then push the row. Returns the
    /// node id + hash.
    fn push_uint_leaf(
        &mut self,
        ptr: UintPtr,
        bound_ptr: UintPtr,
        is_pinned: bool,
        value: [u32; 8],
        p2: &mut Poseidon2Requires,
    ) -> (u32, P2Digest) {
        let lo: [Felt; DIGEST_WIDTH] = core::array::from_fn(|i| Felt::from(value[i]));
        let hi: [Felt; DIGEST_WIDTH] =
            core::array::from_fn(|i| Felt::from(value[DIGEST_WIDTH + i]));
        let cap = if is_pinned {
            P2Cap::uint_pin_claim(bound_ptr.addr(), ptr.addr())
        } else {
            P2Cap::uint_value(bound_ptr.addr())
        };
        let absorption = p2.require_one_shot(cap, lo, hi);
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
                is_pinned,
                lo,
                hi,
            },
        });
        (id, hash)
    }

    /// Record a *transient* uint leaf binding `value` to
    /// `Binding(hash, Uint, ptr, bound_ptr)` — a value-binding consumed by
    /// downstream arithmetic over the bus, not folded into the spine —
    /// driving its `UintVal` demand and Poseidon2 absorption. One leaf
    /// node per stored uint: ptrs are `(value, modulus)`-canonical, so
    /// re-leafing a value returns the existing shared-use handle (and
    /// lays nothing). A fresh node's consumer count starts at 0 and must
    /// be bumped by at least one op-use.
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
        store.require_uintval(ptr);
        let (id, hash) = self.push_uint_leaf(ptr, bound_ptr, false, value, p2);
        self.node_consumers.insert(id, 0);
        let node = UintNode { id, hash, ptr, bound_ptr };
        self.uint_dedup.insert(UintKey::Leaf(ptr), node);
        node
    }

    /// Record a value-producing uint op (`Add` / `Sub` / `Mul`) over `a` and
    /// `b`: dedup by `(op, child hashes)` — a re-requested op returns the
    /// existing shared-use handle — else record the relation-chiplet op through
    /// `uints` (interning the result), drive the Poseidon2 absorption of
    /// `a.hash ‖ b.hash` under the VM uint op cap, consume each child once, and
    /// bind the result to `Binding(hash, Uint, r_ptr, bound_ptr)`. Returns
    /// the result's handle.
    pub fn uint_op(
        &mut self,
        op: UintOpId,
        a: &UintNode,
        b: &UintNode,
        mut uints: UintRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> UintNode {
        assert!(!matches!(op, UintOpId::Is), "Is goes through record_is");
        assert_eq!(a.bound_ptr, b.bound_ptr, "op operands must share a modulus");
        let key = UintKey::Op(op, a.hash, b.hash);
        if let Some(&node) = self.uint_dedup.get(&key) {
            return node;
        }

        let r_ptr = match op {
            UintOpId::Add => uints.add(a.ptr, b.ptr),
            UintOpId::Sub => uints.sub(a.ptr, b.ptr),
            UintOpId::Mul => uints.mac(1, a.ptr, b.ptr, 0, a.bound_ptr),
            UintOpId::Is => unreachable!("Is goes through record_is"),
        };

        let bound_ptr = a.bound_ptr;
        self.consume_uint(a);
        self.consume_uint(b);
        let absorption =
            p2.require_one_shot(P2Cap::uint_op(op), a.hash.as_array(), b.hash.as_array());
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
                rhs: b.hash,
                a_ptr: a.ptr.addr(),
                b_ptr: b.ptr.addr(),
                r_ptr: r_ptr.addr(),
                bound_ptr: bound_ptr.addr(),
            },
        });
        self.node_consumers.insert(id, 0);
        let node = UintNode { id, hash, ptr: r_ptr, bound_ptr };
        self.uint_dedup.insert(key, node);
        node
    }

    /// Record an `Is` node asserting `a ≡ b`, consuming each child's
    /// value-binding once, driving the Poseidon2 absorption of
    /// `a.hash ‖ b.hash` under the VM uint `EQ`/`Is` cap, and binding
    /// `(hash, True)` — the predicate that folds uint values into the
    /// transcript spine. Equality is asserted on the bus (the row
    /// carries one shared ptr for both child consumes), so the honest
    /// prover must have interned both sides to the same ptr — the
    /// canonical-interning completeness contract. Returns the foldable
    /// [`Truthy`].
    pub fn record_is(&mut self, a: &UintNode, b: &UintNode, p2: &mut Poseidon2Requires) -> Truthy {
        assert_eq!(a.bound_ptr, b.bound_ptr, "Is operands must share a modulus");
        assert_eq!(
            a.ptr, b.ptr,
            "Is operands are unequal (distinct interned ptrs) — the claim is unprovable",
        );
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
            },
        });
        out
    }

    /// Record an EcCreate node — a curve point from two uint coords `(x, y)` on
    /// an already-selected group. Dedups by `(group, x hash, y hash)`; else
    /// drives the EC value work (eager-membership point) through `ec`, the
    /// Poseidon2 absorption of
    /// `x.hash ‖ y.hash ‖ [CurvePrecompile::id(), VALUE_OP_ID, group, 0]`, consumes
    /// both coords, and binds `(hash, Group, point_ptr)`. Returns the shared-use
    /// [`EcNode`].
    pub fn ec_create(
        &mut self,
        group_ptr: u32,
        x: &UintNode,
        y: &UintNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        assert_eq!(x.bound_ptr, y.bound_ptr, "coordinates must share a modulus");
        let key = EcKey::Create(group_ptr, x.hash, y.hash);
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let point = ec.point_on_group(EcGroupPtr::from_addr(group_ptr), x.ptr, y.ptr);
        self.consume_uint(x);
        self.consume_uint(y);
        let absorption =
            p2.require_one_shot(P2Cap::ec_create(group_ptr), x.hash.as_array(), y.hash.as_array());
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
                x_ptr: x.ptr.addr(),
                y_ptr: y.ptr.addr(),
                group_ptr,
                point_ptr: point.addr(),
                bound_ptr: x.bound_ptr.addr(),
                is_pai: false,
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point };
        self.ec_dedup.insert(key, node);
        node
    }

    /// Record an EcCreate/PAI node — the group's point-at-infinity. Dedups by
    /// `(group, 0, 0)` (one ∞ per group); else drives `ec.pai_on_group` (routing
    /// the row's `EcPoint(∞)` demand), the Poseidon2 absorption of
    /// `0 ‖ 0 ‖ [CurvePrecompile::id(), VALUE_OP_ID, group, 0]`, and binds
    /// `(hash, Group, pai_ptr)`. No coord children. Returns the shared-use
    /// [`EcNode`].
    pub fn ec_pai(
        &mut self,
        group_ptr: u32,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        let key = EcKey::Create(group_ptr, P2Digest::default(), P2Digest::default());
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let pai = ec.pai_on_group(EcGroupPtr::from_addr(group_ptr));
        let absorption = p2.require_one_shot(
            P2Cap::ec_create(group_ptr),
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
                x_ptr: 0,
                y_ptr: 0,
                group_ptr,
                point_ptr: pai.addr(),
                bound_ptr: 0,
                is_pai: true,
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point: pai };
        self.ec_dedup.insert(key, node);
        node
    }

    /// Record an EcBinOp/Add node `R = P + Q`. Dedups by `(Add, P hash,
    /// Q hash)`; else drives `ec.add` (the group law at provide mult 1)
    /// for `(group, R)`, the Poseidon2 absorption of `P.hash ‖ Q.hash ‖
    /// [CurvePrecompile::id(), ADD_OP_ID, 0, 0]`, consumes both operands, and binds `(hash,
    /// Group, r_ptr)`. Returns the shared-use [`EcNode`].
    pub fn ec_add(
        &mut self,
        p: &EcNode,
        q: &EcNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        let key = EcKey::Op(EcOpId::Add, p.hash, q.hash);
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let group = ec.group_of(p.point);
        let r = ec.add(p.point, q.point, 1);
        self.consume_ec(p);
        self.consume_ec(q);
        let absorption =
            p2.require_one_shot(P2Cap::ec_op(EcOpId::Add), p.hash.as_array(), q.hash.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcBinOp {
                op: EcOpId::Add,
                lhs: p.hash,
                rhs: q.hash,
                p_ptr: p.point.addr(),
                q_ptr: q.point.addr(),
                r_ptr: r.addr(),
                group_ptr: group.addr(),
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point: r };
        self.ec_dedup.insert(key, node);
        node
    }

    /// Record an EcBinOp/Sub node `R = P − Q` — the *rearranged* relation
    /// `R + Q = P` (one `EcGroupAdd` block via [`EcRequire::sub`]), the EC
    /// parallel of uint sub. Dedups by `(Sub, P hash, Q hash)`; else drives
    /// `ec.sub` (intern the witness `R`, certify `R + Q = P` at provide
    /// mult 1), consumes both operands, absorbs `P.hash ‖ Q.hash ‖
    /// [CurvePrecompile::id(), SUB_OP_ID, 0, 0]`, and binds `(hash, Group, r_ptr)` — `R`. The
    /// row carries `(p_ptr, q_ptr, r_ptr) = (P, Q, R)`; the AIR's Sub arm
    /// permutes the consume to `EcGroupAdd(g, R, Q, P)`. Returns the
    /// shared-use [`EcNode`].
    pub fn ec_sub(
        &mut self,
        p: &EcNode,
        q: &EcNode,
        mut ec: EcRequire<'_>,
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        let key = EcKey::Op(EcOpId::Sub, p.hash, q.hash);
        if let Some(&node) = self.ec_dedup.get(&key) {
            return node;
        }
        let group = ec.group_of(p.point);
        let r = ec.sub(p.point, q.point, 1);
        self.consume_ec(p);
        self.consume_ec(q);
        let absorption =
            p2.require_one_shot(P2Cap::ec_op(EcOpId::Sub), p.hash.as_array(), q.hash.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::EcBinOp {
                op: EcOpId::Sub,
                lhs: p.hash,
                rhs: q.hash,
                p_ptr: p.point.addr(),
                q_ptr: q.point.addr(),
                r_ptr: r.addr(),
                group_ptr: group.addr(),
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash, point: r };
        self.ec_dedup.insert(key, node);
        node
    }

    /// Record a EcBinOp/Is node asserting `P ≡ Q` — point-ptr equality
    /// (canonical interning means equal points share a ptr), consuming
    /// both operands' Group bindings at one shared ptr, driving the
    /// Poseidon2 absorption of `P.hash ‖ Q.hash ‖ [CurvePrecompile::id(), EQ_OP_ID, 0, 0]`,
    /// and binding `(hash, True)`. Returns the foldable [`Truthy`].
    pub fn ec_is(&mut self, p: &EcNode, q: &EcNode, p2: &mut Poseidon2Requires) -> Truthy {
        assert_eq!(
            p.point, q.point,
            "Is operands are unequal points (distinct interned ptrs) — unprovable",
        );
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
                q_ptr: q.point.addr(), // == p_ptr — the equality
                r_ptr: 0,
                group_ptr: 0,
            },
        });
        out
    }

    /// Record an EcMsm claim node `R = Σ sᵢ·Pᵢ` — the VM PairList sponge over
    /// caller-declared `terms = [(Pᵢ, sᵢ)]`. The whole term list is one
    /// Poseidon2 absorption under the VM curve MSM IV
    /// `[CurvePrecompile::id(), MSM_OP_ID, 0, 0]`; the returned absorption
    /// digest is `h_claim` and it binds `(h_claim, Group, val)`. Consumes each
    /// term's child `Group`/`Uint` binding (their `out_mult`);
    /// the absorb rows additionally consume `MsmClaimTerm` and the boundary
    /// `MsmExpr` over the bus (laid by the AIR). Dedups by `expr`. Returns
    /// the value's shared-use [`EcNode`].
    pub fn record_ec_msm(
        &mut self,
        expr: u32,
        group: u32,
        val: EcPointPtr,
        bound: u32,
        terms: &[(EcNode, UintNode)],
        p2: &mut Poseidon2Requires,
    ) -> EcNode {
        if let Some(&node) = self.ec_dedup.get(&EcKey::Msm(expr)) {
            return node;
        }
        assert!(!terms.is_empty(), "an MSM claim needs at least one term");
        let blocks: Vec<_> = terms
            .iter()
            .map(|(base, scalar)| {
                assert_eq!(
                    scalar.bound_ptr.addr(),
                    bound,
                    "term scalar must be stored under the claim's scalar bound",
                );
                (base.hash.as_array(), scalar.hash.as_array())
            })
            .collect();

        let initial_cap = P2Cap::ec_msm_iv();
        let absorption = p2.require_absorption(initial_cap, blocks.iter().copied());
        let _ = p2.require_digest(absorption.digest);
        let h_claim = absorption.digest;

        let mut absorbs = Vec::with_capacity(terms.len());
        let mut cap = initial_cap.as_array();
        let span_head = absorption.head().seq();
        for (idx, ((base, scalar), &(rate0, rate1))) in terms.iter().zip(blocks.iter()).enumerate()
        {
            let mut state = [Felt::ZERO; STATE_WIDTH];
            state[0..4].copy_from_slice(&rate0);
            state[4..8].copy_from_slice(&rate1);
            state[8..12].copy_from_slice(&cap);
            let state_out = apply_permutation(state);
            let digest = P2Digest([state_out[0], state_out[1], state_out[2], state_out[3]]);
            cap = [state_out[8], state_out[9], state_out[10], state_out[11]];

            absorbs.push(MsmAbsorb {
                base_hash: base.hash,
                scalar_hash: scalar.hash,
                base_ptr: base.point.addr(),
                scalar_ptr: scalar.ptr.addr(),
                perm_seq_id: span_head + idx as u32,
                digest,
            });
            self.consume_ec(base);
            self.consume_uint(scalar);
        }
        debug_assert_eq!(absorbs.last().expect("non-empty MSM").digest, h_claim);
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(EvalNode {
            id,
            absorbed: None, // per-row perms / digests live in `absorbs`
            kind: NodeKind::EcMsm {
                absorbs,
                expr,
                group,
                val: val.addr(),
                bound,
            },
        });
        self.node_consumers.insert(id, 0);
        let node = EcNode { id, hash: h_claim, point: val };
        self.ec_dedup.insert(EcKey::Msm(expr), node);
        node
    }

    fn consume_ec(&mut self, node: &EcNode) {
        *self
            .node_consumers
            .get_mut(&node.id)
            .expect("EcNode consumed under a foreign requires") += 1;
    }

    fn consume_uint(&mut self, node: &UintNode) {
        *self
            .node_consumers
            .get_mut(&node.id)
            .expect("UintNode consumed under a foreign requires") += 1;
    }

    /// Panic on any value node no op ever consumed — a dead DAG branch
    /// proves nothing about the root, so it is almost certainly a
    /// programming error. The Session calls this at `finish`; bare
    /// requires-level users may lay dormant value nodes deliberately
    /// (`out_mult = 0` is balanced).
    pub fn assert_no_stray_values(&self) {
        if let Some((id, _)) = self.node_consumers.iter().find(|&(_, &count)| count == 0) {
            panic!("stray uint value node (id {id}): recorded but never consumed by an op");
        }
    }

    /// Record an explicit uint pin claim binding `value` to `Binding(hash, True)`.
    ///
    /// The cap is `(UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr = ptr, 0)`, and the row consumes both
    /// `UintVal` halves at `ptr`. The returned handle is foldable into the initial/root transcript
    /// exactly like any [`Truthy`].
    pub fn pin_uint(
        &mut self,
        ptr: UintPtr,
        bound_ptr: UintPtr,
        value: [u32; 8],
        store: &mut UintStoreRequires,
        p2: &mut Poseidon2Requires,
    ) -> Truthy {
        store.require_uintval(ptr);
        let (id, hash) = self.push_uint_leaf(ptr, bound_ptr, true, value, p2);
        self.live.insert(id);
        Truthy { id, hash }
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

/// Lay the eval chip's main trace, designating `root` (its hash is the
/// transcript `public_root`, pinned at row 0). Panics if `root` is not a
/// recorded node — a raw keccak handle has no eval row — or if any other
/// issued `Truthy` is still unconsumed (a stray claim). Zero-consumer
/// *value* nodes are laid dormant (`out_mult = 0`, balanced) — flagging
/// them as bugs is the Session's policy
/// ([`assert_no_stray_values`](TranscriptEvalRequires::assert_no_stray_values)),
/// not this mechanism layer's.
pub fn generate_trace(requires: TranscriptEvalRequires, root: Truthy) -> RowMajorMatrix<Felt> {
    let root_id = root.id;
    let public_root = root.hash;
    assert!(
        requires.live.len() == 1 && requires.live.contains(&root_id),
        "transcript has stray unasserted claims or root is not live: {} live",
        requires.live.len(),
    );

    let root_node = requires.nodes.iter().find(|n| n.id == root_id).expect(
        "root must be a recorded node (zero leaf, AND, or Is node), not a raw keccak handle",
    );

    // Row 0 is the root (out_mult 0 — no parent, it absorbs the Binding σ).
    // Every other True-binding node (AND / pinned leaf / Is) is consumed
    // once; value nodes (transient leaf / value op) carry their op-consumer
    // count. Non-root zero leaves all merge into one row whose out_mult is
    // their count — `Binding(0, True)` has a single provider.
    let non_root = |n: &&EvalNode| n.id != root_id;
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
                NodeKind::Zero => return None, // merged below
                NodeKind::And { .. }
                | NodeKind::UintLeaf { is_pinned: true, .. }
                | NodeKind::UintOp { op: UintOpId::Is, .. }
                | NodeKind::EcBinOp { op: EcOpId::Is, .. } => 1,
                NodeKind::UintLeaf { .. }
                | NodeKind::UintOp { .. }
                | NodeKind::EcCreate { .. }
                | NodeKind::EcBinOp { .. }
                | NodeKind::EcMsm { .. } => requires.node_consumers[&n.id],
            };
            Some((n, out_mult))
        })
        .collect();

    // Most nodes are one row; an EcMsm claim is a run of `absorbs.len()`.
    let node_rows = |kind: &NodeKind| match kind {
        NodeKind::EcMsm { absorbs, .. } => absorbs.len(),
        _ => 1,
    };
    let n_rows = 1
        + rows.iter().map(|(n, _)| node_rows(&n.kind)).sum::<usize>()
        + usize::from(zero_mult > 0);
    let height = n_rows.next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    push_node_row(&mut trace, root_node, 0);
    for (node, out_mult) in rows {
        push_node_row(&mut trace, node, out_mult);
    }
    if zero_mult > 0 {
        // The merged zero row has no backing node — synthesize one (its id
        // is unused by the row layout).
        push_node_row(
            &mut trace,
            &EvalNode {
                id: 0,
                absorbed: None,
                kind: NodeKind::Zero,
            },
            zero_mult,
        );
    }

    // Padding rows are all-zero (out_mult = 0): the Binding provide is
    // `−out_mult`, so they touch no bus. (The provide multiplicity is no
    // longer range-checked — it's pinned to the consumer count by bus
    // balance; see `docs/lookup-argument.md`.)
    trace.resize(height * NUM_MAIN_COLS, Felt::ZERO);

    debug_assert_eq!(public_root, root_hash(&trace), "row 0's hash must pin public_root");
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

/// The shared op-flag column an op id rides — uint and ec ops map by name
/// onto one set of columns (the op-family bit disambiguates).
fn uint_op_col(op: UintOpId) -> usize {
    match op {
        UintOpId::Add => COL_IS_ADD,
        UintOpId::Sub => COL_IS_SUB,
        UintOpId::Mul => COL_IS_MUL,
        UintOpId::Is => COL_IS_IS,
    }
}

fn ec_op_col(op: EcOpId) -> usize {
    match op {
        EcOpId::Add => COL_IS_ADD,
        EcOpId::Sub => COL_IS_SUB,
        EcOpId::Is => COL_IS_IS,
    }
}

fn ec_op_id(op: EcOpId) -> u64 {
    match op {
        EcOpId::Add => CurvePrecompile::ADD_OP_ID,
        EcOpId::Sub => CurvePrecompile::SUB_OP_ID,
        EcOpId::Is => CurvePrecompile::EQ_OP_ID,
    }
}

/// Copy two child digests into the `lhs` / `rhs` hash blocks.
fn write_children(row: &mut [Felt; NUM_MAIN_COLS], lhs: &P2Digest, rhs: &P2Digest) {
    let lhs = lhs.as_array();
    let rhs = rhs.as_array();
    row[COL_LHS_BEGIN..COL_LHS_END].copy_from_slice(&lhs);
    row[COL_RHS_BEGIN..COL_RHS_END].copy_from_slice(&rhs);
}

/// Append one eval row, written by column *constant* so the layout in
/// `mod.rs` is the single source of truth. Each kind sets its family / op
/// flags + reused ptr columns; everything else stays 0.
fn push_node_row(trace: &mut Vec<Felt>, node: &EvalNode, out_mult: ProvideMult) {
    // EcMsm is the one multi-row node: lay its absorb run (one row per term;
    // the head consumes the IV cap, and the last row consumes the final digest /
    // carries the value ptr + Group-binding `out_mult`).
    if let NodeKind::EcMsm { absorbs, expr, group, val, bound } = &node.kind {
        let k = absorbs.len();
        for (idx, a) in absorbs.iter().enumerate() {
            let is_last = idx == k - 1;
            let mut row = [Felt::ZERO; NUM_MAIN_COLS];
            row[COL_ACT] = Felt::ONE;
            row[COL_IS_EC_MSM] = Felt::ONE;
            row[COL_IS_MSM_LAST] = Felt::from(is_last as u8);
            row[COL_MSM_IS_HEAD] = Felt::from((idx == 0) as u8);
            row[COL_PERM_SEQ_ID] = Felt::from(a.perm_seq_id);
            let base_hash = a.base_hash.as_array();
            let scalar_hash = a.scalar_hash.as_array();
            let digest = a.digest.as_array();
            row[COL_LHS_BEGIN..COL_LHS_END].copy_from_slice(&base_hash);
            row[COL_RHS_BEGIN..COL_RHS_END].copy_from_slice(&scalar_hash);
            row[COL_H_BEGIN..COL_H_END].copy_from_slice(&digest);
            row[COL_A_PTR] = Felt::from(a.base_ptr);
            row[COL_B_PTR] = Felt::from(a.scalar_ptr);
            row[COL_MSM_IDX] = Felt::from(idx as u32);
            row[COL_MSM_EXPR] = Felt::from(*expr);
            row[COL_EC_CONTEXT_GROUP_PTR] = Felt::from(*group);
            row[COL_BOUND_PTR] = Felt::from(*bound);
            if is_last {
                row[COL_PTR] = Felt::from(*val);
                row[COL_OUT_MULT] = Felt::from(out_mult);
            }
            trace.extend(row);
        }
        return;
    }

    let mut row = [Felt::ZERO; NUM_MAIN_COLS];
    row[COL_ACT] = Felt::ONE;
    row[COL_OUT_MULT] = Felt::from(out_mult);

    // The constant Zero leaf runs no absorption: act + ZERO_HASH (already 0)
    // + the is_zero flag, perm 0.
    let Some(Absorbed { hash, perm_seq_id }) = node.absorbed else {
        row[COL_IS_ZERO] = Felt::ONE;
        trace.extend(row);
        return;
    };

    // Every other node commits an absorption: the perm-cycle handle + the
    // digest in the h[4] block, shared by all arms.
    row[COL_PERM_SEQ_ID] = Felt::from(perm_seq_id.seq());
    let hash = hash.as_array();
    row[COL_H_BEGIN..COL_H_END].copy_from_slice(&hash);

    match &node.kind {
        NodeKind::Zero => unreachable!("Zero carries no absorption"),
        NodeKind::And { lhs, rhs } => {
            write_children(&mut row, lhs, rhs);
            row[COL_IS_AND] = Felt::ONE;
        },
        NodeKind::UintLeaf { ptr, bound_ptr, is_pinned, lo, hi } => {
            row[COL_LHS_BEGIN..COL_LHS_END].copy_from_slice(lo);
            row[COL_RHS_BEGIN..COL_RHS_END].copy_from_slice(hi);
            row[COL_IS_UINT_LEAF] = Felt::ONE;
            row[COL_IS_PINNED] = Felt::from(*is_pinned as u8);
            row[COL_PTR] = Felt::from(*ptr);
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
            if *is_pinned {
                // Explicit pin claim: `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`.
                row[COL_PIN_CLAIM_BOUND_PTR] = Felt::from(*bound_ptr);
                row[COL_PIN_CLAIM_PIN_PTR] = Felt::from(*ptr);
            } else {
                // Runtime VM uint VALUE: `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]`.
                row[COL_UINT_VALUE_BOUND_PTR] = Felt::from(*bound_ptr);
            }
        },
        NodeKind::UintOp {
            op,
            lhs,
            rhs,
            a_ptr,
            b_ptr,
            r_ptr,
            bound_ptr,
        } => {
            write_children(&mut row, lhs, rhs);
            row[COL_IS_UINT_OP] = Felt::ONE;
            row[uint_op_col(*op)] = Felt::ONE;
            row[COL_PTR] = Felt::from(*r_ptr); // result ptr
            row[COL_BOUND_PTR] = Felt::from(*bound_ptr);
            row[COL_A_PTR] = Felt::from(*a_ptr);
            row[COL_B_PTR] = Felt::from(*b_ptr);
            row[COL_TAG_ARG0] = Felt::from(*op as u8); // cap slot 1 = op id
            // cap slot 2 stays 0: the bound rides the Binding / uint-relation buses.
        },
        NodeKind::EcCreate {
            x_hash,
            y_hash,
            x_ptr,
            y_ptr,
            group_ptr,
            point_ptr,
            bound_ptr,
            is_pai,
        } => {
            write_children(&mut row, x_hash, y_hash); // (x, y) coord hashes (0 on PAI)
            row[if *is_pai { COL_IS_EC_PAI } else { COL_IS_EC_CREATE }] = Felt::ONE;
            row[COL_EC_CREATE_POINT_PTR] = Felt::from(*point_ptr); // the point (finite / PAI)
            row[COL_EC_CREATE_COORD_BOUND_PTR] = Felt::from(*bound_ptr); // coord modulus (0 on PAI)
            row[COL_EC_CREATE_X_PTR] = Felt::from(*x_ptr); // x coord (0 on PAI)
            row[COL_EC_CREATE_Y_PTR] = Felt::from(*y_ptr); // y coord (0 on PAI)
            row[COL_EC_CREATE_GROUP_PTR] = Felt::from(*group_ptr); // curve VALUE group_ptr
            // COL_TAG_ARG0 stays 0: curve VALUE_OP_ID. COL_EC_CONTEXT_GROUP_PTR is not live on
            // create rows.
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
            write_children(&mut row, lhs, rhs); // P, Q hashes
            row[COL_IS_EC_OP] = Felt::ONE;
            row[ec_op_col(*op)] = Felt::ONE;
            row[COL_PTR] = Felt::from(*r_ptr); // result (0 for Is)
            row[COL_A_PTR] = Felt::from(*p_ptr); // P
            row[COL_B_PTR] = Felt::from(*q_ptr); // Q
            row[COL_TAG_ARG0] = Felt::from_u32(ec_op_id(*op) as u32); // curve op cap slot 1
            row[COL_EC_CONTEXT_GROUP_PTR] = Felt::from(*group_ptr); // 0 for Is
        },
        NodeKind::EcMsm { .. } => unreachable!("EcMsm is laid as a multi-row run above"),
    }
    trace.extend(row);
}

/// Row 0's `h[4]` columns (the first-row root pin) as a digest.
fn root_hash(trace: &[Felt]) -> P2Digest {
    P2Digest(core::array::from_fn(|i| trace[COL_H_BEGIN + i]))
}

// PROVER
// ================================================================================================

/// Aux-trace builder for [`TranscriptEvalAir`] — the generic
/// [`build_logup_aux_trace`] driver. Called by the AIR's
/// `LiftedAir::build_aux_trace`.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&TranscriptEvalAir, main, challenges)
}
