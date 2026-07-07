//! Orchestration facade over the fourteen-chiplet stack: the Keccak
//! transcript, the uint store and its arithmetic relations, and the EC
//! layer (group table + point store + group-law add).
//!
//! [`Session`] owns the per-chiplet `*Requires` accumulators and lends
//! them to the recording layers that do the wiring — the six-`&mut`
//! [`KeccakNodeRequires::require`] call, the eval layer's node entries
//! (which drive their own Poseidon2 absorptions and the
//! [`UintRequire`](crate::uint::UintRequire) relation recording) — and
//! owns the dependency-ordered trace-gen sweep (eval before its
//! Poseidon2 / BPL demand; round before bitwise64 and BPL; the
//! arithmetic ops' store demand before the store; BPL last, since every
//! chiplet feeds it). Callers [`keccak`](Session::keccak) inputs into
//! [`Truthy`] claim handles, fold them into the transcript with
//! [`assert_and`](Session::assert_and) /
//! [`assert_and_fold`](Session::assert_and_fold), and
//! [`finish`](Session::finish) the chosen root into a [`SessionTraces`]
//! bundle.
//!
//! **The public surface is DAG-aware only**: what a runner populating the
//! statement from serialized deferred precompile calls needs — `keccak`,
//! explicit `pin_uint`, the [`UintNode`] value ops (`uint_leaf`, `uint_add` / `uint_sub` /
//! `uint_mul`, the `uint_is` predicate), and the `Truthy`
//! folds. Each value op lays one eval uint-op node over its
//! children's hashes with the relation op recorded underneath; results
//! intern with canonical `(value, modulus)` dedup, so equal values share
//! a ptr — the `uint_is` completeness contract — and nodes intern by
//! `(op, child hashes)` in the eval layer, mirroring keccak interning.
//! Ptrs themselves never surface in the API or any cap.
//!
//! This produces traces only. Assembling the AIRs and provers and calling
//! `prove_multi` (or a bus-balance check) is the caller's job — that's
//! generic lifted-stark usage, not chiplet wiring.

use alloc::{vec, vec::Vec};

pub use miden_core::proof::{DeferredProof, StarkProof};
use miden_core::{Felt, utils::RowMajorMatrix};

pub use crate::transcript::eval::trace::{EcNode, Truthy, UintNode};
use crate::{
    ec::{
        EcStores,
        add::trace::generate_trace as ec_add_trace,
        msm::{
            require,
            trace::{EcExprPtr, EcMsmRequires, generate_trace as msm_trace},
        },
        trace::{EcGroupPtr, generate_traces as ec_store_traces},
    },
    hash::{
        chunk::trace::{ChunkRequires, generate_trace as chunk_trace},
        keccak::{
            digest::KeccakDigest,
            node::trace::{KeccakNodeRequires, generate_trace as keccak_node_trace},
            round::{RoundRequires, generate_trace as round_trace},
            sponge::trace::{SpongeRequires, generate_trace as sponge_trace},
        },
    },
    math::{U256, from_limbs32, to_limbs32},
    primitives::{
        bitwise64::{Bitwise64Requires, generate_trace as bw64_trace},
        byte_pair_lut::{BytePairLutRequires, generate_trace as bpl_trace},
    },
    transcript::{
        eval::trace::{TranscriptEvalRequires, generate_trace as eval_trace},
        nodes::UintOpId,
        poseidon2::{
            P2Digest,
            trace::{Poseidon2Requires, generate_trace as p2_trace},
        },
    },
    uint::{
        UintStores,
        add::trace::generate_trace as uint_add_trace,
        mul::trace::generate_trace as uint_mul_trace,
        trace::{UintPtr, generate_trace as uint_trace},
    },
};

mod fixed;
mod prove;
pub(crate) use fixed::{fixed_ecgroup_msgs, fixed_uintval_msgs};
pub mod statements;
pub mod strategies;
pub use prove::{ChipletAir, ChipletMultiAir, VerifyError, verify_deferred, verify_stark};

/// Number of chiplets in the stack (= the width of [`SessionTraces::mains`]).
pub const NUM_CHIPLETS: usize = 15;

/// Stateful builder over the full chiplet stack.
///
/// Holds the per-chiplet `*Requires` accumulators privately and threads
/// them internally, so a caller only ever sees the DAG-level methods and
/// the final [`finish`](Self::finish).
#[derive(Debug)]
pub struct Session {
    p2: Poseidon2Requires,
    chunk: ChunkRequires,
    round: RoundRequires,
    bw64: Bitwise64Requires,
    bpl: BytePairLutRequires,
    sponge: SpongeRequires,
    node: KeccakNodeRequires,
    eval: TranscriptEvalRequires,
    uint: UintStores,
    ec: EcStores,
    msm: EcMsmRequires,
}

impl Session {
    pub fn new() -> Self {
        let mut session = Self {
            p2: Poseidon2Requires::new(),
            chunk: ChunkRequires::new(),
            round: RoundRequires::new(),
            bw64: Bitwise64Requires::new(),
            bpl: BytePairLutRequires::new(),
            sponge: SpongeRequires::new(),
            node: KeccakNodeRequires::new(),
            eval: TranscriptEvalRequires::new(),
            uint: UintStores::new(),
            ec: EcStores::new(),
            msm: EcMsmRequires::new(),
        };
        session.install_fixed_uints();
        session.ec.store.require_fixed_groups();
        session
    }

    fn install_fixed_uints(&mut self) {
        for (addr, bound_addr, limbs) in fixed::fixed_uints() {
            let value = from_limbs32(&limbs);
            let ptr = if addr == bound_addr {
                self.uint.store.pin_modulus(addr, value)
            } else {
                let bound = self.uint.store.pinned(bound_addr);
                self.uint.store.intern_fixed_pinned(addr, value, bound)
            };
            self.uint.store.require_uintval(ptr);
        }
    }

    /// Record a Keccak-256 of `input`. Returns its digest and a [`Truthy`]
    /// handle to the `Binding(H_keccak, True)` claim — fold the handle into
    /// the transcript via [`assert_and`](Self::assert_and) /
    /// [`assert_and_fold`](Self::assert_and_fold).
    ///
    /// Interning is below this layer: identical input collapses onto one
    /// keccak-node row (its `out_mult` bumped) and lays no fresh sponge /
    /// chunk / Poseidon2 work — but each call still yields its own handle,
    /// so the keccak row's `out_mult` matches its eval consumes.
    pub fn keccak(&mut self, input: &[u8]) -> (KeccakDigest, Truthy) {
        // Seven disjoint fields borrowed in one expression — the borrow
        // checker's field-splitting allows it (these are direct field
        // accesses, not a `&mut self` method that re-borrows the rest).
        let out = self.node.require(
            input,
            &mut self.sponge,
            &mut self.chunk,
            &mut self.round,
            &mut self.bw64,
            &mut self.bpl,
            &mut self.p2,
        );
        let handle = self.eval.issue(out.h_keccak);
        (out.keccak_digest, handle)
    }

    /// Record an explicit uint pin claim at protocol address `ptr ∈ [1, 2^16)` under the modulus
    /// pinned at `bound_ptr`.
    ///
    /// This installs the value in the uint store, hashes `lo[4] || hi[4]` under the manual
    /// pin-claim cap `(UINT_PIN_CLAIM_TAG, bound_ptr, ptr, 0)`, consumes both `UintVal` halves at
    /// `ptr`, and returns the foldable [`Truthy`] for `Binding(h_pin, True)`. Default fixed domains
    /// and curve coefficients are already installed by [`Session::new`] and should not be pinned
    /// manually; ordinary runtime constants should use [`uint_leaf`](Self::uint_leaf) instead. The
    /// modulus itself is a self-referential pin (`bound_ptr == ptr`).
    pub fn pin_uint(&mut self, ptr: u32, value: U256, bound_ptr: u32) -> Truthy {
        let handle = if ptr == bound_ptr {
            self.uint.store.pin_modulus(ptr, value)
        } else {
            let bound = self.uint.store.pinned(bound_ptr);
            self.uint.store.intern_pinned(ptr, value, bound)
        };
        let bound = self.uint.store.pinned(bound_ptr);
        self.eval
            .pin_uint(handle, bound, to_limbs32(value), &mut self.uint.store, &mut self.p2)
    }

    /// Commit a uint value into the DAG as a *transient* uint leaf —
    /// the value entry point for [`uint_add`](Self::uint_add) /
    /// [`uint_mul`](Self::uint_mul) / [`uint_is`](Self::uint_is). The
    /// value is interned with canonical `(value, modulus)` dedup (a value
    /// value equal to a pinned constant lands on the pin's ptr), hashed
    /// under the VM uint value cap `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]`, and bound
    /// as `Binding(h, Uint, ptr, bound_ptr)`. One leaf node per stored
    /// uint: re-leafing a value returns the same shared-use handle.
    ///
    /// Unlike [`pin_uint`](Self::pin_uint), nothing about a *store
    /// address* is committed — the hash carries the value itself; pin
    /// separately if the statement needs `store[ptr] = value` in the
    /// root. The modulus must already be interned (it is itself a pin).
    pub fn uint_leaf(&mut self, value: U256, bound_ptr: u32) -> UintNode {
        let bound = self.uint.store.pinned(bound_ptr);
        let ptr = self.uint.store.intern(value, bound);
        self.eval
            .uint_leaf(ptr, bound, to_limbs32(value), &mut self.uint.store, &mut self.p2)
    }

    /// The DAG node `a + b mod p`: hashes the uint `Add` op cap over the children's hashes,
    /// consumes their `Uint` bindings plus one [`UintAdd`](crate::relations::BusId::UintAdd)
    /// relation tuple carrying the shared bound, and binds the reduced sum. Returns the result's
    /// shared-use handle.
    pub fn uint_add(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.uint_op(UintOpId::Add, a, b)
    }

    /// The DAG node `a − b mod p` — the `UintAdd` arrangement
    /// `b + r = a`, so no transcript-level negation opcode is needed.
    pub fn uint_sub(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.uint_op(UintOpId::Sub, a, b)
    }

    /// The DAG node `a · b mod p`: consumes one
    /// [`UintMul`](crate::relations::BusId::UintMul) relation tuple in
    /// the plain `κₐ = 1, κ_c = 0` arrangement (the dummy `c_ptr` is the
    /// modulus — no zero uint involved).
    pub fn uint_mul(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.uint_op(UintOpId::Mul, a, b)
    }

    /// The `is` predicate: the DAG node asserting `a ≡ b`, consuming both
    /// children's `Uint` bindings on one shared ptr — equality enforced by
    /// the bus, zero constraints — and binding `(h, True)`. This is what
    /// makes uint values transcript-assertable: fold the returned
    /// [`Truthy`] into the root. Panics if the values differ (the claim
    /// would be unprovable); completeness across distinct DAG shapes is
    /// the canonical interning above.
    pub fn uint_is(&mut self, a: &UintNode, b: &UintNode) -> Truthy {
        self.eval.record_is(a, b, &mut self.p2)
    }

    /// Create a curve point `(x, y)` on the fixed short-Weierstrass group
    /// selected by `group_ptr`. The group row is preseeded in the EC store;
    /// its `(a, b, bound)` metadata supplies the curve parameters and
    /// coordinate field, while `group_ptr` is the curve cap selector. Proves
    /// on-curve membership and binds `(h, Group, point_ptr)`.
    /// Returns the shared-use [`EcNode`]. Panics if `(x, y)` is not on the
    /// group or if the coordinate nodes are not stored under the group's base
    /// field bound.
    pub fn ec_create(&mut self, group_ptr: u32, x: &UintNode, y: &UintNode) -> EcNode {
        let group = EcGroupPtr::from_addr(group_ptr);
        let (_, _, bound) = self.ec.store.group_params(group);
        assert_eq!(x.bound_ptr, y.bound_ptr, "coordinates must share a modulus");
        assert_eq!(
            x.bound_ptr, bound,
            "coordinates must be stored under the group's base-field modulus",
        );
        self.eval
            .ec_create(group_ptr, x, y, self.ec.require(self.uint.require()), &mut self.p2)
    }

    /// Declare the **scalar field** of `point`'s group: from here its MSM
    /// scalars (and the shared-base merge `mod`) live under the modulus
    /// pinned at `sbound_ptr` — the curve order `n`, not the base field `p`.
    /// Recording metadata only (no DAG node — name a *pinned* modulus ptr,
    /// e.g. via [`pin_uint`](Self::pin_uint)); call it **before** laying any
    /// MSM whose scalar arithmetic must be sound `mod n` (e.g. binding a GLV
    /// split `u ≡ uₐ + uᵦ·λ (mod n)`, where the split's scalar nodes must be
    /// the very ones the MSM consumes). Idempotent on the same handle.
    pub fn constrain_scalar_bound(&mut self, point: &EcNode, sbound_ptr: u32) {
        let group = self.ec.store.point_params(point.point).0;
        self.ec.store.set_scalar_bound(group, UintPtr::from_addr(sbound_ptr));
    }

    /// Create the selected group's point-at-infinity — binds `(h, Group,
    /// pai_ptr)`, the identity for `ec_add` pass-throughs (∞+Q, P+∞, ∞+∞).
    pub fn ec_pai(&mut self, group_ptr: u32) -> EcNode {
        let group = EcGroupPtr::from_addr(group_ptr);
        let _ = self.ec.store.group_params(group);
        self.eval.ec_pai(group_ptr, self.ec.require(self.uint.require()), &mut self.p2)
    }

    /// The DAG node `R = P + Q`: consumes one
    /// [`EcGroupAdd`](crate::relations::BusId::EcGroupAdd) relation tuple
    /// (the group law, provided at mult 1) and binds `(h, Group, r_ptr)`.
    pub fn ec_add(&mut self, p: &EcNode, q: &EcNode) -> EcNode {
        self.eval.ec_add(p, q, self.ec.require(self.uint.require()), &mut self.p2)
    }

    /// The `is` predicate over points: asserts `P ≡ Q` (point-ptr
    /// equality, enforced on the bus — canonical interning lands equal
    /// points on one ptr across distinct DAG shapes) and binds
    /// `(h, True)`. Fold the returned [`Truthy`] into the root. Panics if
    /// the points differ.
    pub fn ec_is(&mut self, p: &EcNode, q: &EcNode) -> Truthy {
        self.eval.ec_is(p, q, &mut self.p2)
    }

    /// The DAG node `R = P − Q` — one `EcBinOp/Sub` row consuming the
    /// *rearranged* `EcGroupAdd(g, R, Q, P)` (`R + Q = P`) at mult 1,
    /// binding `(h, Group, r_ptr)`. One row, one block — the EC parallel
    /// of uint sub.
    pub fn ec_sub(&mut self, p: &EcNode, q: &EcNode) -> EcNode {
        self.eval.ec_sub(p, q, self.ec.require(self.uint.require()), &mut self.p2)
    }

    /// Promote a stored point to the 1-term MSM expression `⟨P × 1⟩` (value
    /// = P) — the base of any addition chain. Chiplet-internal: the strategy
    /// never touches the DAG, only [`ec_msm`](Self::ec_msm) does. Mechanism
    /// in [`msm::require::intro`](crate::ec::msm::require::intro).
    pub fn msm_intro(&mut self, point: &EcNode) -> EcExprPtr {
        require::intro(&mut self.msm, &mut self.ec, &mut self.uint, point.point)
    }

    /// Combine two MSM expressions: union their term multisets (shared-base
    /// scalars merge `mod` the scalar bound) and add their values; the
    /// operands' use counts are bumped. Mechanism in
    /// [`msm::require::combine`](crate::ec::msm::require::combine).
    pub fn msm_combine(&mut self, a: EcExprPtr, b: EcExprPtr) -> EcExprPtr {
        require::combine(&mut self.msm, &mut self.ec, &mut self.uint, a, b)
    }

    /// Negate an MSM expression: every term's scalar negated (the base
    /// kept), the value negated. Mechanism in
    /// [`msm::require::neg`](crate::ec::msm::require::neg).
    pub fn msm_neg(&mut self, a: EcExprPtr) -> EcExprPtr {
        require::neg(&mut self.msm, &mut self.ec, &mut self.uint, a)
    }

    /// The DAG node `R = Σ sᵢ·Pᵢ` — resolve a symbolic MSM expression into a
    /// curve point on the transcript. Lays the eval `EcMsm` node (the
    /// chaining sponge over the claim's `(Pᵢ, sᵢ)` terms), binding its value
    /// as a `Group` point. A third point-producing EC node beside
    /// [`ec_create`](Self::ec_create) and [`ec_add`](Self::ec_add); compare
    /// it to a claimed point with [`ec_is`](Self::ec_is) (or feed it onward
    /// like any [`EcNode`]) — that consumes it, so the claim enters the root.
    ///
    /// `terms` are the claim's `(base, scalar)` DAG-node pairs, **in absorb
    /// order**. The eval `EcMsm` seam consumes the claim's terms as a
    /// positionless set (`MsmClaimTerm`), so the transcript root is a function
    /// of *this* declared sequence — each term's specific base and scalar
    /// **nodes** (both are absorbed by hash), in this order — and **not** of
    /// the chiplet's internal `idx` storage order (hence not of the
    /// addition-chain strategy). The caller's pairing is validated against the
    /// expression by the bus; each scalar node must be stored under the group's
    /// scalar bound. Bumps the resolve use count.
    ///
    /// Panics unless the claim is **fully merged** — distinct bases, exactly
    /// one pair per term — the canonical form that makes the root well-defined
    /// (an unmerged `P×a, P×b` would hash differently from `P×(a+b)`).
    pub fn ec_msm(&mut self, expr: EcExprPtr, terms: &[(EcNode, UintNode)]) -> EcNode {
        let group = self.msm.group(expr);
        let sbound = self.msm.sbound(expr);
        let val = self.msm.value(expr);
        let chiplet = self.msm.terms(expr);

        // Fully-merged claim: one pair per chiplet term, distinct bases, each
        // pair a real term of `expr`. With distinct bases + matching count +
        // each-pair-a-term, the pairs *are* the chiplet's term set — so the
        // seam's set match is well-defined and the root tracks the term set,
        // not an unmerged split.
        assert_eq!(
            terms.len(),
            chiplet.len(),
            "ec_msm needs exactly one (base, scalar) pair per claim term",
        );
        for i in 0..terms.len() {
            for j in (i + 1)..terms.len() {
                assert_ne!(terms[i].0.point, terms[j].0.point, "duplicate base in ec_msm claim");
            }
            assert!(
                chiplet.iter().any(|&(b, s)| b == terms[i].0.point && s == terms[i].1.ptr),
                "(base, scalar) pair is not a term of this MSM expression",
            );
        }

        let value = self.eval.record_ec_msm(
            expr.addr(),
            group.addr(),
            val,
            sbound.addr(),
            terms,
            &mut self.p2,
        );
        self.msm.consume_claim(expr, 1);
        value
    }

    /// Number of MSM expressions laid so far (intros + combines + negs) — a
    /// chain-cost diagnostic, e.g. to compare addition-chain
    /// [`strategies`]. Not a DAG quantity.
    pub fn msm_expr_count(&self) -> usize {
        self.msm.expr_count()
    }

    /// The coordinates of an MSM expression's value point — for
    /// off-circuit cross-checks (e.g. against a reference MSM) until the
    /// eval resolve seam binds the value in-circuit. Panics if the value is
    /// the point at infinity.
    pub fn msm_value_coords(&self, expr: EcExprPtr) -> (U256, U256) {
        let val = self.msm.value(expr);
        let (_, coords) = self.ec.store.point_params(val);
        let (x, y) = coords.expect("MSM value is the point at infinity");
        (self.uint.store.uint(x).value, self.uint.store.uint(y).value)
    }

    /// Delegate a value op to the eval layer's [`uint_op`]
    /// (TranscriptEvalRequires::uint_op), lending it the uint recording
    /// layer and the Poseidon2 accumulator (disjoint field borrows).
    fn uint_op(&mut self, op: UintOpId, a: &UintNode, b: &UintNode) -> UintNode {
        self.eval.uint_op(op, a, b, self.uint.require(), &mut self.p2)
    }

    /// A `ZERO_HASH` leaf claim — the trivial truthy, and the usual base
    /// for [`assert_and_fold`](Self::assert_and_fold).
    pub fn zero(&mut self) -> Truthy {
        self.eval.zero()
    }

    /// Fold two claims: assert both truthy and bind their AND
    /// `Hash(a || b || cap_transcript)` into the transcript. Consumes `a`
    /// and `b`; returns the combined claim.
    pub fn assert_and(&mut self, a: Truthy, b: Truthy) -> Truthy {
        self.eval.record_and(a, b, &mut self.p2)
    }

    /// Left-fold claims into the transcript from a `ZERO_HASH` base:
    /// `Hash(… Hash(Hash(0, h₀), h₁) …, hₙ)`. `assert_and_fold(keccaks)`
    /// reproduces the left-leaning spine.
    pub fn assert_and_fold(&mut self, handles: impl IntoIterator<Item = Truthy>) -> Truthy {
        let mut acc = self.zero();
        for h in handles {
            acc = self.assert_and(acc, h);
        }
        acc
    }

    /// Generate every chiplet's main trace and bundle them. `root` is the
    /// transcript's top claim (its hash becomes `public_root`); it must be
    /// an asserted node, and every other issued handle must already be
    /// consumed — the eval chip's `generate_trace` panics otherwise.
    ///
    /// The sweep runs in dependency order — eval first (its `out_mult`
    /// checks feed BPL), round before bitwise64 (round drives bw64's
    /// per-row Logic64 / Rol64 demand), the uint store's Range16 before BPL,
    /// BPL last (every chiplet feeds it). `finish` owns that order so callers
    /// can't transpose it; each trace-gen consumes its accumulator, so a
    /// chiplet can't be laid twice.
    pub fn finish(mut self, root: Truthy) -> SessionTraces {
        macro_rules! trace_span {
            ($name:literal, $expr:expr) => {{
                let _span = tracing::info_span!($name).entered();
                $expr
            }};
        }

        let public_root = root.hash();
        self.eval.assert_no_stray_values();
        // EcCreate rows hash the group pointer and bind it through their EcPoint consume.
        let eval = trace_span!("eval", eval_trace(self.eval, root));
        let chunk = trace_span!("chunk", chunk_trace(self.chunk));
        let p2 = trace_span!("poseidon2", p2_trace(self.p2));
        let sponge = trace_span!("keccak_sponge", sponge_trace(self.sponge));
        let node = trace_span!("keccak_node", keccak_node_trace(self.node));
        let round =
            trace_span!("keccak_round", round_trace(self.round, &mut self.bw64, &mut self.bpl));
        let bw64_active_rows = self.bw64.active_rows();
        let bw64 = trace_span!("bitwise64", bw64_trace(self.bw64));
        // The relation traces route their store demand as they lay, so
        // they run before the store reads its provide multiplicities;
        // every Range16 consumer fires before BPL. (The EC add chiplet
        // consumes no UintVal — its predicates are ptr-level certificates
        // already routed by the uint relations.)
        let add = trace_span!("uint_add", uint_add_trace(self.uint.add, &mut self.uint.store));
        let mul = trace_span!(
            "uint_mul",
            uint_mul_trace(self.uint.mul, &mut self.uint.store, &mut self.bpl)
        );
        // EcMsm routes its intros' literal-1 UintVal demand into the store,
        // so it runs before the store reads its provide ledger.
        let msm = trace_span!("ec_msm", msm_trace(self.msm, &mut self.uint.store, &mut self.bpl));
        let uint = trace_span!("uint_store", uint_trace(self.uint.store, &mut self.bpl));
        // The add relation routes its EcGroup / EcPoint demand as it lays,
        // so it runs before the stores read their provide ledgers; it also
        // raises the closure-cert ptr-ordering Range16 requires into BPL
        // (which is traced last, below).
        let ec_add =
            trace_span!("ec_add", ec_add_trace(self.ec.add, &mut self.ec.store, &mut self.bpl));
        let (ec_groups, ec) = trace_span!("ec_store", ec_store_traces(self.ec.store));
        let bpl = trace_span!("byte_pair_lut", bpl_trace(self.bpl));

        SessionTraces {
            chunk,
            p2,
            round,
            bw64,
            bpl,
            sponge,
            node,
            eval,
            uint,
            add,
            mul,
            ec_groups,
            ec,
            ec_add,
            msm,
            public_root,
            bw64_active_rows,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// The fourteen chiplet main traces plus the transcript root, ready to
/// feed `prove_multi` or a bus-balance check.
#[derive(Debug)]
pub struct SessionTraces {
    chunk: RowMajorMatrix<Felt>,
    p2: RowMajorMatrix<Felt>,
    round: RowMajorMatrix<Felt>,
    bw64: RowMajorMatrix<Felt>,
    bpl: RowMajorMatrix<Felt>,
    sponge: RowMajorMatrix<Felt>,
    node: RowMajorMatrix<Felt>,
    eval: RowMajorMatrix<Felt>,
    uint: RowMajorMatrix<Felt>,
    add: RowMajorMatrix<Felt>,
    mul: RowMajorMatrix<Felt>,
    ec_groups: RowMajorMatrix<Felt>,
    ec: RowMajorMatrix<Felt>,
    ec_add: RowMajorMatrix<Felt>,
    msm: RowMajorMatrix<Felt>,
    public_root: P2Digest,
    bw64_active_rows: usize,
}

impl SessionTraces {
    /// The fourteen main traces in canonical chiplet order: chunk,
    /// poseidon2, round, bitwise64, byte_pair_lut, sponge, keccak-node,
    /// eval, uint, uint-add, uint-mul, ec-groups, ec-points, ec-add. The
    /// AIRs, provers, and public values a caller assembles must line up
    /// with this order.
    pub fn mains(&self) -> [&RowMajorMatrix<Felt>; NUM_CHIPLETS] {
        [
            &self.chunk,
            &self.p2,
            &self.round,
            &self.bw64,
            &self.bpl,
            &self.sponge,
            &self.node,
            &self.eval,
            &self.uint,
            &self.add,
            &self.mul,
            &self.ec_groups,
            &self.ec,
            &self.ec_add,
            &self.msm,
        ]
    }

    /// The fifteen main traces by value in [`mains`](Self::mains) order,
    /// consuming the bundle — lets the prover take ownership rather than
    /// clone the (potentially large) traces.
    pub fn into_mains(self) -> Vec<RowMajorMatrix<Felt>> {
        vec![
            self.chunk,
            self.p2,
            self.round,
            self.bw64,
            self.bpl,
            self.sponge,
            self.node,
            self.eval,
            self.uint,
            self.add,
            self.mul,
            self.ec_groups,
            self.ec,
            self.ec_add,
            self.msm,
        ]
    }

    /// The VM's shared public inputs (0.26 `air_inputs`): the 4-felt
    /// transcript root. All AIRs declare it (`num_public_values = 4`); only
    /// the eval chip reads it (pinning its row-0 hash). The old `inv_n` slot
    /// is gone — the natural last-row closing needs no per-AIR height input.
    pub fn air_inputs(&self) -> Vec<Felt> {
        self.public_root.as_array().to_vec()
    }

    /// The transcript root committed by the eval chip.
    pub fn public_root(&self) -> P2Digest {
        self.public_root
    }

    /// Active (pre-power-of-two-pad) bitwise64 row count — a trace-density
    /// diagnostic; the chiplet's other dimensions come from `mains()`.
    pub fn bw64_active_rows(&self) -> usize {
        self.bw64_active_rows
    }
}
