//! Symbolic capture: run an AIR's `eval` against a recording builder and intern the
//! resulting constraint expressions into a [`Graph`].
//!
//! Per crate invariant 1, capture that feeds artifact generation or oracle
//! anchoring must receive an AIR whose `eval` routes to the hand-written
//! constraint definitions.
//!
//! The symbolic expressions form `Arc` trees; the walk memoizes on `Arc` pointer
//! identity (valid because every `Arc` outlives the walk, so no address is reused)
//! and hash-conses structurally into the target [`GraphBuilder`]. Pointer identity
//! is only an accelerator: structural interning defines node identity.

use std::{collections::HashMap, sync::Arc};

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::BasedVectorSpace,
    stark::air::{
        BaseAir, LiftedAir,
        symbolic::{
            AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicAirBuilder,
            SymbolicExpression, SymbolicExpressionExt,
        },
    },
};

use super::{
    analyze::OpCounts,
    graph::{Class, Graph, GraphBuilder, Leaf, NodeId, OpKind},
};

type EF = QuadFelt;

/// The constraints of one captured AIR: per-constraint graph roots in assertion
/// (layout-local) order, their global constraint indices, and walk statistics.
#[derive(Debug)]
pub struct CapturedConstraints {
    /// Base constraint roots, in assertion (layout-local) order.
    pub base_roots: Vec<NodeId>,
    /// Ext constraint roots, in assertion (layout-local) order.
    pub ext_roots: Vec<NodeId>,
    /// Global constraint index of each base root (from the AIR's constraint layout).
    pub base_global_indices: Vec<usize>,
    /// Global constraint index of each ext root (from the AIR's constraint layout).
    pub ext_global_indices: Vec<usize>,
    /// Base ops as executed by the hand-written eval (subtrees shared by `Arc`
    /// counted once); the gap to [`super::op_counts`] on the graph is the sharing
    /// recovered by CSE.
    pub naive_base: OpCounts,
    /// Ext ops as executed by the hand-written eval (see [`Self::naive_base`]).
    pub naive_ext: OpCounts,
}

/// Capture `air`'s constraints into a fresh graph.
///
/// See [`capture_into`] for semantics and panics.
pub fn capture<A>(air: &A) -> (Graph, CapturedConstraints)
where
    A: LiftedAir<Felt, EF>,
{
    let mut builder = GraphBuilder::new();
    let captured = capture_into(air, &mut builder);
    (builder.freeze(), captured)
}

/// Capture `air`'s constraints into an existing [`GraphBuilder`].
///
/// Two evaluators captured into the same builder produce equal per-constraint root
/// ids iff their constraint expressions are structurally identical: hash-consing
/// canonicalizes both sides to their maximally-shared form. This is the primitive
/// behind structural drift tests.
///
/// # Panics
///
/// Panics if the AIR uses features outside the supported surface: preprocessed
/// columns, or main/aux row offsets greater than 1.
pub fn capture_into<A>(air: &A, builder: &mut GraphBuilder) -> CapturedConstraints
where
    A: LiftedAir<Felt, EF>,
{
    let air_layout = AirLayout {
        preprocessed_width: 0,
        main_width: BaseAir::<Felt>::width(air),
        num_public_values: BaseAir::<Felt>::num_public_values(air),
        permutation_width: LiftedAir::<Felt, EF>::aux_width(air),
        num_permutation_challenges: LiftedAir::<Felt, EF>::num_randomness(air),
        num_permutation_values: LiftedAir::<Felt, EF>::num_aux_values(air),
        num_periodic_columns: BaseAir::<Felt>::periodic_columns(air).len(),
    };
    let mut symbolic = SymbolicAirBuilder::<Felt, EF>::new(air_layout);
    air.eval(&mut symbolic);
    let base_constraints = symbolic.base_constraints();
    let ext_constraints = symbolic.extension_constraints();
    let layout = symbolic.constraint_layout();

    let mut w = Walker::new(builder);
    let base_roots = base_constraints.iter().map(|c| w.base_node(c)).collect();
    let ext_roots = ext_constraints.iter().map(|c| w.ext_node(c)).collect();

    CapturedConstraints {
        base_roots,
        ext_roots,
        base_global_indices: layout.base_indices,
        ext_global_indices: layout.ext_indices,
        naive_base: w.naive_base,
        naive_ext: w.naive_ext,
    }
}

/// Walks symbolic expression trees into the graph builder.
struct Walker<'a> {
    builder: &'a mut GraphBuilder,
    base_memo: HashMap<usize, NodeId>,
    ext_memo: HashMap<usize, NodeId>,
    naive_base: OpCounts,
    naive_ext: OpCounts,
}

impl<'a> Walker<'a> {
    fn new(builder: &'a mut GraphBuilder) -> Self {
        Self {
            builder,
            base_memo: HashMap::new(),
            ext_memo: HashMap::new(),
            naive_base: OpCounts::default(),
            naive_ext: OpCounts::default(),
        }
    }

    fn op(&mut self, class: Class, op: OpKind, x: NodeId, y: Option<NodeId>) -> NodeId {
        match class {
            Class::Base => self.naive_base.bump(op),
            Class::Ext => self.naive_ext.bump(op),
        }
        self.builder.op(class, op, x, y).0
    }

    fn base_child(&mut self, c: &Arc<SymbolicExpression<Felt>>) -> NodeId {
        let ptr = Arc::as_ptr(c) as usize;
        if let Some(&id) = self.base_memo.get(&ptr) {
            return id;
        }
        let id = self.base_node(c);
        self.base_memo.insert(ptr, id);
        id
    }

    fn base_node(&mut self, e: &SymbolicExpression<Felt>) -> NodeId {
        match e {
            SymbolicExpression::Leaf(leaf) => {
                let leaf = match leaf {
                    BaseLeaf::Variable(v) => match v.entry {
                        BaseEntry::Main { offset } if offset <= 1 => {
                            Leaf::Main { offset, index: v.index }
                        },
                        BaseEntry::Main { offset } => {
                            panic!("unsupported main row offset {offset}")
                        },
                        BaseEntry::Public => Leaf::Public(v.index),
                        BaseEntry::Periodic => Leaf::Periodic(v.index),
                        BaseEntry::Preprocessed { .. } => {
                            panic!("preprocessed columns not supported")
                        },
                    },
                    BaseLeaf::IsFirstRow => Leaf::IsFirst,
                    BaseLeaf::IsLastRow => Leaf::IsLast,
                    BaseLeaf::IsTransition => Leaf::IsTransition,
                    BaseLeaf::Constant(c) => Leaf::BaseConst(c.as_canonical_u64()),
                };
                self.builder.leaf(leaf)
            },
            SymbolicExpression::Add { x, y, .. } => {
                let (xi, yi) = (self.base_child(x), self.base_child(y));
                self.op(Class::Base, OpKind::Add, xi, Some(yi))
            },
            SymbolicExpression::Sub { x, y, .. } => {
                let (xi, yi) = (self.base_child(x), self.base_child(y));
                self.op(Class::Base, OpKind::Sub, xi, Some(yi))
            },
            SymbolicExpression::Mul { x, y, .. } => {
                let (xi, yi) = (self.base_child(x), self.base_child(y));
                self.op(Class::Base, OpKind::Mul, xi, Some(yi))
            },
            SymbolicExpression::Neg { x, .. } => {
                let xi = self.base_child(x);
                self.op(Class::Base, OpKind::Neg, xi, None)
            },
        }
    }

    fn ext_child(&mut self, c: &Arc<SymbolicExpressionExt<Felt, EF>>) -> NodeId {
        let ptr = Arc::as_ptr(c) as usize;
        if let Some(&id) = self.ext_memo.get(&ptr) {
            return id;
        }
        let id = self.ext_node(c);
        self.ext_memo.insert(ptr, id);
        id
    }

    fn ext_node(&mut self, e: &SymbolicExpressionExt<Felt, EF>) -> NodeId {
        match e {
            SymbolicExpressionExt::Leaf(leaf) => match leaf {
                ExtLeaf::Base(base) => {
                    let bid = self.base_node(base);
                    self.builder.leaf(Leaf::ExtBase(bid))
                },
                ExtLeaf::ExtVariable(v) => {
                    let leaf = match v.entry {
                        ExtEntry::Permutation { offset } if offset <= 1 => {
                            Leaf::Aux { offset, index: v.index }
                        },
                        ExtEntry::Permutation { offset } => {
                            panic!("unsupported aux row offset {offset}")
                        },
                        ExtEntry::Challenge => Leaf::Challenge(v.index),
                        ExtEntry::PermutationValue => Leaf::PermValue(v.index),
                    };
                    self.builder.leaf(leaf)
                },
                ExtLeaf::ExtConstant(c) => {
                    let coeffs: &[Felt] = c.as_basis_coefficients_slice();
                    let key = [coeffs[0].as_canonical_u64(), coeffs[1].as_canonical_u64()];
                    self.builder.leaf(Leaf::ExtConst(key))
                },
            },
            SymbolicExpressionExt::Add { x, y, .. } => {
                let (xi, yi) = (self.ext_child(x), self.ext_child(y));
                self.op(Class::Ext, OpKind::Add, xi, Some(yi))
            },
            SymbolicExpressionExt::Sub { x, y, .. } => {
                let (xi, yi) = (self.ext_child(x), self.ext_child(y));
                self.op(Class::Ext, OpKind::Sub, xi, Some(yi))
            },
            SymbolicExpressionExt::Mul { x, y, .. } => {
                let (xi, yi) = (self.ext_child(x), self.ext_child(y));
                self.op(Class::Ext, OpKind::Mul, xi, Some(yi))
            },
            SymbolicExpressionExt::Neg { x, .. } => {
                let xi = self.ext_child(x);
                self.op(Class::Ext, OpKind::Neg, xi, None)
            },
        }
    }
}
