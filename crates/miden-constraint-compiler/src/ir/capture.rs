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
use miden_crypto::field::BasedVectorSpace;
use miden_stark::air::{
    BaseAir, LiftedAir,
    native::{
        self, AirDescriptor, AirKernel, DescriptorError,
        symbolic::{
            AuxInput, BaseInput, BaseLeaf as NativeBaseLeaf, ExtLeaf as NativeExtLeaf,
            SymbolicExpression as NativeExpression, SymbolicExpressionExt as NativeExpressionExt,
        },
    },
    symbolic::{
        AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicAirBuilder, SymbolicExpression,
        SymbolicExpressionExt, eval_air,
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
/// Panics if the AIR uses main, preprocessed, or aux row offsets greater than 1.
pub fn capture_into<A>(air: &A, builder: &mut GraphBuilder) -> CapturedConstraints
where
    A: LiftedAir<Felt, EF>,
{
    capture_into_with(air, builder, |symbolic| eval_air(air, symbolic))
}

/// Capture a selected part of an AIR into an existing graph using the AIR's input layout.
///
/// `eval` supplies the assertions to capture. For example, evaluating only the ordinary lookup
/// adapter lets an analysis distinguish its assertions from the AIR's other extension constraints.
/// The same handwritten-source requirement and row-offset restrictions as [`capture_into`] apply.
pub fn capture_into_with<A>(
    air: &A,
    builder: &mut GraphBuilder,
    eval: impl FnOnce(&mut SymbolicAirBuilder<Felt, EF>),
) -> CapturedConstraints
where
    A: LiftedAir<Felt, EF>,
{
    let air_layout = AirLayout {
        preprocessed_width: BaseAir::<Felt>::preprocessed_width(air),
        main_width: BaseAir::<Felt>::width(air),
        num_public_values: BaseAir::<Felt>::num_public_values(air),
        permutation_width: LiftedAir::<Felt, EF>::aux_width(air),
        num_permutation_challenges: LiftedAir::<Felt, EF>::num_randomness(air),
        num_permutation_values: LiftedAir::<Felt, EF>::num_aux_values(air),
        num_periodic_columns: BaseAir::<Felt>::periodic_columns(air).len(),
    };
    let mut symbolic = SymbolicAirBuilder::<Felt, EF>::new(air_layout);
    eval(&mut symbolic);
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

/// Capture a native authored source into the common IR and retain its checked descriptor.
///
/// Artifact generation and oracle anchors must use this source route. The explicit symbolic
/// constant extension matches the compiler's quadratic extension field.
pub fn capture_native<A>(
    air: &A,
) -> Result<(Graph, CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: native::LiftedAir<F = Felt>,
{
    let mut builder = GraphBuilder::new();
    let (captured, descriptor) = capture_native_into(air, &mut builder)?;
    Ok((builder.freeze(), captured, descriptor))
}

/// Add native source constraints to an existing graph for structural comparison or composition.
pub fn capture_native_into<A>(
    air: &A,
    builder: &mut GraphBuilder,
) -> Result<(CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: native::LiftedAir<F = Felt>,
{
    let captured = native::capture_with::<A, EF>(air)?;
    Ok(lower_native(captured, builder))
}

/// Capture a selected native declaration using its source's one validated shape snapshot.
///
/// This is the subset-observation route for lookup/security consumers. As with full capture,
/// `eval` must observe authored equations when its output anchors artifacts or expectations.
pub fn capture_native_into_with<A>(
    air: &A,
    builder: &mut GraphBuilder,
    eval: impl FnOnce(
        &native::Frame<'_, native::SymbolicSink<Felt, EF>>,
        native::Inputs<'_, native::SymbolicSink<Felt, EF>>,
        &mut native::SymbolicSink<Felt, EF>,
    ),
) -> Result<(CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: native::LiftedAir<F = Felt>,
{
    let captured = native::capture_from_spec::<Felt, EF>(air.spec(), eval)?;
    Ok(lower_native(captured, builder))
}

/// Observe a prepared native kernel only as the subject of a source/kernel comparison.
///
/// Never use this route as an artifact source or to generate its own oracle. Binding prepares
/// against the exact symbolic inputs allocated from the kernel's descriptor; preparation owns its
/// expressions and is released after row evaluation. A trusted kernel overriding `bind` contrary
/// to its descriptor/input contract may panic at this comparison boundary.
pub fn capture_kernel_native_into<K>(
    kernel: &K,
    builder: &mut GraphBuilder,
) -> Result<(CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    K: AirKernel<F = Felt>,
{
    let captured = native::capture_from_spec::<Felt, EF>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| {
            let session = kernel.bind(inputs).expect("symbolic inputs match the kernel descriptor");
            session.eval(frame, sink);
        },
    )?;
    Ok(lower_native(captured, builder))
}

fn lower_native(
    captured: native::Capture<Felt, EF>,
    builder: &mut GraphBuilder,
) -> (CapturedConstraints, AirDescriptor<Felt>) {
    let native::Capture { descriptor, assertions } = captured;
    let layout = descriptor.analysis().layout();
    let mut walker = Walker::new(builder);
    // Preserve the legacy graph's discovery convention separately from assertion emission order.
    // Repeated and zero roots retain their individual global positions through this layout.
    let base_roots = layout
        .base_indices()
        .iter()
        .map(|&index| {
            let native::Assertion::Base(expression) = &assertions[index] else {
                unreachable!("validated capture class/layout mismatch")
            };
            walker.native_base_node(expression)
        })
        .collect();
    let ext_roots = layout
        .ext_indices()
        .iter()
        .map(|&index| {
            let native::Assertion::Extension(expression) = &assertions[index] else {
                unreachable!("validated capture class/layout mismatch")
            };
            walker.native_ext_node(expression)
        })
        .collect();
    let constraints = CapturedConstraints {
        base_roots,
        ext_roots,
        base_global_indices: layout.base_indices().to_vec(),
        ext_global_indices: layout.ext_indices().to_vec(),
        naive_base: walker.naive_base,
        naive_ext: walker.naive_ext,
    };
    (constraints, descriptor)
}

/// Walks symbolic expression trees into the graph builder.
struct Walker<'a> {
    builder: &'a mut GraphBuilder,
    // A Walker is scoped to one capture and visits either upstream or native ASTs, never both.
    // The same pointer caches can therefore serve both frontends without retaining old nodes.
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
                        BaseEntry::Preprocessed { offset } if offset <= 1 => {
                            Leaf::Preprocessed { offset, index: v.index }
                        },
                        BaseEntry::Preprocessed { offset } => {
                            panic!("unsupported preprocessed row offset {offset}")
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

    fn native_base_child(&mut self, expression: &Arc<NativeExpression<Felt>>) -> NodeId {
        let pointer = Arc::as_ptr(expression) as usize;
        if let Some(&id) = self.base_memo.get(&pointer) {
            return id;
        }
        let id = self.native_base_node(expression);
        self.base_memo.insert(pointer, id);
        id
    }

    fn native_base_node(&mut self, expression: &NativeExpression<Felt>) -> NodeId {
        match expression {
            NativeExpression::Leaf(leaf) => {
                let leaf = match leaf {
                    NativeBaseLeaf::Input(input) => match *input {
                        BaseInput::Main { offset, index } => {
                            Leaf::Main { offset: offset.index(), index }
                        },
                        BaseInput::Preprocessed { offset, index } => {
                            Leaf::Preprocessed { offset: offset.index(), index }
                        },
                        BaseInput::Public(index) => Leaf::Public(index),
                        BaseInput::Periodic(index) => Leaf::Periodic(index),
                    },
                    NativeBaseLeaf::IsFirstRow => Leaf::IsFirst,
                    NativeBaseLeaf::IsLastRow => Leaf::IsLast,
                    NativeBaseLeaf::IsTransition => Leaf::IsTransition,
                    NativeBaseLeaf::Constant(value) => Leaf::BaseConst(value.as_canonical_u64()),
                };
                self.builder.leaf(leaf)
            },
            NativeExpression::Add { x, y, .. } => {
                let (left, right) = (self.native_base_child(x), self.native_base_child(y));
                self.op(Class::Base, OpKind::Add, left, Some(right))
            },
            NativeExpression::Sub { x, y, .. } => {
                let (left, right) = (self.native_base_child(x), self.native_base_child(y));
                self.op(Class::Base, OpKind::Sub, left, Some(right))
            },
            NativeExpression::Mul { x, y, .. } => {
                let (left, right) = (self.native_base_child(x), self.native_base_child(y));
                self.op(Class::Base, OpKind::Mul, left, Some(right))
            },
            NativeExpression::Neg { x, .. } => {
                let inner = self.native_base_child(x);
                self.op(Class::Base, OpKind::Neg, inner, None)
            },
        }
    }

    fn native_ext_child(&mut self, expression: &Arc<NativeExpressionExt<Felt, EF>>) -> NodeId {
        let pointer = Arc::as_ptr(expression) as usize;
        if let Some(&id) = self.ext_memo.get(&pointer) {
            return id;
        }
        let id = self.native_ext_node(expression);
        self.ext_memo.insert(pointer, id);
        id
    }

    fn native_ext_node(&mut self, expression: &NativeExpressionExt<Felt, EF>) -> NodeId {
        match expression {
            NativeExpressionExt::Leaf(leaf) => match leaf {
                NativeExtLeaf::Base(base) => {
                    let id = self.native_base_node(base);
                    self.builder.leaf(Leaf::ExtBase(id))
                },
                NativeExtLeaf::Input(input) => {
                    let leaf = match *input {
                        AuxInput::Trace { offset, index } => {
                            Leaf::Aux { offset: offset.index(), index }
                        },
                        AuxInput::Challenge(index) => Leaf::Challenge(index),
                        AuxInput::Export(index) => Leaf::PermValue(index),
                    };
                    self.builder.leaf(leaf)
                },
                NativeExtLeaf::ExtConstant(value) => {
                    let coefficients: &[Felt] = value.as_basis_coefficients_slice();
                    self.builder.leaf(Leaf::ExtConst([
                        coefficients[0].as_canonical_u64(),
                        coefficients[1].as_canonical_u64(),
                    ]))
                },
            },
            NativeExpressionExt::Add { x, y, .. } => {
                let (left, right) = (self.native_ext_child(x), self.native_ext_child(y));
                self.op(Class::Ext, OpKind::Add, left, Some(right))
            },
            NativeExpressionExt::Sub { x, y, .. } => {
                let (left, right) = (self.native_ext_child(x), self.native_ext_child(y));
                self.op(Class::Ext, OpKind::Sub, left, Some(right))
            },
            NativeExpressionExt::Mul { x, y, .. } => {
                let (left, right) = (self.native_ext_child(x), self.native_ext_child(y));
                self.op(Class::Ext, OpKind::Mul, left, Some(right))
            },
            NativeExpressionExt::Neg { x, .. } => {
                let inner = self.native_ext_child(x);
                self.op(Class::Ext, OpKind::Neg, inner, None)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use miden_core::utils::RowMajorMatrix;
    use miden_crypto::field::{Algebra, PrimeCharacteristicRing};
    use miden_stark::air::{ExtensionBuilder, LiftedAirBuilder, native::LiftedAirBuilder as _};
    use p3_field::Dup;

    use super::*;

    struct Source;

    /// The same authored body is evaluated by the old facade and the native source/kernel.
    fn relation<S: native::LiftedAirBuilder<F = Felt>>(
        frame: &native::Frame<'_, S>,
        inputs: native::Inputs<'_, S>,
        sink: &mut S,
    ) {
        let base = (frame.main.current[0].dup() + frame.main.next[1].dup())
            * (frame.preprocessed.current[0].dup() + frame.periodic[0].dup())
            - frame.preprocessed.next[0].dup()
            - inputs.public(0);
        let extension = frame.aux.next[0].dup() - frame.aux.current[0].dup()
            + inputs.challenge(0) * inputs.challenge(1)
            + inputs.export(0)
            + S::ExtExpr::from(base.dup());
        sink.assert_zero(base.dup());
        sink.assert_zero_ext(extension.dup());
        sink.assert_zero(-frame.last_row() + frame.first_row() * frame.transition());
        sink.when(S::Expr::ZERO).assert_zero(base.dup());
        sink.assert_zero_ext(extension);
        sink.assert_zero(base);
    }

    impl native::LiftedAir for Source {
        type F = Felt;

        fn spec(&self) -> native::AirSpec<'_, Felt> {
            native::AirSpec {
                main_width: 2,
                aux_width: 1,
                num_public_values: 1,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: Some(native::PreprocessedSpec { width: 1, log_height: 2 }),
                periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::TWO]]),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            panic!("compiler capture must not build fixed matrices")
        }

        fn eval<S: native::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &native::Frame<'_, S>,
            inputs: native::Inputs<'_, S>,
            sink: &mut S,
        ) {
            relation(frame, inputs, sink);
        }
    }

    impl BaseAir<Felt> for Source {
        fn width(&self) -> usize {
            2
        }
        fn preprocessed_width(&self) -> usize {
            1
        }
        fn num_public_values(&self) -> usize {
            1
        }
        fn num_periodic_columns(&self) -> usize {
            1
        }

        fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
            native::LiftedAir::spec(self).periodic_columns
        }
    }

    impl LiftedAir<Felt, EF> for Source {
        type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

        fn log_preprocessed_height(&self) -> Option<u8> {
            Some(2)
        }
        fn num_randomness(&self) -> usize {
            2
        }
        fn aux_width(&self) -> usize {
            1
        }
        fn num_aux_values(&self) -> usize {
            1
        }

        fn build_aux_trace(
            &self,
            _main: &RowMajorMatrix<Felt>,
            _public: &[Felt],
            _statement: &[Felt],
            _challenges: &[EF],
        ) -> (RowMajorMatrix<EF>, Vec<EF>) {
            panic!("compiler capture must not construct witnesses")
        }

        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
            native::migration::eval_source(self, builder);
        }
    }

    fn assert_same(left: &CapturedConstraints, right: &CapturedConstraints) {
        assert_eq!(left.base_roots, right.base_roots);
        assert_eq!(left.ext_roots, right.ext_roots);
        assert_eq!(left.base_global_indices, right.base_global_indices);
        assert_eq!(left.ext_global_indices, right.ext_global_indices);
    }

    #[test]
    fn native_and_legacy_source_capture_have_the_same_ordered_graph() {
        let (legacy_graph, legacy) = capture(&Source);
        let (native_graph, captured, descriptor) = capture_native(&Source).unwrap();
        assert_eq!(legacy_graph, native_graph);
        assert_same(&legacy, &captured);
        assert_eq!(captured.base_global_indices, vec![0, 2, 3, 5]);
        assert_eq!(captured.ext_global_indices, vec![1, 4]);
        assert_eq!(captured.base_roots[0], captured.base_roots[3]);
        assert_eq!(captured.ext_roots[0], captured.ext_roots[1]);
        assert_eq!(descriptor.analysis().counts().base, 4);
        assert_eq!(descriptor.analysis().counts().ext, 2);

        let leaves: Vec<_> = native_graph
            .iter()
            .filter_map(|(_, node)| {
                if let super::super::Node::Leaf(leaf) = node {
                    Some(leaf)
                } else {
                    None
                }
            })
            .collect();
        for expected in [
            Leaf::Main { offset: 0, index: 0 },
            Leaf::Main { offset: 1, index: 1 },
            Leaf::Preprocessed { offset: 0, index: 0 },
            Leaf::Preprocessed { offset: 1, index: 0 },
            Leaf::Public(0),
            Leaf::Periodic(0),
            Leaf::IsFirst,
            Leaf::IsLast,
            Leaf::IsTransition,
            Leaf::Aux { offset: 0, index: 0 },
            Leaf::Aux { offset: 1, index: 0 },
            Leaf::Challenge(0),
            Leaf::Challenge(1),
            Leaf::PermValue(0),
            Leaf::BaseConst(0),
        ] {
            assert!(leaves.contains(&expected), "missing input {expected:?}");
        }
    }

    #[test]
    fn shared_graph_kernel_comparison_retains_root_and_global_indices() {
        let kernel = native::DirectKernel::new(Source).unwrap();
        let mut builder = GraphBuilder::new();
        let legacy = capture_into(&Source, &mut builder);
        let (source, source_descriptor) = capture_native_into(&Source, &mut builder).unwrap();
        let (prepared, observed_descriptor) =
            capture_kernel_native_into(&kernel, &mut builder).unwrap();
        assert_same(&legacy, &source);
        assert_same(&source, &prepared);
        assert_eq!(source_descriptor.fingerprint(), observed_descriptor.fingerprint());
        assert_eq!(kernel.descriptor().fingerprint(), observed_descriptor.fingerprint());
    }

    #[test]
    fn selected_capture_maps_quadratic_constants_without_changing_basis_order() {
        let value = EF::new([Felt::from_u32(3), Felt::from_u32(4)]);
        let mut builder = GraphBuilder::new();
        let legacy = capture_into_with(&Source, &mut builder, |sink| {
            sink.assert_zero_ext(SymbolicExpressionExt::<Felt, EF>::from(value));
        });
        let (selected, descriptor) =
            capture_native_into_with(&Source, &mut builder, |_, _, sink| {
                native::LiftedAirBuilder::assert_zero_ext(
                    sink,
                    NativeExpressionExt::<Felt, EF>::from(value),
                );
            })
            .unwrap();
        assert_same(&legacy, &selected);
        assert_eq!(selected.base_roots.len(), 0);
        assert_eq!(selected.ext_global_indices, vec![0]);
        assert_eq!(descriptor.analysis().counts().ext, 1);
        let graph = builder.freeze();
        assert!(
            graph
                .iter()
                .any(|(_, node)| node == super::super::Node::Leaf(Leaf::ExtConst([3, 4])))
        );
    }
}
