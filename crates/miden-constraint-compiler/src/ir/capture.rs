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

use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{self, AirDescriptor, AirKernel, DescriptorError};

use super::{
    analyze::OpCounts,
    graph::{Graph, GraphBuilder, NodeId},
    program::{CapturedProgram, lower_assertions_into},
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

/// Capture a native authored source into the common IR and retain its checked descriptor.
///
/// Artifact generation and oracle anchors must use this source route. The explicit symbolic
/// constant extension matches the compiler's quadratic extension field.
pub fn capture_native<A>(
    air: &A,
) -> Result<(Graph, CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: air::LiftedAir<F = Felt>,
{
    let (program, descriptor) = capture_program_native_with_descriptor(air)?;
    let (graph, constraints) = program.into_lowered();
    Ok((graph, constraints, descriptor))
}

/// Capture the authored operations and checked source metadata in one execution.
pub fn capture_program_native_with_descriptor<A>(
    air: &A,
) -> Result<(CapturedProgram, AirDescriptor<Felt>), DescriptorError>
where
    A: air::LiftedAir<F = Felt>,
{
    let air::Capture { descriptor, assertions } = air::capture_with::<A, EF>(air)?;
    Ok((CapturedProgram::from_assertions(assertions), descriptor))
}

/// Add native source constraints to an existing graph for structural comparison or composition.
pub fn capture_native_into<A>(
    air: &A,
    builder: &mut GraphBuilder,
) -> Result<(CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: air::LiftedAir<F = Felt>,
{
    let captured = air::capture_with::<A, EF>(air)?;
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
        &air::Frame<'_, air::SymbolicSink<Felt, EF>>,
        air::Inputs<'_, air::SymbolicSink<Felt, EF>>,
        &mut air::SymbolicSink<Felt, EF>,
    ),
) -> Result<(CapturedConstraints, AirDescriptor<Felt>), DescriptorError>
where
    A: air::LiftedAir<F = Felt>,
{
    let captured = air::capture_from_spec::<Felt, EF>(air.spec(), eval)?;
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
    let captured = air::capture_from_spec::<Felt, EF>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| {
            let session = kernel.bind(inputs).expect("symbolic inputs match the kernel descriptor");
            session.eval(frame, sink);
        },
    )?;
    Ok(lower_native(captured, builder))
}

fn lower_native(
    captured: air::Capture<Felt, EF>,
    builder: &mut GraphBuilder,
) -> (CapturedConstraints, AirDescriptor<Felt>) {
    let air::Capture { descriptor, assertions } = captured;
    let constraints = lower_assertions_into(&assertions, builder);
    (constraints, descriptor)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use miden_core::utils::RowMajorMatrix;
    use miden_crypto::field::PrimeCharacteristicRing;
    use miden_stark::air::{
        LiftedAirBuilder as _, symbolic::SymbolicExpressionExt as NativeExpressionExt,
    };
    use p3_field::{Algebra, Dup};

    use super::*;
    use crate::ir::Leaf;

    struct Source;

    /// One authored body supplies source and direct-kernel observations.
    fn relation<S: air::LiftedAirBuilder<F = Felt>>(
        frame: &air::Frame<'_, S>,
        inputs: air::Inputs<'_, S>,
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

    impl air::LiftedAir for Source {
        type F = Felt;

        fn spec(&self) -> air::AirSpec<'_, Felt> {
            air::AirSpec {
                main_width: 2,
                aux_width: 1,
                num_public_values: 1,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: Some(air::PreprocessedSpec { width: 1, log_height: 2 }),
                periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::TWO]]),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            panic!("compiler capture must not build fixed matrices")
        }

        fn eval<S: air::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &air::Frame<'_, S>,
            inputs: air::Inputs<'_, S>,
            sink: &mut S,
        ) {
            relation(frame, inputs, sink);
        }
    }

    fn assert_same(left: &CapturedConstraints, right: &CapturedConstraints) {
        assert_eq!(left.base_roots, right.base_roots);
        assert_eq!(left.ext_roots, right.ext_roots);
        assert_eq!(left.base_global_indices, right.base_global_indices);
        assert_eq!(left.ext_global_indices, right.ext_global_indices);
    }

    #[test]
    fn source_capture_retains_ordered_graph_and_all_input_namespaces() {
        let (native_graph, captured, descriptor) = capture_native(&Source).unwrap();
        let (program, program_descriptor) =
            capture_program_native_with_descriptor(&Source).unwrap();
        assert_same(&captured, program.constraints());
        assert_eq!(descriptor.fingerprint(), program_descriptor.fingerprint());
        for seed in [0, 42, u64::MAX] {
            crate::testing::assert_program_lowering(&program, seed);
        }
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
    fn kernel_capture_prepares_and_evaluates_without_source_forwarding() {
        struct Kernel(AirDescriptor<Felt>);

        impl air::LiftedAir for Kernel {
            type F = Felt;

            fn spec(&self) -> air::AirSpec<'_, Felt> {
                self.0.spec().as_borrowed()
            }

            fn eval<S: air::LiftedAirBuilder<F = Felt>>(
                &self,
                _frame: &air::Frame<'_, S>,
                _inputs: air::Inputs<'_, S>,
                _sink: &mut S,
            ) {
                panic!("kernel comparison must not capture the source forwarding method")
            }
        }

        impl AirKernel for Kernel {
            type F = Felt;
            type Prepared<B: Algebra<Felt>, E: Algebra<B>> = bool;

            fn descriptor(&self) -> &AirDescriptor<Felt> {
                &self.0
            }

            fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
                &self,
                _inputs: air::UniformInputs<'_, B, E>,
            ) -> bool {
                true
            }

            fn eval_row<S: air::LiftedAirBuilder<F = Felt>>(
                &self,
                frame: &air::Frame<'_, S>,
                inputs: air::Inputs<'_, S>,
                prepared: &bool,
                sink: &mut S,
            ) {
                assert!(*prepared, "kernel comparison must retain preparation");
                relation(frame, inputs, sink);
            }
        }

        let kernel = Kernel(air::capture_with::<_, EF>(&Source).unwrap().descriptor);
        let mut builder = GraphBuilder::new();
        let (source, source_descriptor) = capture_native_into(&Source, &mut builder).unwrap();
        let (prepared, observed_descriptor) =
            capture_kernel_native_into(&kernel, &mut builder).unwrap();
        assert_same(&source, &prepared);
        assert_eq!(source_descriptor.fingerprint(), observed_descriptor.fingerprint());
        assert_eq!(kernel.descriptor().fingerprint(), observed_descriptor.fingerprint());
    }

    #[test]
    fn selected_capture_maps_quadratic_constants_without_changing_basis_order() {
        let value = EF::new([Felt::from_u32(3), Felt::from_u32(4)]);
        let mut builder = GraphBuilder::new();
        let (selected, descriptor) =
            capture_native_into_with(&Source, &mut builder, |_, _, sink| {
                air::LiftedAirBuilder::assert_zero_ext(
                    sink,
                    NativeExpressionExt::<Felt, EF>::from(value),
                );
            })
            .unwrap();
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
