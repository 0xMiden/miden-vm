//! Equivalence checks for generated AIR evaluators against independent source definitions.

use std::collections::HashMap;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::{BasedVectorSpace, PrimeCharacteristicRing},
    stark::air::LiftedAir,
};

use crate::ir::{Class, Graph, Leaf, Node, NodeId, OpKind, capture, capture_into};

const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

/// Assert that handwritten and generated dispatch produce different raw constraint captures.
///
/// The emitter flips mixed-class commutative operands so extension expressions drive arithmetic.
/// AIRs containing these flips have distinct roots before commutative canonicalization. For those
/// AIRs, this guards against both dispatch paths selecting the same evaluator, which equivalence
/// checks alone would accept.
///
/// # Panics
///
/// Panics if both captures have identical base and extension roots.
#[track_caller]
pub fn assert_distinct_captures<A, B>(source: &A, generated: &B)
where
    A: LiftedAir<Felt, QuadFelt>,
    B: LiftedAir<Felt, QuadFelt> + core::fmt::Debug,
{
    let mut builder = Graph::builder();
    let handwritten = capture_into(source, &mut builder);
    let generated_capture = capture_into(generated, &mut builder);
    assert!(
        handwritten.base_roots != generated_capture.base_roots
            || handwritten.ext_roots != generated_capture.ext_roots,
        "{generated:?}: handwritten and generated captures are identical; check evaluator dispatch",
    );
}

/// Assert identical ordered constraints, modulo commutative operand order.
///
/// `source` must evaluate independent handwritten definitions. This checks expression structure,
/// base/extension classification and assertion order for all field inputs, including selectors
/// outside the trace domain.
///
/// # Panics
///
/// Panics if either constraint stream or its assertion order differs.
pub fn assert_structurally_equivalent<A, B>(source: &A, generated: &B)
where
    A: LiftedAir<Felt, QuadFelt>,
    B: LiftedAir<Felt, QuadFelt>,
{
    let mut builder = Graph::builder();
    let handwritten = capture_into(source, &mut builder);
    let generated = capture_into(generated, &mut builder);
    let graph = builder.freeze();
    let canon = canonical_ids(&graph);
    let canonical =
        |roots: &[NodeId]| -> Vec<usize> { roots.iter().map(|r| canon[r.index()]).collect() };
    assert_eq!(canonical(&handwritten.base_roots), canonical(&generated.base_roots));
    assert_eq!(canonical(&handwritten.ext_roots), canonical(&generated.ext_roots));
    assert_eq!(handwritten.base_global_indices, generated.base_global_indices);
    assert_eq!(handwritten.ext_global_indices, generated.ext_global_indices);
}

/// Compare constraint values on four deterministic assignments of arbitrary field inputs.
///
/// The two AIRs are captured independently. This complements structural equivalence without
/// relying on shared graph interning or commutative canonicalization; it is a sampled check,
/// not a proof of polynomial identity. `source` must evaluate the handwritten definitions.
///
/// # Panics
///
/// Panics if assertion order or a sampled constraint value differs.
pub fn assert_evaluations_match<A, B>(source: &A, generated: &B)
where
    A: LiftedAir<Felt, QuadFelt>,
    B: LiftedAir<Felt, QuadFelt>,
{
    let (hand_graph, hand) = capture(source);
    let (gen_graph, generated) = capture(generated);
    assert_eq!(hand.base_global_indices, generated.base_global_indices);
    assert_eq!(hand.ext_global_indices, generated.ext_global_indices);

    for seed in SEEDS {
        let hand_values = eval_graph(&hand_graph, seed);
        let gen_values = eval_graph(&gen_graph, seed);
        let pairs = hand
            .base_roots
            .iter()
            .zip(&generated.base_roots)
            .zip(hand.base_global_indices.iter())
            .chain(hand.ext_roots.iter().zip(&generated.ext_roots).zip(&hand.ext_global_indices));
        for ((h, g), global) in pairs {
            assert_eq!(
                hand_values[h.index()],
                gen_values[g.index()],
                "constraint {global} differs (seed {seed:#x})"
            );
        }
    }
}

/// Canonical id per node: a second hash-cons pass with `Add`/`Mul` children
/// sorted, so two nodes get equal canonical ids iff their subgraphs are
/// structurally identical modulo commutative operand order.
fn canonical_ids(graph: &Graph) -> Vec<usize> {
    #[derive(PartialEq, Eq, Hash)]
    enum Key {
        Leaf(Leaf),
        Lift(usize),
        Op(Class, OpKind, usize, Option<usize>),
    }
    let mut interner: HashMap<Key, usize> = HashMap::new();
    let mut canon: Vec<usize> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let key = match node {
            Node::Leaf(Leaf::ExtBase(inner)) => Key::Lift(canon[inner.index()]),
            Node::Leaf(leaf) => Key::Leaf(leaf),
            Node::Op { class, op, x, y } => {
                let a = canon[x.index()];
                let b = y.map(|y| canon[y.index()]);
                match (op, b) {
                    (OpKind::Add | OpKind::Mul, Some(b)) => {
                        Key::Op(class, op, a.min(b), Some(a.max(b)))
                    },
                    _ => Key::Op(class, op, a, b),
                }
            },
        };
        let next = interner.len();
        canon.push(*interner.entry(key).or_insert(next));
    }
    canon
}

/// Evaluate every node of `graph`, assigning each leaf a value derived from its
/// content and `seed` (so identical leaves in different graphs agree), with
/// constants evaluating to themselves. Base values live embedded in `QuadFelt`;
/// the algebra is exact either way.
fn eval_graph(graph: &Graph, seed: u64) -> Vec<QuadFelt> {
    let mut values: Vec<QuadFelt> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let value = match node {
            Node::Leaf(Leaf::ExtBase(inner)) => values[inner.index()],
            Node::Leaf(leaf) => leaf_value(seed, leaf),
            Node::Op { op, x, y, .. } => {
                let xv = values[x.index()];
                match (op, y) {
                    (OpKind::Add, Some(y)) => xv + values[y.index()],
                    (OpKind::Sub, Some(y)) => xv - values[y.index()],
                    (OpKind::Mul, Some(y)) => xv * values[y.index()],
                    (OpKind::Neg, None) => -xv,
                    _ => unreachable!("op arity is enforced by the graph builder"),
                }
            },
        };
        values.push(value);
    }
    values
}

fn leaf_value(seed: u64, leaf: Leaf) -> QuadFelt {
    let base = |tag: u64, a: u64| QuadFelt::from(Felt::from_u64(mix(seed, tag, a, 0)));
    let ext = |tag: u64, a: u64| quad(mix(seed, tag, a, 0), mix(seed, tag, a, 1));
    // One tag per leaf kind; windowed inputs use one per row offset.
    match leaf {
        Leaf::Preprocessed { offset, index } => base(12 + offset as u64, index as u64),
        Leaf::Main { offset, index } => base(1 + offset as u64, index as u64),
        Leaf::Public(i) => base(3, i as u64),
        Leaf::Periodic(i) => base(4, i as u64),
        Leaf::IsFirst => base(5, 0),
        Leaf::IsLast => base(6, 0),
        Leaf::IsTransition => base(7, 0),
        Leaf::BaseConst(c) => QuadFelt::from(Felt::from_u64(c)),
        Leaf::Aux { offset, index } => ext(8 + offset as u64, index as u64),
        Leaf::Challenge(i) => ext(10, i as u64),
        Leaf::PermValue(i) => ext(11, i as u64),
        Leaf::ExtConst([c0, c1]) => quad(c0, c1),
        Leaf::ExtBase(_) => unreachable!("handled in eval_graph"),
    }
}

fn quad(c0: u64, c1: u64) -> QuadFelt {
    let coeffs = [Felt::from_u64(c0), Felt::from_u64(c1)];
    <QuadFelt as BasedVectorSpace<Felt>>::from_basis_coefficients_slice(&coeffs)
        .expect("two coefficients form a QuadFelt")
}

/// splitmix64-style mixer over a packed leaf key.
fn mix(seed: u64, tag: u64, a: u64, b: u64) -> u64 {
    let mut x = seed
        .wrapping_add(tag.wrapping_mul(0x9e3779b97f4a7c15))
        .wrapping_add(a.wrapping_mul(0xbf58476d1ce4e5b9))
        .wrapping_add(b.wrapping_mul(0x94d049bb133111eb));
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}
