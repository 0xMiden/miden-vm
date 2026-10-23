//! Shared structural and polynomial evaluator-drift oracles.

use std::collections::HashMap;

use miden_constraint_compiler::ir::{Class, Graph, Leaf, Node, OpKind};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::{BasedVectorSpace, PrimeCharacteristicRing};

pub const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

/// Canonical id per node: a second hash-cons pass with `Add`/`Mul` children
/// sorted, so two nodes get equal canonical ids iff their subgraphs are
/// structurally identical modulo commutative operand order.
pub fn canonical_ids(graph: &Graph) -> Vec<usize> {
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
pub fn eval_graph(graph: &Graph, seed: u64) -> Vec<QuadFelt> {
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
