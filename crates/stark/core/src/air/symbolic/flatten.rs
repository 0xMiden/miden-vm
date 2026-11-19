// Derived from p3-air 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Modified for Miden native expression inputs; provenance and changes are recorded in README.md.

//! Flattened wire format for [`SymbolicExpr`].
//!
//! An expression tree is an acyclic DAG whose interior nodes share `Arc`
//! children. Serializing the `Arc` pointers directly would expand each shared
//! sub-tree once per parent, so instead the tree is lowered to a topologically
//! ordered `Vec` of [`FlatNode`]s in which children are referenced by index.
//! Shared sub-trees collapse to a single node, giving the compact "list of
//! operations" encoding used by serde. It does not validate cached degrees or source addresses.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::SymbolicExpr;

/// A single node in the flattened expression arena.
///
/// Interior nodes refer to their operands by their position in the node list.
/// Every operand index is strictly smaller than the node's own index, so the
/// list is a valid topological (post-order) ordering with the root last.
#[derive(Debug, Serialize, Deserialize)]
enum FlatNode<A> {
    Leaf(A),
    Add {
        x: usize,
        y: usize,
        degree_multiple: usize,
    },
    Sub {
        x: usize,
        y: usize,
        degree_multiple: usize,
    },
    Neg {
        x: usize,
        degree_multiple: usize,
    },
    Mul {
        x: usize,
        y: usize,
        degree_multiple: usize,
    },
}

/// Lower `node` into `nodes` in post-order, returning its index.
///
/// `seen` maps the address of an already-emitted node to its index so shared
/// `Arc` children are emitted exactly once. The whole tree is borrowed for the
/// duration, so addresses stay live and unique while flattening.
fn flatten_into<'a, A>(
    node: &'a SymbolicExpr<A>,
    nodes: &mut Vec<FlatNode<&'a A>>,
    seen: &mut BTreeMap<*const SymbolicExpr<A>, usize>,
) -> usize {
    let key: *const SymbolicExpr<A> = node;
    if let Some(&idx) = seen.get(&key) {
        return idx;
    }
    let flat = match node {
        SymbolicExpr::Leaf(a) => FlatNode::Leaf(a),
        SymbolicExpr::Add { x, y, degree_multiple } => {
            let x = flatten_into(x, nodes, seen);
            let y = flatten_into(y, nodes, seen);
            FlatNode::Add { x, y, degree_multiple: *degree_multiple }
        },
        SymbolicExpr::Sub { x, y, degree_multiple } => {
            let x = flatten_into(x, nodes, seen);
            let y = flatten_into(y, nodes, seen);
            FlatNode::Sub { x, y, degree_multiple: *degree_multiple }
        },
        SymbolicExpr::Neg { x, degree_multiple } => {
            let x = flatten_into(x, nodes, seen);
            FlatNode::Neg { x, degree_multiple: *degree_multiple }
        },
        SymbolicExpr::Mul { x, y, degree_multiple } => {
            let x = flatten_into(x, nodes, seen);
            let y = flatten_into(y, nodes, seen);
            FlatNode::Mul { x, y, degree_multiple: *degree_multiple }
        },
    };
    let idx = nodes.len();
    nodes.push(flat);
    seen.insert(key, idx);
    idx
}

/// Rebuild a tree from a flattened arena, sharing `Arc`s for repeated indices.
///
/// Returns `None` if the list is empty, an operand index is not strictly
/// smaller than its node's index (a forward or self reference), or the root is
/// somehow still shared after construction.
fn unflatten<A>(nodes: Vec<FlatNode<A>>) -> Option<SymbolicExpr<A>> {
    let mut built: Vec<Arc<SymbolicExpr<A>>> = Vec::with_capacity(nodes.len());
    for (i, flat) in nodes.into_iter().enumerate() {
        let expr = match flat {
            FlatNode::Leaf(a) => SymbolicExpr::Leaf(a),
            FlatNode::Add { x, y, degree_multiple } => {
                if x >= i || y >= i {
                    return None;
                }
                SymbolicExpr::Add {
                    x: built[x].clone(),
                    y: built[y].clone(),
                    degree_multiple,
                }
            },
            FlatNode::Sub { x, y, degree_multiple } => {
                if x >= i || y >= i {
                    return None;
                }
                SymbolicExpr::Sub {
                    x: built[x].clone(),
                    y: built[y].clone(),
                    degree_multiple,
                }
            },
            FlatNode::Neg { x, degree_multiple } => {
                if x >= i {
                    return None;
                }
                SymbolicExpr::Neg { x: built[x].clone(), degree_multiple }
            },
            FlatNode::Mul { x, y, degree_multiple } => {
                if x >= i || y >= i {
                    return None;
                }
                SymbolicExpr::Mul {
                    x: built[x].clone(),
                    y: built[y].clone(),
                    degree_multiple,
                }
            },
        };
        built.push(Arc::new(expr));
    }
    // The root is the last node emitted; no other node references it, so it is
    // uniquely owned and can be unwrapped without cloning.
    Arc::try_unwrap(built.pop()?).ok()
}

impl<A: Serialize> Serialize for SymbolicExpr<A> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut nodes: Vec<FlatNode<&A>> = Vec::new();
        let mut seen: BTreeMap<*const Self, usize> = BTreeMap::new();
        flatten_into(self, &mut nodes, &mut seen);
        nodes.serialize(serializer)
    }
}

impl<'de, A: Deserialize<'de>> Deserialize<'de> for SymbolicExpr<A> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let nodes = Vec::<FlatNode<A>>::deserialize(deserializer)?;
        unflatten(nodes).ok_or_else(|| D::Error::custom("invalid flattened symbolic expression"))
    }
}
