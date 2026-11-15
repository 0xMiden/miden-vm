//! Gate-count normalization for completed ACE DAGs.

use std::collections::{HashMap, HashSet};

use miden_crypto::field::Field;

use super::{AceDag, DagBuilder, NodeId, NodeKind, ir::DagId};
use crate::{compiler::encode::StreamGeometry, encode::BASE_FELTS_PER_EF};

#[cfg(any(test, feature = "testing"))]
pub use products::{ProductSharing, with_product_sharing};

/// Normalize identities that depend on final node fanout.
///
/// Each rewrite consumes only single-use intermediate nodes. Common-factor extraction replaces
/// two products and their sum or difference with one product and one sum or difference.
/// Associative rotation is applied only when the alternate inner expression already exists, so it
/// removes a node instead of merely changing the tree shape. Signed rotation also handles sums
/// and differences, for example `(a + b) - c` becomes `(a - c) + b` if `a - c` already exists.
pub(crate) fn normalize_dag<EF: Field>(mut dag: AceDag<EF>) -> AceDag<EF> {
    let mut products_attempted = false;
    loop {
        let (normalized, reduced) = normalize_once(dag);
        if reduced {
            dag = normalized;
            continue;
        }
        let (shared, reduced) = share_additive_segments(normalized);
        if reduced {
            dag = shared;
            continue;
        }
        if !products_attempted && products::policy() != products::ProductSharing::Baseline {
            products_attempted = true;
            let (products, reduced) = products::share_product_fragments(shared, products::policy());
            if reduced {
                // Give the established rewrites a chance to simplify the new sharing, without
                // silently turning the one-pass Pairs policy into iterative subset extraction.
                dag = products;
                continue;
            }
            return products;
        }
        return shared;
    }
}

fn normalize_once<EF: Field>(dag: AceDag<EF>) -> (AceDag<EF>, bool) {
    let before = dag.nodes.len();
    let fanout = fanout(&dag);
    let node_by_kind: HashMap<_, _> = dag
        .nodes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, node)| (node, index))
        .collect();
    let mut planned = dag.nodes.clone();
    let mut changed = false;

    for (index, node) in dag.nodes.iter().enumerate() {
        let replacement = match *node {
            NodeKind::Add(a, b) | NodeKind::Sub(a, b) => {
                let subtract = matches!(node, NodeKind::Sub(_, _));
                if let Some((factor, a_other, b_other)) = common_factor(&dag, &fanout, a, b) {
                    let inner = NodeId::in_dag(planned.len(), dag.dag_id());
                    planned.push(if subtract {
                        NodeKind::Sub(a_other, b_other)
                    } else {
                        NodeKind::Add(a_other, b_other)
                    });
                    NodeKind::Mul(factor, inner)
                } else if let Some(rotation) =
                    signed_rotation(&dag, &fanout, &node_by_kind, (a, false), (b, subtract))
                        .or_else(|| {
                            signed_rotation(&dag, &fanout, &node_by_kind, (b, subtract), (a, false))
                        })
                {
                    let lhs = NodeId::in_dag(rotation.lhs, dag.dag_id());
                    let rhs = NodeId::in_dag(rotation.rhs, dag.dag_id());
                    if rotation.subtract {
                        NodeKind::Sub(lhs, rhs)
                    } else {
                        NodeKind::Add(lhs, rhs)
                    }
                } else {
                    node.clone()
                }
            },
            NodeKind::Mul(a, b) => {
                if let Some((existing, remaining)) =
                    existing_rotation(&dag, &fanout, &node_by_kind, a, b)
                        .or_else(|| existing_rotation(&dag, &fanout, &node_by_kind, b, a))
                {
                    NodeKind::Mul(
                        NodeId::in_dag(existing, dag.dag_id()),
                        NodeId::in_dag(remaining, dag.dag_id()),
                    )
                } else {
                    node.clone()
                }
            },
            NodeKind::Input(_) | NodeKind::Constant(_) | NodeKind::Neg(_) => continue,
        };
        if replacement != *node {
            planned[index] = replacement;
            changed = true;
        }
    }
    if !changed {
        return (dag, false);
    }

    let normalized = rebuild(&planned, dag.root());
    if normalized.nodes.len() < before {
        (normalized, true)
    } else {
        // Interacting rewrites can make an otherwise saved node already dead. Discard a
        // size-neutral round so normalization cannot oscillate or change the protocol for no win.
        (dag, false)
    }
}

fn rebuild<EF: Field>(planned: &[NodeKind<EF>], root: NodeId) -> AceDag<EF> {
    // A reused pair can be discovered after its consumer. Rebuild in dependency order rather
    // than source order. Every replacement dependency has strictly smaller fully expanded
    // original expression-tree size than its parent: a rotation removes one positive-size term,
    // factor extraction removes the duplicated factor, and sum fragments contain only proper parts of their owning region. This is a well-founded rank even
    // with shared nodes, so planned rewrites cannot introduce a cycle. The iterative traversal
    // also keeps deep constraint folds off the Rust call stack.
    let mut builder = DagBuilder::new();
    let mut mapped: Vec<Option<NodeId>> = vec![None; planned.len()];
    let mut stack = vec![root.index()];
    while let Some(index) = stack.pop() {
        if mapped[index].is_some() {
            continue;
        }
        let operands = match planned[index] {
            NodeKind::Add(a, b) | NodeKind::Sub(a, b) | NodeKind::Mul(a, b) => {
                [Some(a.index()), Some(b.index())]
            },
            NodeKind::Neg(a) => [Some(a.index()), None],
            NodeKind::Input(_) | NodeKind::Constant(_) => [None, None],
        };
        if operands.into_iter().flatten().any(|operand| mapped[operand].is_none()) {
            stack.push(index);
            for operand in operands.into_iter().flatten().rev() {
                if mapped[operand].is_none() {
                    stack.push(operand);
                }
            }
            continue;
        }
        let mapped_operand = |id: NodeId| mapped[id.index()].expect("operands were rebuilt first");
        let id = match planned[index] {
            NodeKind::Input(key) => builder.input(key),
            NodeKind::Constant(value) => builder.constant(value),
            NodeKind::Add(a, b) => builder.add(mapped_operand(a), mapped_operand(b)),
            NodeKind::Sub(a, b) => builder.sub(mapped_operand(a), mapped_operand(b)),
            NodeKind::Mul(a, b) => builder.mul(mapped_operand(a), mapped_operand(b)),
            NodeKind::Neg(a) => builder.neg(mapped_operand(a)),
        };
        mapped[index] = Some(id);
    }

    let root = mapped[root.index()].expect("the root was rebuilt");
    let mut normalized = builder.build(root);
    normalized.compact();
    normalized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct SignedTerm {
    id: NodeId,
    negative: bool,
}

struct AdditiveRegion {
    root: usize,
    terms: Vec<SignedTerm>,
    changed: bool,
}

/// Share repeated segments in maximal single-use sums without opening shared expressions.
/// Canonical atom ordering makes the experiment independent of binary-tree association. Greedy
/// adjacent-pair compression also finds longer segments after their first pair is materialized.
fn share_additive_segments<EF: Field>(dag: AceDag<EF>) -> (AceDag<EF>, bool) {
    let fanout = fanout(&dag);
    let mut absorbed = vec![false; dag.nodes.len()];
    for node in &dag.nodes {
        if let NodeKind::Add(a, b) | NodeKind::Sub(a, b) = *node {
            for child in [a, b] {
                if fanout[child.index()] == 1
                    && matches!(dag.nodes[child.index()], NodeKind::Add(_, _) | NodeKind::Sub(_, _))
                {
                    absorbed[child.index()] = true;
                }
            }
        }
    }
    let mut regions = Vec::new();
    for (index, node) in dag.nodes.iter().enumerate() {
        if absorbed[index] || !matches!(node, NodeKind::Add(_, _) | NodeKind::Sub(_, _)) {
            continue;
        }
        let mut terms = Vec::new();
        let mut stack = vec![SignedTerm {
            id: NodeId::in_dag(index, dag.dag_id()),
            negative: false,
        }];
        while let Some(term) = stack.pop() {
            if term.id.index() == index || fanout[term.id.index()] == 1 {
                match dag.nodes[term.id.index()] {
                    NodeKind::Add(a, b) => {
                        stack.push(SignedTerm { id: b, negative: term.negative });
                        stack.push(SignedTerm { id: a, negative: term.negative });
                        continue;
                    },
                    NodeKind::Sub(a, b) => {
                        stack.push(SignedTerm { id: b, negative: !term.negative });
                        stack.push(SignedTerm { id: a, negative: term.negative });
                        continue;
                    },
                    _ => {},
                }
            }
            terms.push(term);
        }
        terms.sort_unstable();
        regions.push(AdditiveRegion { root: index, terms, changed: false });
    }

    let mut planned = dag.nodes.clone();
    let mut cache: HashMap<_, _> = planned
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, node)| (node, NodeId::in_dag(index, dag.dag_id())))
        .collect();
    loop {
        let mut counts = HashMap::new();
        for region in &regions {
            let mut last_end = HashMap::new();
            for (index, pair) in region.terms.windows(2).enumerate() {
                let pair = (pair[0], pair[1]);
                if index < *last_end.get(&pair).unwrap_or(&0) {
                    continue;
                }
                *counts.entry(pair).or_insert(0usize) += 1;
                last_end.insert(pair, index + 2);
            }
        }
        let Some((pair, _)) = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .max_by(|(a, a_count), (b, b_count)| a_count.cmp(b_count).then_with(|| b.cmp(a)))
        else {
            break;
        };
        let shared = plan_pair(pair.0, pair.1, &mut planned, &mut cache, dag.dag_id());
        for region in &mut regions {
            let mut read = 0;
            let mut write = 0;
            while read < region.terms.len() {
                if read + 1 < region.terms.len()
                    && (region.terms[read], region.terms[read + 1]) == pair
                {
                    region.terms[write] = shared;
                    region.changed = true;
                    read += 2;
                } else {
                    region.terms[write] = region.terms[read];
                    read += 1;
                }
                write += 1;
            }
            region.terms.truncate(write);
        }
    }
    if !regions.iter().any(|region| region.changed) {
        return (dag, false);
    }

    for region in regions.iter_mut().filter(|region| region.changed) {
        // Reduce adjacent pairs in place. Negative pairs keep their sign outside the fragment,
        // so an arbitrary signed sum still uses one binary gate per pair.
        while region.terms.len() > 1 {
            let mut read = 0;
            let mut write = 0;
            while read < region.terms.len() {
                let term = if read + 1 < region.terms.len() {
                    let term = plan_pair(
                        region.terms[read],
                        region.terms[read + 1],
                        &mut planned,
                        &mut cache,
                        dag.dag_id(),
                    );
                    read += 2;
                    term
                } else {
                    let term = region.terms[read];
                    read += 1;
                    term
                };
                region.terms[write] = term;
                write += 1;
            }
            region.terms.truncate(write);
        }
        let term = region.terms[0];
        // A region contains a positive atom; pairing preserves at least one positive term.
        assert!(!term.negative);
        planned[region.root] = planned[term.id.index()].clone();
    }

    let normalized = rebuild(&planned, dag.root());
    if normalized.nodes.len() < dag.nodes.len() && stream_cost(&normalized) < stream_cost(&dag) {
        (normalized, true)
    } else {
        (dag, false)
    }
}

fn plan_pair<EF: Field>(
    a: SignedTerm,
    b: SignedTerm,
    planned: &mut Vec<NodeKind<EF>>,
    cache: &mut HashMap<NodeKind<EF>, NodeId>,
    dag_id: DagId,
) -> SignedTerm {
    let (node, negative) = match (a.negative, b.negative) {
        (false, false) | (true, true) => {
            let (lhs, rhs) = canonical_pair(a.id, b.id);
            (NodeKind::Add(lhs, rhs), a.negative)
        },
        (false, true) => (NodeKind::Sub(a.id, b.id), false),
        (true, false) => (NodeKind::Sub(b.id, a.id), false),
    };
    let id = *cache.entry(node.clone()).or_insert_with(|| {
        let id = NodeId::in_dag(planned.len(), dag_id);
        planned.push(node);
        id
    });
    SignedTerm { id, negative }
}

/// Compare final aligned stream size, breaking ties by raw EVAL operations. Negation also
/// contributes the emitter's implicit zero constant when no explicit zero is already present.
fn stream_cost<EF: Field>(dag: &AceDag<EF>) -> (usize, usize) {
    let mut constants = HashSet::new();
    let mut inputs = 0;
    let mut operations = 0;
    for node in &dag.nodes {
        match node {
            NodeKind::Input(_) => inputs += 1,
            NodeKind::Constant(value) => {
                constants.insert(*value);
            },
            NodeKind::Neg(_) => {
                constants.insert(EF::ZERO);
                operations += 1;
            },
            NodeKind::Add(_, _) | NodeKind::Sub(_, _) | NodeKind::Mul(_, _) => operations += 1,
        }
    }
    if operations == 0 && constants.is_empty() {
        return (0, 0);
    }
    let geometry = StreamGeometry::from_counts(inputs, constants.len(), operations);
    (
        geometry.num_const_nodes() * BASE_FELTS_PER_EF + geometry.num_padded_ops(),
        operations,
    )
}

fn fanout<EF>(dag: &AceDag<EF>) -> Vec<usize> {
    let mut fanout = vec![0usize; dag.nodes.len()];
    for node in &dag.nodes {
        match node {
            NodeKind::Add(a, b) | NodeKind::Sub(a, b) | NodeKind::Mul(a, b) => {
                fanout[a.index()] += 1;
                fanout[b.index()] += 1;
            },
            NodeKind::Neg(a) => fanout[a.index()] += 1,
            NodeKind::Input(_) | NodeKind::Constant(_) => {},
        }
    }
    fanout[dag.root().index()] += 1;
    fanout
}

fn common_factor<EF>(
    dag: &AceDag<EF>,
    fanout: &[usize],
    a: NodeId,
    b: NodeId,
) -> Option<(NodeId, NodeId, NodeId)> {
    let NodeKind::Mul(a0, a1) = dag.nodes[a.index()] else {
        return None;
    };
    let NodeKind::Mul(b0, b1) = dag.nodes[b.index()] else {
        return None;
    };
    if fanout[a.index()] != 1 || fanout[b.index()] != 1 {
        return None;
    }

    for (factor, a_other) in [(a0, a1), (a1, a0)] {
        if factor == b0 {
            return Some((factor, a_other, b1));
        }
        if factor == b1 {
            return Some((factor, a_other, b0));
        }
    }
    None
}

fn existing_rotation<EF>(
    dag: &AceDag<EF>,
    fanout: &[usize],
    node_by_kind: &HashMap<NodeKind<EF>, usize>,
    inner: NodeId,
    other: NodeId,
) -> Option<(usize, usize)>
where
    EF: Eq + core::hash::Hash,
{
    if fanout[inner.index()] != 1 {
        return None;
    }
    let NodeKind::Mul(x, y) = dag.nodes[inner.index()] else {
        return None;
    };

    for (candidate_operand, remaining) in [(x, y), (y, x)] {
        let (lhs, rhs) = canonical_pair(candidate_operand, other);
        let candidate = NodeKind::Mul(lhs, rhs);
        if let Some(&candidate_index) = node_by_kind.get(&candidate)
            && candidate_index != inner.index()
        {
            return Some((candidate_index, remaining.index()));
        }
    }
    None
}

struct SignedRotation {
    lhs: usize,
    rhs: usize,
    subtract: bool,
}

/// Reassociate three signed terms only when one pair already exists and the discarded inner
/// operation is unshared. Keep the result to one operation; two negative outer terms would need
/// both an addition and a negation, so they are not candidates.
fn signed_rotation<EF>(
    dag: &AceDag<EF>,
    fanout: &[usize],
    node_by_kind: &HashMap<NodeKind<EF>, usize>,
    inner: (NodeId, bool),
    other: (NodeId, bool),
) -> Option<SignedRotation>
where
    EF: Eq + core::hash::Hash,
{
    let (inner, inner_negative) = inner;
    let (other, other_negative) = other;
    if fanout[inner.index()] != 1 {
        return None;
    }
    let terms = match dag.nodes[inner.index()] {
        NodeKind::Add(x, y) => [(x, inner_negative), (y, inner_negative)],
        NodeKind::Sub(x, y) => [(x, inner_negative), (y, !inner_negative)],
        _ => return None,
    };
    for index in [0, 1] {
        let (operand, operand_negative) = terms[index];
        let (remaining, remaining_negative) = terms[1 - index];
        let (candidate, candidate_negative) = match (operand_negative, other_negative) {
            (false, false) | (true, true) => {
                let (lhs, rhs) = canonical_pair(operand, other);
                (NodeKind::Add(lhs, rhs), operand_negative)
            },
            (false, true) => (NodeKind::Sub(operand, other), false),
            (true, false) => (NodeKind::Sub(other, operand), false),
        };
        if candidate_negative && remaining_negative {
            continue;
        }
        if let Some(&existing) = node_by_kind.get(&candidate)
            && existing != inner.index()
        {
            return Some(match (candidate_negative, remaining_negative) {
                (false, false) => SignedRotation {
                    lhs: existing,
                    rhs: remaining.index(),
                    subtract: false,
                },
                (false, true) => SignedRotation {
                    lhs: existing,
                    rhs: remaining.index(),
                    subtract: true,
                },
                (true, false) => SignedRotation {
                    lhs: remaining.index(),
                    rhs: existing,
                    subtract: true,
                },
                (true, true) => unreachable!(),
            });
        }
    }
    None
}

fn canonical_pair(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    if a <= b { (a, b) } else { (b, a) }
}

// Product regions are an arithmetic planning view; the source AST remains authoritative.
mod products {
    #[cfg(any(test, feature = "testing"))]
    use std::cell::Cell;
    use std::collections::HashMap;

    use miden_crypto::field::Field;

    use super::{AceDag, DagId, NodeId, NodeKind, canonical_pair, fanout, rebuild, stream_cost};

    /// Product-sharing policies for one ACE compiler invocation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ProductSharing {
        /// Compare against normalization without product-fragment extraction.
        Baseline,
        /// Introduce repeated pairs of original factors in one extraction pass.
        Pairs,
        /// Also combine newly introduced pairs into larger repeated subsets.
        Subsets,
    }

    #[cfg(any(test, feature = "testing"))]
    std::thread_local! {
        static POLICY: Cell<Option<ProductSharing>> = const { Cell::new(None) };
    }

    /// Select a generation-time experiment, restoring the previous policy on unwind.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_product_sharing<R>(mode: ProductSharing, compile: impl FnOnce() -> R) -> R {
        struct Restore(Option<ProductSharing>);
        impl Drop for Restore {
            fn drop(&mut self) {
                POLICY.with(|policy| policy.set(self.0));
            }
        }
        let _restore = Restore(POLICY.with(|policy| policy.replace(Some(mode))));
        compile()
    }

    pub(super) fn policy() -> ProductSharing {
        #[cfg(any(test, feature = "testing"))]
        if let Some(policy) = POLICY.with(Cell::get) {
            return policy;
        }
        ProductSharing::Subsets
    }

    struct ProductRegion {
        root: usize,
        factors: Vec<NodeId>,
        changed: bool,
    }

    // Audited selector/gating regions contain at most eight factors. A larger bound also covers
    // lookup products without making an unexpectedly large unshared product quadratic to mine.
    const MAX_FACTORS: usize = 64;

    /// Introduce repeated products without opening a shared computation. Every candidate is a
    /// pair of atomic factors in maximal single-use multiplication regions. Count the number of
    /// disjoint occurrences (including repeated factors), rather than the number of index pairs.
    ///
    /// Factor order is canonical only inside these arithmetic regions. Negation, sums and shared
    /// multiplication nodes are atoms. Replacing factors with their product preserves arbitrary
    /// extension-field inputs; no Boolean/selector or witness assumptions are used.
    pub(super) fn share_product_fragments<EF: Field>(
        dag: AceDag<EF>,
        mode: ProductSharing,
    ) -> (AceDag<EF>, bool) {
        if mode == ProductSharing::Baseline {
            return (dag, false);
        }
        let uses = fanout(&dag);
        let mut absorbed = vec![false; dag.nodes.len()];
        for node in &dag.nodes {
            if let NodeKind::Mul(a, b) = *node {
                for child in [a, b] {
                    if uses[child.index()] == 1
                        && matches!(dag.nodes[child.index()], NodeKind::Mul(_, _))
                    {
                        absorbed[child.index()] = true;
                    }
                }
            }
        }
        let mut regions = Vec::new();
        for (index, node) in dag.nodes.iter().enumerate() {
            if absorbed[index] || !matches!(node, NodeKind::Mul(_, _)) {
                continue;
            }
            let mut factors = Vec::new();
            let mut stack = vec![NodeId::in_dag(index, dag.dag_id())];
            while let Some(id) = stack.pop() {
                if (id.index() == index || uses[id.index()] == 1)
                    && let NodeKind::Mul(a, b) = dag.nodes[id.index()]
                {
                    stack.extend([b, a]);
                } else {
                    factors.push(id);
                    if factors.len() > MAX_FACTORS {
                        break;
                    }
                }
            }
            // Two-factor regions are already exact hash-consed products. They offer no missing
            // proper subset, and counting their root as a reusable occurrence inflates the gain.
            if stack.is_empty() && (3..=MAX_FACTORS).contains(&factors.len()) {
                factors.sort_unstable();
                regions.push(ProductRegion { root: index, factors, changed: false });
            }
        }

        let original_len = dag.nodes.len();
        let mut planned = dag.nodes.clone();
        let mut cache: HashMap<_, _> = planned
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, node)| (node, NodeId::in_dag(index, dag.dag_id())))
            .collect();
        loop {
            let mut counts = HashMap::<(NodeId, NodeId), usize>::new();
            for region in &regions {
                let mut multiplicities = Vec::<(NodeId, usize)>::new();
                for &factor in &region.factors {
                    if mode == ProductSharing::Pairs && factor.index() >= original_len {
                        continue;
                    }
                    if let Some((previous, count)) = multiplicities.last_mut()
                        && *previous == factor
                    {
                        *count += 1;
                    } else {
                        multiplicities.push((factor, 1));
                    }
                }
                for (index, &(a, a_count)) in multiplicities.iter().enumerate() {
                    if a_count >= 2 {
                        *counts.entry((a, a)).or_default() += a_count / 2;
                    }
                    for &(b, b_count) in &multiplicities[index + 1..] {
                        *counts.entry((a, b)).or_default() += a_count.min(b_count);
                    }
                }
            }
            let Some((pair, _)) = counts
                .into_iter()
                .filter(|(_, count)| *count > 1)
                .max_by(|(a, a_count), (b, b_count)| a_count.cmp(b_count).then_with(|| b.cmp(a)))
            else {
                break;
            };
            let shared = plan_product(pair.0, pair.1, &mut planned, &mut cache, dag.dag_id());
            for region in &mut regions {
                let a_count = region.factors.iter().filter(|&&id| id == pair.0).count();
                let b_count = region.factors.iter().filter(|&&id| id == pair.1).count();
                let occurrences = if pair.0 == pair.1 {
                    a_count / 2
                } else {
                    a_count.min(b_count)
                };
                if occurrences == 0 {
                    continue;
                }
                let mut a_remaining = occurrences;
                let mut b_remaining = occurrences;
                region.factors.retain(|&factor| {
                    if factor == pair.0 && a_remaining > 0 {
                        a_remaining -= 1;
                        false
                    } else if factor == pair.1 && b_remaining > 0 {
                        b_remaining -= 1;
                        false
                    } else {
                        true
                    }
                });
                debug_assert_eq!((a_remaining, b_remaining), (0, 0));
                region.factors.extend(core::iter::repeat_n(shared, occurrences));
                region.factors.sort_unstable();
                region.changed = true;
            }
            // Every selected occurrence replaces two factors with one. The sum of factor-list
            // lengths strictly decreases, even when pair compression grows a longer subset.
        }
        if !regions.iter().any(|region| region.changed) {
            return (dag, false);
        }

        for region in regions.iter_mut().filter(|region| region.changed) {
            // Balanced completion keeps a deterministic association without opening any atoms.
            // Existing and introduced products use the same cache, including original roots.
            while region.factors.len() > 1 {
                let mut write = 0;
                for read in (0..region.factors.len()).step_by(2) {
                    let factor = if read + 1 < region.factors.len() {
                        plan_product(
                            region.factors[read],
                            region.factors[read + 1],
                            &mut planned,
                            &mut cache,
                            dag.dag_id(),
                        )
                    } else {
                        region.factors[read]
                    };
                    region.factors[write] = factor;
                    write += 1;
                }
                region.factors.truncate(write);
            }
            planned[region.root] = planned[region.factors[0].index()].clone();
        }
        // Introduced fragments depend only on proper subsets of a region's original factors.
        // They cannot depend on the region being rewritten; rebuild visits these dependencies
        // before their users even if an equivalent product was discovered later in source order.
        let shared = rebuild(&planned, dag.root());
        if shared.nodes.len() < dag.nodes.len() && stream_cost(&shared) < stream_cost(&dag) {
            (shared, true)
        } else {
            (dag, false)
        }
    }

    fn plan_product<EF: Field>(
        a: NodeId,
        b: NodeId,
        planned: &mut Vec<NodeKind<EF>>,
        cache: &mut HashMap<NodeKind<EF>, NodeId>,
        dag_id: DagId,
    ) -> NodeId {
        let (a, b) = canonical_pair(a, b);
        let node = NodeKind::Mul(a, b);
        *cache.entry(node.clone()).or_insert_with(|| {
            let id = NodeId::in_dag(planned.len(), dag_id);
            planned.push(node);
            id
        })
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, field::QuadFelt};

    use super::{
        ProductSharing, normalize_dag, products, share_additive_segments, with_product_sharing,
    };
    use crate::{
        InputCounts, InputKey, InputLayout,
        compiler::{
            dag::DagBuilder,
            testing::{eval_dag, fill_inputs},
        },
    };

    fn product_layout(num_public: usize) -> InputLayout {
        InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public,
            num_randomness: 2,
            num_quotient_chunks: 0,
        })
    }

    fn product_inputs(layout: &InputLayout, seed: u64) -> Vec<QuadFelt> {
        let shift = QuadFelt::new([
            Felt::new_unchecked(seed & 0xffff_ffff),
            Felt::new_unchecked(seed >> 32),
        ]);
        fill_inputs(layout).into_iter().map(|value| value + shift).collect()
    }

    #[test]
    fn product_experiments_restore_the_production_default() {
        assert_eq!(products::policy(), ProductSharing::Subsets);
        with_product_sharing(ProductSharing::Pairs, || {
            assert_eq!(products::policy(), ProductSharing::Pairs);
            with_product_sharing(ProductSharing::Subsets, || {
                assert_eq!(products::policy(), ProductSharing::Subsets);
            });
            assert_eq!(products::policy(), ProductSharing::Pairs);
        });
        let panic = std::panic::catch_unwind(|| {
            with_product_sharing(ProductSharing::Subsets, || panic!("restore product policy"));
        });
        assert!(panic.is_err());
        assert_eq!(products::policy(), ProductSharing::Subsets);
    }

    #[test]
    fn product_fragments_share_eighteen_nested_gates_on_arbitrary_extension_inputs() {
        let layout = product_layout(20);
        let mut streams = Vec::new();
        for mode in [ProductSharing::Pairs, ProductSharing::Subsets, ProductSharing::Pairs] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let transition = builder.input(InputKey::Public(0));
            let boundary = builder.input(InputKey::Public(1));
            let one = builder.constant(QuadFelt::from(Felt::new_unchecked(1)));
            let not_boundary = builder.sub(one, boundary);
            let mut root = builder.constant(QuadFelt::from(Felt::new_unchecked(0)));
            for index in 0..18 {
                let residual = builder.input(InputKey::Public(index + 2));
                let inner = builder.mul(not_boundary, residual);
                let gated = builder.mul(transition, inner);
                // Distinct weights model independent folded assertions without granting any
                // selector assumptions or allowing their residuals to cancel accidentally.
                let weight = builder.constant(QuadFelt::new([
                    Felt::new_unchecked(index as u64 + 2),
                    Felt::new_unchecked(index as u64 + 11),
                ]));
                let weighted = builder.mul(weight, gated);
                root = builder.add(root, weighted);
            }
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();
            let before_cost = super::stream_cost(&dag);
            let (shared, reduced) = products::share_product_fragments(dag, mode);
            assert!(reduced, "{mode:?}");
            assert_eq!(shared.nodes.len(), before - 17, "{mode:?}");
            assert!(super::stream_cost(&shared) < before_cost);
            for seed in [0, 42, u64::MAX] {
                let inputs = product_inputs(&layout, seed);
                let value = |index| inputs[layout.index(InputKey::Public(index)).unwrap()];
                let gate = value(0) * (QuadFelt::from(Felt::new_unchecked(1)) - value(1));
                let expected =
                    (0..18).fold(QuadFelt::from(Felt::new_unchecked(0)), |sum, index| {
                        let weight = QuadFelt::new([
                            Felt::new_unchecked(index as u64 + 2),
                            Felt::new_unchecked(index as u64 + 11),
                        ]);
                        sum + weight * gate * value(index + 2)
                    });
                assert_eq!(eval_dag(&shared, &inputs, &layout).unwrap(), expected, "{mode:?}");
            }
            let circuit = crate::compiler::emit_circuit(&shared, product_layout(20)).unwrap();
            streams.push(circuit.to_ace().unwrap().instructions().to_vec());
        }
        // Rebuilding in separate DAGs assigns different provenance IDs. Packed instructions must
        // nevertheless be deterministic and independent of HashMap iteration order.
        assert_eq!(streams[0], streams[2]);
    }

    #[test]
    fn product_subsets_grow_beyond_a_single_new_pair() {
        let layout = product_layout(5);
        for (mode, removed) in [(ProductSharing::Pairs, 1), (ProductSharing::Subsets, 2)] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let x = builder.input(InputKey::Public(3));
            let y = builder.input(InputKey::Public(4));
            let ax = builder.mul(a, x);
            let axc = builder.mul(ax, c);
            let first = builder.mul(axc, b);
            let ay = builder.mul(a, y);
            let ayc = builder.mul(ay, c);
            let second = builder.mul(ayc, b);
            let root = builder.add(first, second);
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();
            let (shared, reduced) = products::share_product_fragments(dag, mode);
            assert!(reduced);
            assert_eq!(shared.nodes.len(), before - removed, "{mode:?}");
            for seed in [0, 42, u64::MAX] {
                let inputs = product_inputs(&layout, seed);
                let value = |index| inputs[layout.index(InputKey::Public(index)).unwrap()];
                let expected = value(0) * value(1) * value(2) * (value(3) + value(4));
                assert_eq!(eval_dag(&shared, &inputs, &layout).unwrap(), expected, "{mode:?}");
            }
        }
    }

    #[test]
    fn product_fragments_keep_shared_products_atomic_and_reuse_them() {
        let layout = product_layout(6);
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let c = builder.input(InputKey::Public(2));
        let d = builder.input(InputKey::Public(3));
        let x = builder.input(InputKey::Public(4));
        let y = builder.input(InputKey::Public(5));
        let ab = builder.mul(a, b);
        let first = builder.mul(ab, c);
        let second = builder.mul(ab, d);
        let ax = builder.mul(a, x);
        let third = builder.mul(ax, b);
        let ay = builder.mul(a, y);
        let fourth = builder.mul(ay, b);
        let left = builder.add(first, second);
        let right = builder.add(third, fourth);
        let root = builder.add(left, right);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();
        let (shared, reduced) = products::share_product_fragments(dag, ProductSharing::Subsets);
        assert!(reduced);
        assert_eq!(shared.nodes.len(), before - 2);
        let uses = super::fanout(&shared);
        let is_public = |id: super::NodeId, index| matches!(shared.nodes[id.index()], super::NodeKind::Input(InputKey::Public(i)) if i == index);
        assert!(shared.nodes.iter().enumerate().any(|(index, node)| {
            matches!(*node, super::NodeKind::Mul(a, b)
                if ((is_public(a, 0) && is_public(b, 1))
                    || (is_public(a, 1) && is_public(b, 0))) && uses[index] == 4)
        }));
        for seed in [0, 42, u64::MAX] {
            let inputs = product_inputs(&layout, seed);
            let value = |index| inputs[layout.index(InputKey::Public(index)).unwrap()];
            let expected = value(0) * value(1) * (value(2) + value(3) + value(4) + value(5));
            assert_eq!(eval_dag(&shared, &inputs, &layout).unwrap(), expected);
        }
    }

    #[test]
    fn product_fragment_counts_respect_repeated_factor_multiplicity() {
        let layout = product_layout(5);
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let x = builder.input(InputKey::Public(1));
        let y = builder.input(InputKey::Public(2));
        let u = builder.input(InputKey::Public(3));
        let v = builder.input(InputKey::Public(4));
        let ax = builder.mul(a, x);
        let ay = builder.mul(a, y);
        let first = builder.mul(ax, ay);
        let au = builder.mul(a, u);
        let av = builder.mul(a, v);
        let second = builder.mul(au, av);
        let root = builder.add(first, second);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();
        let (shared, reduced) = products::share_product_fragments(dag, ProductSharing::Subsets);
        assert!(reduced);
        assert_eq!(shared.nodes.len(), before - 1);
        for seed in [0, 42, u64::MAX] {
            let inputs = product_inputs(&layout, seed);
            let value = |index| inputs[layout.index(InputKey::Public(index)).unwrap()];
            let expected = value(0) * value(0) * (value(1) * value(2) + value(3) * value(4));
            assert_eq!(eval_dag(&shared, &inputs, &layout).unwrap(), expected);
        }

        // Three copies contain only one disjoint pair, not three reusable index combinations.
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let aa = builder.mul(a, a);
        let root = builder.mul(aa, a);
        let dag = builder.build(root);
        let before = dag.nodes.clone();
        let (unchanged, reduced) = products::share_product_fragments(dag, ProductSharing::Subsets);
        assert!(!reduced);
        assert_eq!(unchanged.nodes, before);
    }

    #[test]
    fn product_fragments_do_not_cross_negation_boundaries() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let x = builder.input(InputKey::Public(2));
        let y = builder.input(InputKey::Public(3));
        let ax = builder.mul(a, x);
        let negative_ax = builder.neg(ax);
        let first = builder.mul(negative_ax, b);
        let ay = builder.mul(a, y);
        let negative_ay = builder.neg(ay);
        let second = builder.mul(negative_ay, b);
        let root = builder.add(first, second);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.clone();
        let (unchanged, reduced) = products::share_product_fragments(dag, ProductSharing::Subsets);
        assert!(!reduced);
        assert_eq!(unchanged.nodes, before);
    }

    #[test]
    fn normalizes_deterministic_dags_against_independent_field_values() {
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 4,
            num_randomness: 2,
            num_quotient_chunks: 0,
        });
        for seed in 0..16u64 {
            let mut random_state = seed + 1;
            let mut next = || {
                random_state = random_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                random_state
            };
            let mut builder = DagBuilder::<QuadFelt>::new();
            let mut inputs = fill_inputs(&layout);
            let mut terms = Vec::new();
            for index in 0..4 {
                // Keep both coordinates canonical and the extension coordinate nonzero.
                let value = QuadFelt::new([
                    Felt::new_unchecked(next() & 0xffff_ffff),
                    Felt::new_unchecked((next() & 0xffff_ffff) + 1),
                ]);
                inputs[layout.index(InputKey::Public(index)).unwrap()] = value;
                terms.push((builder.input(InputKey::Public(index)), value));
            }
            let zero = QuadFelt::from(Felt::new_unchecked(0));
            let one = QuadFelt::from(Felt::new_unchecked(1));
            for value in [zero, one, -one] {
                terms.push((builder.constant(value), value));
            }
            let mut root = builder.constant(zero);
            let mut expected = zero;
            for _ in 0..128 {
                let (lhs, x) = terms[next() as usize % terms.len()];
                let (rhs, y) = terms[next() as usize % terms.len()];
                let (term, value) = match next() % 12 {
                    0..=2 => (builder.add(lhs, rhs), x + y),
                    3..=4 => (builder.sub(lhs, rhs), x - y),
                    5..=6 => (builder.mul(lhs, rhs), x * y),
                    7 => (builder.neg(lhs), -x),
                    8 => {
                        let sum = builder.add(lhs, rhs);
                        (builder.sub(sum, lhs), y)
                    },
                    9 => {
                        let (third, _) = terms[next() as usize % terms.len()];
                        let first = builder.add(lhs, third);
                        let second = builder.add(rhs, third);
                        (builder.sub(first, second), x - y)
                    },
                    10 => {
                        let difference = builder.sub(lhs, rhs);
                        (builder.neg(difference), y - x)
                    },
                    11 => {
                        let neg_lhs = builder.neg(lhs);
                        let neg_rhs = builder.neg(rhs);
                        (builder.sub(neg_lhs, neg_rhs), y - x)
                    },
                    _ => unreachable!(),
                };
                terms.push((term, value));
                // Give every authored result an independent nonzero weight to reduce accidental
                // cancellation between errors in the final oracle.
                let weight = QuadFelt::new([
                    Felt::new_unchecked((next() & 0xffff_ffff) + 1),
                    Felt::new_unchecked((next() & 0xffff_ffff) + 1),
                ]);
                let weight_id = builder.constant(weight);
                let weighted_term = builder.mul(term, weight_id);
                root = builder.add(root, weighted_term);
                expected += value * weight;
            }
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();
            assert_eq!(eval_dag(&dag, &inputs, &layout).unwrap(), expected, "builder seed {seed}");

            let normalized = normalize_dag(dag);

            assert!(normalized.nodes.len() <= before, "seed {seed}");
            assert_eq!(
                eval_dag(&normalized, &inputs, &layout).unwrap(),
                expected,
                "normalized seed {seed}"
            );
        }
    }

    #[test]
    fn reuses_late_signed_and_product_nodes_without_changing_values() {
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 4,
            num_randomness: 2,
            num_quotient_chunks: 0,
        });
        for multiply in [false, true] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let d = builder.input(InputKey::Public(3));
            let root = if multiply {
                let ab = builder.mul(a, b);
                let cd = builder.mul(c, d);
                let balanced = builder.mul(ab, cd);
                let prefix = builder.mul(ab, c);
                let keep_balanced = builder.mul(balanced, b);
                builder.add(keep_balanced, prefix)
            } else {
                let inner = builder.sub(b, c);
                let target = builder.sub(a, inner);
                let existing = builder.sub(a, b);
                builder.mul(target, existing)
            };
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();
            let normalized = normalize_dag(dag);
            assert_eq!(normalized.nodes.len(), before - 1, "multiply={multiply}");

            for shift in [0, 1, 7] {
                let shift = QuadFelt::from(Felt::new_unchecked(shift));
                let inputs: Vec<_> =
                    fill_inputs(&layout).into_iter().map(|value| value + shift).collect();
                let a = inputs[layout.index(InputKey::Public(0)).unwrap()];
                let b = inputs[layout.index(InputKey::Public(1)).unwrap()];
                let c = inputs[layout.index(InputKey::Public(2)).unwrap()];
                let d = inputs[layout.index(InputKey::Public(3)).unwrap()];
                let expected = if multiply {
                    (a * b) * (c * d) * b + (a * b) * c
                } else {
                    (a - (b - c)) * (a - b)
                };
                assert_eq!(
                    eval_dag(&normalized, &inputs, &layout).unwrap(),
                    expected,
                    "multiply={multiply}"
                );
            }
        }
    }

    #[test]
    fn factors_single_use_products() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let factor = builder.input(InputKey::Public(2));
        let af = builder.mul(a, factor);
        let bf = builder.mul(b, factor);
        let root = builder.add(af, bf);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert_eq!(normalized.nodes.len(), before - 1);
    }

    #[test]
    fn preserves_products_with_multiple_consumers() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let factor = builder.input(InputKey::Public(2));
        let c = builder.input(InputKey::Public(3));
        let d = builder.input(InputKey::Public(4));
        let independent_factor = builder.input(InputKey::Public(5));
        let af = builder.mul(a, factor);
        let bf = builder.mul(b, factor);
        let sum = builder.add(af, bf);
        let shared = builder.add(sum, af);
        let cf = builder.mul(c, independent_factor);
        let df = builder.mul(d, independent_factor);
        let independent_sum = builder.add(cf, df);
        let root = builder.add(shared, independent_sum);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert!(normalized.nodes.len() < before, "the independent factorization must run");
        let fanout = super::fanout(&normalized);
        assert!(
            normalized
                .nodes
                .iter()
                .enumerate()
                .any(|(index, node)| matches!(node, crate::compiler::NodeKind::Mul(_, _))
                    && fanout[index] == 2),
            "the shared product must keep both consumers"
        );
    }

    #[test]
    fn rotates_signed_chains_toward_existing_nodes() {
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 3,
            num_randomness: 2,
            num_quotient_chunks: 0,
        });
        for case in 0..4 {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let (existing, target) = match case {
                0 => {
                    let existing = builder.sub(a, c);
                    let inner = builder.add(a, b);
                    (existing, builder.sub(inner, c))
                },
                1 => {
                    let existing = builder.add(a, c);
                    let inner = builder.sub(a, b);
                    (existing, builder.add(inner, c))
                },
                2 => {
                    let existing = builder.sub(a, b);
                    let inner = builder.sub(b, c);
                    (existing, builder.sub(a, inner))
                },
                3 => {
                    let existing = builder.add(b, c);
                    let inner = builder.sub(a, b);
                    (existing, builder.sub(inner, c))
                },
                _ => unreachable!(),
            };
            let root = builder.mul(existing, target);
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();
            let normalized = normalize_dag(dag);
            assert_eq!(normalized.nodes.len(), before - 1, "case {case}");

            for shift in [0, 1, 7] {
                let shift = QuadFelt::from(Felt::new_unchecked(shift));
                let inputs: Vec<_> =
                    fill_inputs(&layout).into_iter().map(|value| value + shift).collect();
                let a = inputs[layout.index(InputKey::Public(0)).unwrap()];
                let b = inputs[layout.index(InputKey::Public(1)).unwrap()];
                let c = inputs[layout.index(InputKey::Public(2)).unwrap()];
                let expected = match case {
                    0 => (a - c) * ((a + b) - c),
                    1 => (a + c) * ((a - b) + c),
                    2 => (a - b) * (a - (b - c)),
                    3 => (b + c) * ((a - b) - c),
                    _ => unreachable!(),
                };
                assert_eq!(
                    eval_dag(&normalized, &inputs, &layout).unwrap(),
                    expected,
                    "case {case}"
                );
            }
        }
    }

    #[test]
    fn shares_repeated_signed_segments_without_changing_values() {
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 5,
            num_randomness: 2,
            num_quotient_chunks: 0,
        });
        for subtract in [false, true] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let d = builder.input(InputKey::Public(3));
            let e = builder.input(InputKey::Public(4));
            let ab = if subtract { builder.sub(a, b) } else { builder.add(a, b) };
            let abc = builder.add(ab, c);
            let first = builder.add(abc, d);
            let bc = if subtract { builder.sub(c, b) } else { builder.add(b, c) };
            let bce = builder.add(bc, e);
            let second = builder.add(a, bce);
            let root = builder.mul(first, second);
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();

            let (shared, reduced) = share_additive_segments(dag);

            assert!(reduced);
            assert_eq!(shared.nodes.len(), before - 2);
            for shift in [0, 1, 7] {
                let shift = QuadFelt::from(Felt::new_unchecked(shift));
                let inputs: Vec<_> =
                    fill_inputs(&layout).into_iter().map(|value| value + shift).collect();
                let a = inputs[layout.index(InputKey::Public(0)).unwrap()];
                let b = inputs[layout.index(InputKey::Public(1)).unwrap()];
                let c = inputs[layout.index(InputKey::Public(2)).unwrap()];
                let d = inputs[layout.index(InputKey::Public(3)).unwrap()];
                let e = inputs[layout.index(InputKey::Public(4)).unwrap()];
                let common = if subtract { a - b + c } else { a + b + c };
                assert_eq!(
                    eval_dag(&shared, &inputs, &layout).unwrap(),
                    (common + d) * (common + e)
                );
            }
        }
    }

    #[test]
    fn does_not_count_overlapping_pairs_as_multiple_uses() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let aa = builder.add(a, a);
        let root = builder.add(aa, a);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.clone();

        let (shared, reduced) = share_additive_segments(dag);

        assert!(!reduced);
        assert_eq!(shared.nodes, before);
    }

    #[test]
    fn segment_sharing_keeps_shared_sums_atomic() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let c = builder.input(InputKey::Public(2));
        let d = builder.input(InputKey::Public(3));
        let shared = builder.add(a, b);
        let first = builder.add(shared, c);
        let second = builder.add(shared, d);
        let root = builder.mul(first, second);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.clone();

        let (normalized, reduced) = share_additive_segments(dag);

        assert!(!reduced);
        assert_eq!(normalized.nodes, before);
    }

    #[test]
    fn reuses_a_prefix_discovered_after_its_consumer() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let c = builder.input(InputKey::Public(2));
        let d = builder.input(InputKey::Public(3));
        let ab = builder.add(a, b);
        let cd = builder.add(c, d);
        let balanced = builder.add(ab, cd);
        let prefix = builder.add(ab, c);
        let root = builder.mul(balanced, prefix);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert_eq!(normalized.nodes.len(), before - 1);
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 4,
            num_randomness: 2,
            num_quotient_chunks: 0,
        });
        for shift in [0, 1, 7] {
            let shift = QuadFelt::from(Felt::new_unchecked(shift));
            let inputs: Vec<_> =
                fill_inputs(&layout).into_iter().map(|value| value + shift).collect();
            let a = inputs[layout.index(InputKey::Public(0)).unwrap()];
            let b = inputs[layout.index(InputKey::Public(1)).unwrap()];
            let c = inputs[layout.index(InputKey::Public(2)).unwrap()];
            let d = inputs[layout.index(InputKey::Public(3)).unwrap()];
            let expected = ((a + b) + (c + d)) * ((a + b) + c);
            assert_eq!(eval_dag(&normalized, &inputs, &layout).unwrap(), expected);
        }
    }

    #[test]
    fn signed_rotation_preserves_an_inner_difference_with_multiple_consumers() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let c = builder.input(InputKey::Public(2));
        let existing = builder.add(a, c);
        let inner = builder.sub(a, b);
        let target = builder.add(inner, c);
        let keep_inner = builder.mul(inner, target);
        let root = builder.mul(existing, keep_inner);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert_eq!(normalized.nodes.len(), before);
    }

    #[test]
    fn rotates_single_use_chains_toward_existing_nodes() {
        for multiply in [false, true] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let existing = if multiply { builder.mul(a, c) } else { builder.add(a, c) };
            let nested = if multiply { builder.mul(a, b) } else { builder.add(a, b) };
            let target = if multiply {
                builder.mul(nested, c)
            } else {
                builder.add(nested, c)
            };
            let root = builder.add(existing, target);
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();

            let normalized = normalize_dag(dag);

            assert_eq!(normalized.nodes.len(), before - 1);
        }
    }
}
