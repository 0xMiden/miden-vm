//! Challenge-degree bounds for auxiliary identities with affine register updates.

#[cfg(test)]
mod tests;

use alloc::{vec, vec::Vec};

use hashbrown::HashSet;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};

use super::{Graph, Leaf, Node, NodeId, OpKind};

type Result<T> = core::result::Result<T, &'static str>;

/// Bound extra polynomial identities by beta degree H*d at trace height H.
///
/// Returns d after checking that every extra register starts at a known constant and has an affine
/// update on every non-final row. The next register's coefficient must be a nonzero constant.
/// Update inputs may include fixed data, beta (challenge 1), and current registers. Other
/// challenges, auxiliary public values, nonlinear register use, and mixing registers with ordinary
/// LogUp cells are rejected.
///
/// Capture the handwritten AIR and its ordinary LogUp adapter into the same graph. The adapter's
/// assertions are excluded from this analysis. Affine guards using only ordinary LogUp cells and
/// fixed data are covered by the adapter's denominator bound.
///
/// The returned d is the largest local beta degree, computed with register cells assigned degree
/// zero. Initial values have beta degree zero, and each update adds at most d, so the register
/// degree on row i is at most i*d. Substituting these cells into an affine identity gives degree
/// at most (H-1)*d + d = H*d, including the last row's wrap to row zero.
pub fn beta_degree_bound(
    graph: &Graph,
    full: &[NodeId],
    lookup: &[NodeId],
    aux_width: usize,
    periodic: &[Vec<Felt>],
) -> Result<usize> {
    let facts = analyze_expressions(graph, periodic)?;
    let (identities, lookup_width) = separate_lookup_constraints(graph, full, lookup, aux_width)?;

    let mut max_local_degree = 0;
    let mut initialized_registers = HashSet::new();
    let mut updated_registers = HashSet::new();
    for identity in identities {
        let inputs = expression_inputs(graph, identity);
        if inputs.iter().any(|input| {
            matches!(input, Leaf::Challenge(index) if *index != 1)
                || matches!(input, Leaf::PermValue(_))
        }) {
            return Err("unsupported adaptive input");
        }
        if facts[identity.index()].aux_degree > 1 {
            return Err("nonlinear auxiliary dependence");
        }
        let aux_cells: Vec<_> = inputs
            .iter()
            .filter_map(|input| match *input {
                Leaf::Aux { offset, index } => Some((offset, index)),
                _ => None,
            })
            .collect();
        if aux_cells.iter().any(|&(offset, column)| offset > 1 || column >= aux_width) {
            return Err("invalid auxiliary cell");
        }

        let local_degree = facts[identity.index()].beta_degree;
        if is_ordinary_lookup_guard(&aux_cells, local_degree, lookup_width)? {
            continue;
        }
        max_local_degree = max_local_degree.max(local_degree);

        if let Some(column) = initialized_register(graph, &facts, identity, &aux_cells) {
            initialized_registers.insert(column);
        }
        if let Some(column) = explicitly_updated_register(graph, &facts, identity, &aux_cells) {
            updated_registers.insert(column);
        }
    }
    if (lookup_width..aux_width).any(|column| !initialized_registers.contains(&column)) {
        return Err("missing fixed initialization");
    }
    if (lookup_width..aux_width).any(|column| !updated_registers.contains(&column)) {
        return Err("missing explicit update");
    }
    Ok(max_local_degree)
}

// Remove each adapter assertion once and identify the contiguous prefix of lookup columns.
fn separate_lookup_constraints(
    graph: &Graph,
    full: &[NodeId],
    lookup: &[NodeId],
    aux_width: usize,
) -> Result<(Vec<NodeId>, usize)> {
    let mut remaining = full.to_vec();
    let mut lookup_columns = HashSet::new();
    for &root in lookup {
        let position = remaining
            .iter()
            .position(|candidate| *candidate == root)
            .ok_or("lookup capture mismatch")?;
        remaining.remove(position);
        for input in expression_inputs(graph, root) {
            if let Leaf::Aux { index, .. } = input {
                lookup_columns.insert(index);
            }
        }
    }
    let lookup_width = lookup_columns.len();
    if lookup_width > aux_width || (0..lookup_width).any(|column| !lookup_columns.contains(&column))
    {
        return Err("noncontiguous LogUp prefix");
    }
    Ok((remaining, lookup_width))
}

// Off denominator zeros, ordinary cells are fixed linear combinations of declared fractions.
// This includes the centered accumulator: the invertible trace height fixes its normalized sum.
// With N denominator factors and maximum message width W, clearing denominators in a nonzero
// affine guard gives alpha degree <= N and beta degree <= N*W. Independent challenges give root
// probability <= N*(W+1)*mu; denominator zeros add N*mu, for maximum point probability mu. Thus
// the guard fits the ordinary N*(W+2)*mu budget. Choosing one failed guard before sampling avoids
// a guard-count multiplier.
fn is_ordinary_lookup_guard(
    aux_cells: &[(usize, usize)],
    beta_degree: usize,
    lookup_width: usize,
) -> Result<bool> {
    if !aux_cells.iter().any(|&(_, column)| column < lookup_width) {
        return Ok(false);
    }
    if aux_cells.iter().any(|&(_, column)| column >= lookup_width) || beta_degree != 0 {
        return Err("identity mixes ordinary LogUp with extra challenge checks");
    }
    Ok(true)
}

// Recognize c*s_0 + b = 0 for known constants b and c != 0 at row zero.
fn initialized_register(
    graph: &Graph,
    facts: &[ExpressionFacts],
    identity: NodeId,
    aux_cells: &[(usize, usize)],
) -> Option<usize> {
    let &[(0, column)] = aux_cells else { return None };
    let equation = without_row_selector(graph, identity, Leaf::IsFirst);
    let _ = facts[equation.index()].first_row_constant?;
    let coefficient = constant_coefficient(
        graph,
        facts,
        equation,
        Leaf::Aux { offset: 0, index: column },
        |fact| fact.first_row_constant,
    )?;
    (coefficient != QuadFelt::ZERO).then_some(column)
}

// Recognize an update that determines one next-row register on every non-final row.
// Only an unconditional equation or a whole-equation transition selector suffices; a periodic
// gate could disable the update on some rows.
fn explicitly_updated_register(
    graph: &Graph,
    facts: &[ExpressionFacts],
    identity: NodeId,
    aux_cells: &[(usize, usize)],
) -> Option<usize> {
    let next_columns: Vec<_> = aux_cells
        .iter()
        .filter_map(|&(offset, column)| (offset == 1).then_some(column))
        .collect();
    let &[column] = next_columns.as_slice() else {
        return None;
    };
    let equation = without_row_selector(graph, identity, Leaf::IsTransition);
    let coefficient = constant_coefficient(
        graph,
        facts,
        equation,
        Leaf::Aux { offset: 1, index: column },
        |fact| fact.constant,
    )?;
    (coefficient != QuadFelt::ZERO).then_some(column)
}

#[derive(Clone, Copy, Debug, Default)]
struct ExpressionFacts {
    // Local degree before substituting register recurrences.
    beta_degree: usize,
    // Capped at two: constant, affine, or nonlinear in auxiliary cells.
    aux_degree: u8,
    constant: Option<QuadFelt>,
    // Value at the first row with all auxiliary variables set to zero.
    first_row_constant: Option<QuadFelt>,
}

fn fold_constants(op: OpKind, a: Option<QuadFelt>, b: Option<QuadFelt>) -> Option<QuadFelt> {
    match op {
        OpKind::Neg => a.map(|a| -a),
        OpKind::Mul if a == Some(QuadFelt::ZERO) || b == Some(QuadFelt::ZERO) => {
            Some(QuadFelt::ZERO)
        },
        OpKind::Add => Some(a? + b?),
        OpKind::Sub => Some(a? - b?),
        OpKind::Mul => Some(a? * b?),
    }
}

fn analyze_expressions(graph: &Graph, periodic: &[Vec<Felt>]) -> Result<Vec<ExpressionFacts>> {
    let mut facts: Vec<ExpressionFacts> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let mut fact = ExpressionFacts::default();
        match node {
            Node::Leaf(Leaf::BaseConst(c)) => fact.constant = Some(QuadFelt::from_u64(c)),
            Node::Leaf(Leaf::ExtConst([a, b])) => {
                fact.constant = Some(QuadFelt::new([Felt::from_u64(a), Felt::from_u64(b)]));
            },
            Node::Leaf(Leaf::ExtBase(id)) => fact = facts[id.index()],
            Node::Leaf(Leaf::Challenge(1)) => fact.beta_degree = 1,
            Node::Leaf(Leaf::Aux { .. }) => {
                fact.aux_degree = 1;
                fact.first_row_constant = Some(QuadFelt::ZERO);
            },
            Node::Leaf(Leaf::Periodic(i)) => {
                fact.first_row_constant = Some(
                    (*periodic.get(i).and_then(|v| v.first()).ok_or("missing periodic value")?)
                        .into(),
                );
            },
            Node::Leaf(
                Leaf::Main { .. }
                | Leaf::Preprocessed { .. }
                | Leaf::Public(_)
                | Leaf::IsFirst
                | Leaf::IsLast
                | Leaf::IsTransition
                | Leaf::Challenge(_)
                | Leaf::PermValue(_),
            ) => {},
            Node::Op { op, x, y, .. } => {
                let left = facts[x.index()];
                let right = y.map_or(ExpressionFacts::default(), |y| facts[y.index()]);
                fact.beta_degree = if op == OpKind::Mul {
                    left.beta_degree.checked_add(right.beta_degree).ok_or("degree overflow")?
                } else {
                    left.beta_degree.max(right.beta_degree)
                };
                fact.aux_degree = if op == OpKind::Mul {
                    (left.aux_degree + right.aux_degree).min(2)
                } else {
                    left.aux_degree.max(right.aux_degree)
                };
                fact.constant = fold_constants(op, left.constant, right.constant);
                fact.first_row_constant =
                    fold_constants(op, left.first_row_constant, right.first_row_constant);
            },
        }
        fact.first_row_constant = fact.first_row_constant.or(fact.constant);
        facts.push(fact);
    }
    Ok(facts)
}

fn expression_inputs(graph: &Graph, root: NodeId) -> HashSet<Leaf> {
    let mut seen = HashSet::new();
    let mut result = HashSet::new();
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        match graph.node(id) {
            Node::Leaf(Leaf::ExtBase(id)) => pending.push(id),
            Node::Leaf(leaf) => {
                result.insert(leaf);
            },
            Node::Op { x, y, .. } => {
                pending.push(x);
                pending.extend(y);
            },
        }
    }
    result
}

// Coefficient of one auxiliary variable. A nonconstant coefficient is unsupported; no division
// by a challenge or a main cell is used to determine a register.
fn constant_coefficient(
    graph: &Graph,
    facts: &[ExpressionFacts],
    root: NodeId,
    variable: Leaf,
    constant_value: fn(&ExpressionFacts) -> Option<QuadFelt>,
) -> Option<QuadFelt> {
    let mut coefficients = Vec::with_capacity(root.index() + 1);
    for (_, node) in graph.iter().take(root.index() + 1) {
        let coefficient = match node {
            Node::Leaf(Leaf::ExtBase(id)) => coefficients[id.index()],
            Node::Leaf(leaf) => Some(if leaf == variable {
                QuadFelt::ONE
            } else {
                QuadFelt::ZERO
            }),
            Node::Op { op: OpKind::Mul, x, y: Some(y), .. } => {
                let left = coefficients[x.index()];
                let right = coefficients[y.index()];
                if left == Some(QuadFelt::ZERO) {
                    fold_constants(OpKind::Mul, right, constant_value(&facts[x.index()]))
                } else if right == Some(QuadFelt::ZERO) {
                    fold_constants(OpKind::Mul, left, constant_value(&facts[y.index()]))
                } else {
                    None
                }
            },
            Node::Op { op, x, y, .. } => {
                fold_constants(op, coefficients[x.index()], y.and_then(|y| coefficients[y.index()]))
            },
        };
        coefficients.push(coefficient);
    }
    coefficients[root.index()]
}

// Row selectors are only guaranteed nonzero on their active rows; they need not equal one.
fn without_row_selector(graph: &Graph, root: NodeId, selector: Leaf) -> NodeId {
    if let Node::Op { op: OpKind::Mul, x, y: Some(y), .. } = graph.node(root) {
        for (mut factor, equation) in [(x, y), (y, x)] {
            while let Node::Leaf(Leaf::ExtBase(inner)) = graph.node(factor) {
                factor = inner;
            }
            if graph.node(factor) == Node::Leaf(selector) {
                return equation;
            }
        }
    }
    root
}
