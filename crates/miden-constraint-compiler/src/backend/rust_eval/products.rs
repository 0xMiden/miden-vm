//! Row scheduling for repeated products. Source nodes remain the only AST.
//!
//! A region contains an emitted binary product and its single-use binary-product
//! interiors. Shared values, lifts, prepared/uniform values, scalar operations,
//! squares and structured operations stay atomic. Pair extraction replaces only
//! actual, non-overlapping occurrences, so each new cached multiplication removes
//! at least one multiplication overall. Subset mode may combine earlier fragments.

use std::collections::BTreeMap;

use miden_stark::air::symbolic::ExprView;

use super::{Class, ExpressionIndex, plan};

const MAX_FACTORS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mode {
    subsets: bool,
    minimum_uses: usize,
}

impl Mode {
    pub(super) const DISABLED: Self = Self { subsets: false, minimum_uses: 0 };
    pub(super) const PAIRS: Self = Self { subsets: false, minimum_uses: 2 };
    #[cfg(any(test, feature = "testing"))]
    pub(super) const SUBSETS: Self = Self { subsets: true, minimum_uses: 2 };
    #[cfg(any(test, feature = "testing"))]
    pub(super) const FREQUENT_PAIRS: Self = Self { subsets: false, minimum_uses: 3 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Factor {
    Source(usize),
    Fragment(usize),
}

pub(super) struct Fragment {
    pub(super) factors: [Factor; 2],
    pub(super) class: Class,
    pub(super) slot: Option<usize>,
    uniform: bool,
}

pub(super) struct Products {
    pub(super) fragments: Vec<Fragment>,
    pub(super) replacements: Vec<Option<Vec<Factor>>>,
}

impl Products {
    pub(super) fn empty(len: usize) -> Self {
        Self {
            fragments: Vec::new(),
            replacements: vec![None; len],
        }
    }

    pub(super) fn new(
        graph: &ExpressionIndex<'_>,
        requested: &[bool],
        uniform: &[bool],
        mode: Mode,
        mut next_slot: usize,
    ) -> Self {
        let mut result = Self::empty(graph.len());
        let mut uses = vec![0usize; graph.len()];
        for node in &graph.nodes {
            for &child in &node.children {
                uses[child] += 1;
            }
        }
        for &(root, _) in &graph.roots {
            uses[root] += 1;
        }
        // Scalar/square calls and embeddings retain their existing trait dispatch.
        let eligible = |id: usize| {
            let children = graph.children(id);
            matches!(graph.node(id).view(), ExprView::Mul { .. })
                && requested[id]
                && !uniform[id]
                && children[0] != children[1]
                && children.iter().all(|&child| graph.constant(child).is_none())
                && !(graph.class(id) == Class::Ext
                    && children.iter().all(|&child| graph.value_class(child) == Class::Base))
        };
        let inline =
            |id: usize, class: Class| eligible(id) && uses[id] == 1 && graph.class(id) == class;
        let mut interior = vec![false; graph.len()];
        for id in 0..graph.len() {
            if eligible(id) {
                for &child in graph.children(id) {
                    if inline(child, graph.class(id)) {
                        interior[child] = true;
                    }
                }
            }
        }
        let mut regions = Vec::new();
        for (owner, &is_interior) in interior.iter().enumerate() {
            if !eligible(owner) || is_interior {
                continue;
            }
            let mut factors = Vec::new();
            let mut pending = vec![owner];
            while let Some(id) = pending.pop() {
                if id == owner || inline(id, graph.class(owner)) {
                    pending.extend(graph.children(id).iter().rev().copied());
                } else {
                    factors.push(Factor::Source(id));
                }
                // An iterative bound also handles very deeply nested source products.
                if factors.len() + pending.len() > MAX_FACTORS {
                    break;
                }
            }
            if pending.is_empty() && factors.len() <= MAX_FACTORS {
                regions.push((owner, factors));
            }
        }

        let minimum_uses = mode.minimum_uses.max(2);
        loop {
            let mut candidates = BTreeMap::<[Factor; 2], usize>::new();
            for (_, factors) in &regions {
                let mut counts = BTreeMap::<Factor, usize>::new();
                for &factor in factors {
                    if mode.subsets || matches!(factor, Factor::Source(_)) {
                        *counts.entry(factor).or_default() += 1;
                    }
                }
                let counts: Vec<_> = counts.into_iter().collect();
                for (i, &(a, a_count)) in counts.iter().enumerate() {
                    for &(b, b_count) in &counts[i..] {
                        let occurrences = if a == b { a_count / 2 } else { a_count.min(b_count) };
                        if occurrences > 0 {
                            *candidates.entry([a, b]).or_default() += occurrences;
                        }
                    }
                }
            }
            // Stable source/fragment IDs break ties, independently of HashMap order.
            let selected = candidates
                .into_iter()
                .filter(|(_, count)| *count >= minimum_uses)
                .max_by(|(a_pair, a_count), (b_pair, b_count)| {
                    a_count.cmp(b_count).then_with(|| b_pair.cmp(a_pair))
                });
            let Some((pair, expected_uses)) = selected else {
                break;
            };
            let fragment = result.fragments.len();
            let class = plan::join(
                result.factor_class(graph, pair[0]),
                result.factor_class(graph, pair[1]),
            );
            let uniform = pair.iter().all(|&factor| result.factor_uniform(uniform, factor));
            let mut actual_uses = 0;
            for (_, factors) in &mut regions {
                actual_uses += replace_pair(factors, pair, Factor::Fragment(fragment));
            }
            assert_eq!(actual_uses, expected_uses, "product pair occurrences are disjoint");
            // Each step removes actual_uses region multiplications and introduces one
            // cached multiplication. It strictly reduces both factor count and total work.
            result.fragments.push(Fragment {
                factors: pair,
                class,
                uniform,
                slot: None,
            });
        }
        for (owner, factors) in regions {
            if factors.iter().any(|factor| matches!(factor, Factor::Fragment(_))) {
                result.replacements[owner] = Some(factors);
            }
        }
        // A later subset can subsume an earlier fragment. Only row-visible uniform
        // results need slots; their dependencies stay inside preparation. Every
        // fragment dependency has a smaller ID.
        let mut needed = vec![false; result.fragments.len()];
        let mut pending: Vec<_> = result.replacements.iter().flatten().flatten().copied().collect();
        while let Some(factor) = pending.pop() {
            if let Factor::Fragment(id) = factor
                && !needed[id]
            {
                needed[id] = true;
                if !(result.fragments[id].uniform && result.fragments[id].class == Class::Ext) {
                    pending.extend(result.fragments[id].factors);
                }
            }
        }
        for (id, fragment) in result.fragments.iter_mut().enumerate() {
            if needed[id] && fragment.uniform && fragment.class == Class::Ext {
                fragment.slot = Some(next_slot);
                next_slot += 1;
            }
        }
        result
    }

    fn factor_class(&self, graph: &ExpressionIndex<'_>, factor: Factor) -> Class {
        match factor {
            Factor::Source(id) => graph.value_class(id),
            Factor::Fragment(id) => self.fragments[id].class,
        }
    }

    fn factor_uniform(&self, uniform: &[bool], factor: Factor) -> bool {
        match factor {
            Factor::Source(id) => uniform[id],
            Factor::Fragment(id) => self.fragments[id].uniform,
        }
    }
}

/// Replace exact, disjoint pairs at their first source position. Other factors
/// retain their relative order; assertion order and classes are never changed.
fn replace_pair(factors: &mut Vec<Factor>, pair: [Factor; 2], replacement: Factor) -> usize {
    let mut uses = 0;
    while let Some(first) = factors.iter().position(|&factor| factor == pair[0]) {
        let Some(second) = factors
            .iter()
            .enumerate()
            .find_map(|(i, &factor)| (i != first && factor == pair[1]).then_some(i))
        else {
            break;
        };
        factors[first.min(second)] = replacement;
        factors.remove(first.max(second));
        uses += 1;
    }
    uses
}
