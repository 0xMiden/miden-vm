//! Native Rust evaluation emitted directly from authored symbolic expression views.
//!
//! One source index supplies sharing, use counts and preparation boundaries.
//! Structured operations remain intact until their specialized trait call is emitted.

use std::{collections::HashMap, fmt::Write as _};

use crate::ir::{CapturedProgram, Class, Leaf, Node, OpKind, index::ExpressionIndex};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::BasedVectorSpace;
use miden_stark::air::symbolic::{AuxInput, BaseInput, ExprView};

mod plan;
mod products;
use plan::{Coefficient, DotKind, MAX_TERMS, Piece, Plan, Rewrite};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeOptions {
    uniform: bool,
    fragments: bool,
    prepared_fragments_only: bool,
    signed_dots: bool,
    factor_runs: bool,
    fragment_min_uses: usize,
    left_sum_folding: bool,
    products: products::Mode,
    cancel_const_offsets: bool,
    // Scalar, Mixed, Same: synthesized dots only, independent of sum fragments.
    dot_min_terms: [usize; 3],
    dot_max_terms: [usize; 3],
}

impl NativeOptions {
    const fn baseline() -> Self {
        Self {
            uniform: false,
            fragments: false,
            prepared_fragments_only: false,
            signed_dots: false,
            factor_runs: false,
            fragment_min_uses: 0,
            left_sum_folding: false,
            products: products::Mode::DISABLED,
            cancel_const_offsets: false,
            dot_min_terms: [4; 3],
            dot_max_terms: [16; 3],
        }
    }
}

impl NativeOptions {
    const fn uniform_fragments() -> Self {
        Self {
            uniform: true,
            fragments: true,
            ..Self::baseline()
        }
    }
}

impl Default for NativeOptions {
    fn default() -> Self {
        Self {
            cancel_const_offsets: true,
            dot_max_terms: [16, 8, 16],
            products: products::Mode::PAIRS,
            ..Self::uniform_fragments()
        }
    }
}

/// Generation-time comparisons; ordinary emission uses the measured production policy.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Copy, Debug)]
pub enum NativeExperiment {
    Baseline,
    LeftSumFolding,
    Uniform,
    UniformFragments,
    PreparedFragmentsOnly,
    SignedDots,
    UniformFragmentsSignedDots,
    FactorRuns,
    FrequentFragments,
    VeryFrequentFragments,
    /// Compare repeated original factor pairs with uniform preparation and sum fragments.
    ProductPairs,
    /// Iteratively combine cached pairs into larger repeated product subsets.
    ProductSubsets,
    /// Require at least three selected row uses of each original factor pair.
    FrequentProductPairs,
    CancelConstOffsets,
    /// Emit the measured production policy.
    Production,
    DotMin2,
    DotMin3,
    DotCap6,
    DotCap8,
    MixedDotMin2,
    MixedDotMin3,
    MixedDotCap6,
    MixedDotCap8,
}

#[cfg(any(test, feature = "testing"))]
std::thread_local! {
    static NATIVE_OPTIONS: std::cell::Cell<Option<NativeOptions>> = const { std::cell::Cell::new(None) };
}

/// Select one native scheduling policy for a generator invocation; nested scopes restore on unwind.
#[cfg(any(test, feature = "testing"))]
pub fn with_native_experiment<T>(mode: NativeExperiment, emit: impl FnOnce() -> T) -> T {
    let options = match mode {
        NativeExperiment::Production => NativeOptions::default(),
        NativeExperiment::Baseline => NativeOptions::baseline(),
        NativeExperiment::CancelConstOffsets => NativeOptions {
            cancel_const_offsets: true,
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::DotMin2 => NativeOptions {
            dot_min_terms: [2; 3],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::DotMin3 => NativeOptions {
            dot_min_terms: [3; 3],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::DotCap6 => NativeOptions {
            dot_max_terms: [6; 3],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::DotCap8 => NativeOptions {
            dot_max_terms: [8; 3],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::MixedDotMin2 => NativeOptions {
            dot_min_terms: [4, 2, 4],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::MixedDotMin3 => NativeOptions {
            dot_min_terms: [4, 3, 4],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::MixedDotCap6 => NativeOptions {
            dot_max_terms: [16, 6, 16],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::MixedDotCap8 => NativeOptions {
            dot_max_terms: [16, 8, 16],
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::LeftSumFolding => NativeOptions {
            left_sum_folding: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::Uniform => NativeOptions {
            uniform: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::UniformFragments => NativeOptions {
            uniform: true,
            fragments: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::PreparedFragmentsOnly => NativeOptions {
            uniform: true,
            fragments: true,
            prepared_fragments_only: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::FrequentFragments => NativeOptions {
            uniform: true,
            fragments: true,
            fragment_min_uses: 3,
            ..NativeOptions::baseline()
        },
        NativeExperiment::VeryFrequentFragments => NativeOptions {
            uniform: true,
            fragments: true,
            fragment_min_uses: 4,
            ..NativeOptions::baseline()
        },
        NativeExperiment::FactorRuns => NativeOptions {
            factor_runs: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::SignedDots => NativeOptions {
            signed_dots: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::UniformFragmentsSignedDots => NativeOptions {
            uniform: true,
            fragments: true,
            signed_dots: true,
            ..NativeOptions::baseline()
        },
        NativeExperiment::ProductPairs => NativeOptions {
            products: products::Mode::PAIRS,
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::ProductSubsets => NativeOptions {
            products: products::Mode::SUBSETS,
            ..NativeOptions::uniform_fragments()
        },
        NativeExperiment::FrequentProductPairs => NativeOptions {
            products: products::Mode::FREQUENT_PAIRS,
            ..NativeOptions::uniform_fragments()
        },
    };
    struct Restore(Option<NativeOptions>);
    impl Drop for Restore {
        fn drop(&mut self) {
            NATIVE_OPTIONS.with(|current| current.set(self.0));
        }
    }
    let previous = NATIVE_OPTIONS.with(|current| current.replace(Some(options)));
    let _restore = Restore(previous);
    emit()
}

fn native_options() -> NativeOptions {
    #[cfg(any(test, feature = "testing"))]
    {
        NATIVE_OPTIONS.with(std::cell::Cell::get).unwrap_or_default()
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        NativeOptions::default()
    }
}

const MODULE_IMPORTS: &str = r"
use miden_core::Felt;
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air::{LiftedAirBuilder, Frame, Inputs, UniformInputs, ConstraintMeta};
use p3_field::Dup;
";

/// Opens every evaluator function: window handles over the main and aux trace
/// slices. `m1`/`a0`/`a1` may be unused by a given AIR, hence the `let _`.
const FN_PROLOGUE: &str = r"    let m0 = frame.main.current;
    let m1 = frame.main.next;
    let a0 = frame.aux.current;
    let a1 = frame.aux.next;
    let _ = (&m0, &m1, &a0, &a1, &inputs, &terms);";

const PREPROCESSED_PROLOGUE: &str = r"    let p0 = frame.preprocessed.current;
    let p1 = frame.preprocessed.next;
    let _ = &p1;";

/// One emitted expression node and its field class.
#[derive(Clone)]
struct Token {
    class: Class,
    /// The emitted identifier — `h{n}` for a leaf, `b{id}`/`e{id}` for an op.
    code: String,
}

#[derive(Clone, Copy)]
struct ExprTypes {
    base: &'static str,
    ext: &'static str,
}

fn lift_base_to_ext(t: &Token, types: ExprTypes) -> String {
    debug_assert!(matches!(t.class, Class::Base));
    format!("{}::from({}.dup())", types.ext, t.code)
}

/// Render a reusable expression in its own field class.
fn operand(t: &Token) -> String {
    format!("{}.dup()", t.code)
}

/// Binary-operator symbol; `Neg` is emitted as a prefix, never through here.
fn sym(op: OpKind) -> char {
    match op {
        OpKind::Add => '+',
        OpKind::Sub => '-',
        OpKind::Mul => '*',
        OpKind::Neg => unreachable!("Neg is unary"),
    }
}

/// One authored capture paired with its original checked source descriptor.
///
/// Both values must come from the same canonical capture. The emitter checks root layout and
/// input addresses; the source fingerprint does not authenticate arbitrary generated code.
pub struct AirEvaluator<'a> {
    pub name: &'a str,
    pub air_label: &'a str,
    pub program: &'a CapturedProgram,
    pub descriptor: &'a miden_stark::air::AirDescriptor<Felt>,
}

/// Emit deterministic, prepared native evaluators directly from authored expressions.
///
/// Sums retain shared and prepared boundaries while exposing unshared product
/// regions to the scalar optimizer. Products, powers, and linear combinations
/// retain their structured operation boundaries.
///
/// # Panics
/// Panics if source roots, classes, global positions, or addresses disagree with the descriptor,
/// the capture violates its domain/arity invariants, or an extension constant is unavailable
/// through the generic builder bounds.
pub fn emit_native_optimized_module(header: &str, evals: &[AirEvaluator<'_>]) -> String {
    let mut out = String::from(header);
    out.push_str(MODULE_IMPORTS);
    out.push_str("use p3_field::Algebra;\n");
    let indexes: Vec<_> = evals
        .iter()
        .map(|eval| ExpressionIndex::new(eval.program.assertions()))
        .collect();
    let plans: Vec<_> = indexes.iter().map(Preparation::new).collect();
    for ((eval, graph), preparation) in evals.iter().zip(&indexes).zip(&plans) {
        validate_native(eval);
        let capacity = preparation.capacity();
        let terms_name = format!("{}_PREPARED_TERMS", eval.name.to_ascii_uppercase());
        writeln!(out, "\npub const {terms_name}: usize = {capacity};").unwrap();
        let mut precompute = Emitter::new(graph, preparation, true);
        let mut results = Vec::with_capacity(capacity);
        for &id in &preparation.terms {
            results.push(precompute.expr(id, Class::Ext));
        }
        for (fragment, value) in preparation.fragments.iter().enumerate() {
            if value.slot.is_some() {
                results.push(operand(&precompute.fragment(fragment)));
            }
        }
        for (fragment, value) in preparation.products.fragments.iter().enumerate() {
            if value.slot.is_some() {
                results.push(operand(&precompute.product_fragment(fragment)));
            }
        }
        let dependencies = if native_options().uniform {
            "uniform-only"
        } else {
            "challenge-only"
        };
        writeln!(out, "\n/// Prepare {dependencies} results for `{}`.", eval.air_label).unwrap();
        writeln!(out, "pub fn precompute_{}<B: Algebra<Felt>, E: Algebra<B>>(inputs: UniformInputs<'_, B, E>) -> [E; {terms_name}] {{", eval.name).unwrap();
        writeln!(out, "    let challenges = inputs.challenges; let _ = challenges;").unwrap();
        for line in precompute.lines {
            writeln!(out, "{line}").unwrap();
        }
        writeln!(out, "    [{}]\n}}", results.join(", ")).unwrap();

        let mut row = Emitter::new(graph, preparation, false);
        for &(root, class) in &graph.roots {
            let value = row.expr(root, class);
            let method = if class == Class::Base { "emit_base" } else { "emit_ext" };
            row.lines
                .push(format!("    builder.{method}({value}, ConstraintMeta::default());"));
        }
        writeln!(out, "\n/// Generated evaluator for `{}`.\n#[inline(never)]\npub fn eval_{}<AB: LiftedAirBuilder<F = Felt>>(frame: &Frame<'_, AB>, inputs: Inputs<'_, AB>, builder: &mut AB, terms: &[AB::ExtExpr; {terms_name}]) {{", eval.air_label, eval.name).unwrap();
        writeln!(out, "{FN_PROLOGUE}").unwrap();
        if (0..graph.len()).any(|id| {
            matches!(graph.node(id).view(), ExprView::BaseInput(BaseInput::Preprocessed { .. }))
        }) {
            writeln!(out, "{PREPROCESSED_PROLOGUE}").unwrap();
        }
        for line in row.lines {
            writeln!(out, "{line}").unwrap();
        }
        writeln!(out, "}}").unwrap();
    }
    out
}

fn validate_native(native: &AirEvaluator<'_>) {
    let graph = native.program.graph();
    let constraints = native.program.constraints();
    let layout = native.descriptor.analysis().layout();
    assert_eq!(
        constraints.base_roots.len(),
        layout.base_indices().len(),
        "native base root count"
    );
    assert_eq!(
        constraints.ext_roots.len(),
        layout.ext_indices().len(),
        "native extension root count"
    );
    assert_eq!(
        constraints.base_global_indices.as_slice(),
        layout.base_indices(),
        "native base assertion positions"
    );
    assert_eq!(
        constraints.ext_global_indices.as_slice(),
        layout.ext_indices(),
        "native extension assertion positions"
    );

    let mut pending: Vec<_> =
        constraints.base_roots.iter().chain(&constraints.ext_roots).copied().collect();
    for &root in &constraints.base_roots {
        assert!(root.index() < graph.len(), "native base root outside graph");
        assert_eq!(graph.class(root), Class::Base, "native base root class");
    }
    let spec = native.descriptor.spec();
    let mut seen = vec![false; graph.len()];
    while let Some(id) = pending.pop() {
        assert!(id.index() < graph.len(), "native operand outside graph");
        if core::mem::replace(&mut seen[id.index()], true) {
            continue;
        }
        match graph.node(id) {
            Node::Op { x, y, .. } => pending.extend([Some(x), y].into_iter().flatten()),
            Node::Leaf(Leaf::ExtBase(inner)) => pending.push(inner),
            Node::Leaf(leaf) => match leaf {
                Leaf::Main { offset, index } => assert!(
                    offset <= 1 && index < spec.main_width,
                    "native main input outside spec"
                ),
                Leaf::Preprocessed { offset, index } => assert!(
                    offset <= 1 && index < spec.preprocessed_width(),
                    "native preprocessed input outside spec"
                ),
                Leaf::Aux { offset, index } => assert!(
                    offset <= 1 && index < spec.aux_width,
                    "native auxiliary input outside spec"
                ),
                Leaf::Public(index) => {
                    assert!(index < spec.num_public_values, "native public input outside spec")
                },
                Leaf::Periodic(index) => assert!(
                    index < spec.periodic_columns.len(),
                    "native periodic input outside spec"
                ),
                Leaf::Challenge(index) => {
                    assert!(index < spec.num_challenges, "native challenge outside spec")
                },
                Leaf::PermValue(index) => {
                    assert!(index < spec.num_exports, "native export outside spec")
                },
                _ => (),
            },
        }
    }
}

/// Whole extension results that cross from uniform-only preparation into row work.
struct Preparation {
    terms: Vec<usize>,
    slots: Vec<Option<usize>>,
    fragments: Vec<SumFragment>,
    replacements: Vec<Option<Vec<FragmentPiece>>>,
    products: products::Products,
}

#[derive(Clone)]
enum FragmentPiece {
    Source(Vec<usize>),
    Cached(usize),
}

struct SumFragment {
    class: Class,
    inputs: Vec<usize>,
    slot: Option<usize>,
}

impl Preparation {
    fn new(graph: &ExpressionIndex<'_>) -> Self {
        let options = native_options();
        let challenge_only = if options.uniform {
            graph.uniform_dependencies()
        } else {
            graph.challenge_dependencies()
        };
        let mut needed = vec![false; graph.len()];
        let mut pending: Vec<_> = graph.roots.iter().map(|&(id, _)| id).collect();
        while let Some(id) = pending.pop() {
            if needed[id] {
                continue;
            }
            needed[id] = true;
            if !challenge_only[id] {
                pending.extend(graph.children(id).iter().copied());
            }
        }
        let mut terms = Vec::new();
        let mut slots = vec![None; graph.len()];
        for id in 0..graph.len() {
            if needed[id]
                && challenge_only[id]
                && graph.class(id) == Class::Ext
                && graph.node(id).identity().is_some()
                && !matches!(graph.node(id).view(), ExprView::Lift { .. })
            {
                slots[id] = Some(terms.len());
                terms.push(id);
            }
        }
        let (fragments, replacements) = if options.fragments {
            sum_fragments(graph, &terms, &slots, &challenge_only, options.prepared_fragments_only)
        } else {
            (Vec::new(), vec![None; graph.len()])
        };
        let mut preparation = Self {
            terms,
            slots,
            fragments,
            replacements,
            products: products::Products::empty(graph.len()),
        };
        if options.products != products::Mode::DISABLED {
            // Observe actual baseline token demand. Dots, scalar rewrites and sum
            // fragments can consume a source product without emitting that node;
            // those products must not inflate the new fragment's reuse count.
            let requested = {
                let mut baseline = Emitter::new(graph, &preparation, false);
                for &(root, class) in &graph.roots {
                    let _ = baseline.expr(root, class);
                }
                baseline.tokens.iter().map(Option::is_some).collect::<Vec<_>>()
            };
            preparation.products = products::Products::new(
                graph,
                &requested,
                &graph.uniform_dependencies(),
                options.products,
                preparation.capacity(),
            );
        }
        preparation
    }

    fn capacity(&self) -> usize {
        self.terms.len()
            + self.fragments.iter().filter(|fragment| fragment.slot.is_some()).count()
            + self
                .products
                .fragments
                .iter()
                .filter(|fragment| fragment.slot.is_some())
                .count()
    }
}

// A native scheduling recipe only: operands remain references to the original source index.
// Exact ordered IDs include Neg nodes, so opposite signs and source domains cannot alias.
fn sum_fragments(
    graph: &ExpressionIndex<'_>,
    materialized: &[usize],
    slots: &[Option<usize>],
    uniform: &[bool],
    only_prepared: bool,
) -> (Vec<SumFragment>, Vec<Option<Vec<FragmentPiece>>>) {
    let minimum_uses = native_options().fragment_min_uses.max(2);
    let plan = Plan::new(graph, materialized);
    let mut pending: Vec<_> = graph.roots.iter().rev().map(|&(id, _)| id).collect();
    let mut seen = vec![false; graph.len()];
    let mut regions = Vec::new();
    while let Some(id) = pending.pop() {
        if seen[id] || slots[id].is_some() {
            continue;
        }
        seen[id] = true;
        if matches!(graph.node(id).view(), ExprView::Sum { .. }) {
            let terms = plan.sum_terms(id);
            pending.extend(terms.iter().rev().copied());
            regions.push((id, graph.class(id), terms));
        } else {
            pending.extend(graph.children(id).iter().rev().copied());
        }
    }
    struct Candidate {
        class: Class,
        inputs: Vec<usize>,
        uses: usize,
        prepared: bool,
    }
    let mut lookup = HashMap::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    for (_, class, terms) in &regions {
        for start in 0..terms.len() {
            for len in 2..=MAX_TERMS.min(terms.len() - start) {
                let inputs = terms[start..start + len].to_vec();
                let next = candidates.len();
                let index = *lookup.entry((*class, inputs.clone())).or_insert_with(|| {
                    let prepared = *class == Class::Ext && inputs.iter().all(|&id| uniform[id]);
                    candidates.push(Candidate { class: *class, inputs, uses: 0, prepared });
                    next
                });
                candidates[index].uses += 1;
            }
        }
    }
    let mut fragments = Vec::new();
    let mut fragment_ids = vec![None; candidates.len()];
    let mut replacements = vec![None; graph.len()];
    let mut next_slot = materialized.len();
    for (owner, class, terms) in regions {
        let mut pieces = Vec::new();
        let mut source = Vec::new();
        let mut start = 0;
        while start < terms.len() {
            let selected = (2..=MAX_TERMS.min(terms.len() - start)).rev().find_map(|len| {
                let candidate = lookup[&(class, terms[start..start + len].to_vec())];
                ((!only_prepared && candidates[candidate].uses >= minimum_uses)
                    || candidates[candidate].prepared)
                    .then_some((len, candidate))
            });
            if let Some((len, candidate)) = selected {
                if !source.is_empty() {
                    pieces.push(FragmentPiece::Source(core::mem::take(&mut source)));
                }
                let fragment = *fragment_ids[candidate].get_or_insert_with(|| {
                    let value = &candidates[candidate];
                    let slot = value.prepared.then(|| {
                        let slot = next_slot;
                        next_slot += 1;
                        slot
                    });
                    let id = fragments.len();
                    fragments.push(SumFragment {
                        class: value.class,
                        inputs: value.inputs.clone(),
                        slot,
                    });
                    id
                });
                pieces.push(FragmentPiece::Cached(fragment));
                start += len;
            } else {
                source.push(terms[start]);
                start += 1;
            }
        }
        if !source.is_empty() {
            pieces.push(FragmentPiece::Source(source));
        }
        if pieces.iter().any(|piece| matches!(piece, FragmentPiece::Cached(_))) {
            replacements[owner] = Some(pieces);
        }
    }
    (fragments, replacements)
}

struct Emitter<'g, 'a> {
    graph: &'g ExpressionIndex<'a>,
    preparation: &'g Preparation,
    preparing: bool,
    plan: Plan<'g, 'a>,
    tokens: Vec<Option<Token>>,
    fragment_tokens: Vec<Option<Token>>,
    product_tokens: Vec<Option<Token>>,
    lines: Vec<String>,
    hoisted: usize,
}

impl<'g, 'a> Emitter<'g, 'a> {
    fn new(graph: &'g ExpressionIndex<'a>, preparation: &'g Preparation, preparing: bool) -> Self {
        Self {
            graph,
            preparation,
            preparing,
            plan: Plan::new(graph, &preparation.terms),
            tokens: vec![None; graph.len()],
            fragment_tokens: vec![None; preparation.fragments.len()],
            product_tokens: vec![None; preparation.products.fragments.len()],
            lines: Vec::new(),
            hoisted: 0,
        }
    }

    fn types(&self) -> ExprTypes {
        if self.preparing {
            ExprTypes { base: "B", ext: "E" }
        } else {
            ExprTypes { base: "AB::Expr", ext: "AB::ExtExpr" }
        }
    }

    fn ty(&self, class: Class) -> &'static str {
        let types = self.types();
        if class == Class::Base { types.base } else { types.ext }
    }

    fn token(&mut self, id: usize) -> Token {
        if let Some(token) = &self.tokens[id] {
            return token.clone();
        }
        if !self.preparing
            && let Some(slot) = self.preparation.slots[id]
        {
            let token = self.hoist(Class::Ext, format!("terms[{slot}].dup()"));
            self.tokens[id] = Some(token.clone());
            return token;
        }
        let graph = self.graph;
        let inputs = graph.children(id);
        let class = graph.class(id);
        let view = graph.node(id).view();
        let token = match view {
            // A lift keeps its base token until an operation needs extension arithmetic.
            ExprView::Lift { .. } => self.token(inputs[0]),
            ExprView::BaseConstant(_)
            | ExprView::ExtensionConstant(_)
            | ExprView::BaseInput(_)
            | ExprView::AuxInput(_)
            | ExprView::IsFirstRow
            | ExprView::IsLastRow
            | ExprView::IsTransition => self.leaf(view),
            _ => {
                let rhs = if !self.preparing
                    && let Some(factors) = self.preparation.products.replacements[id].clone()
                {
                    self.product_rhs(class, &factors)
                } else if !self.preparing
                    && let Some(pieces) = self.preparation.replacements[id].clone()
                {
                    let mut values = Vec::with_capacity(pieces.len());
                    for piece in pieces {
                        values.push(match piece {
                            FragmentPiece::Source(inputs) => self.region_sum(class, &inputs),
                            FragmentPiece::Cached(fragment) => operand(&self.fragment(fragment)),
                        });
                    }
                    self.sum_values(class, &values)
                } else if let Some(rewrite) = self.plan.rewrite(id) {
                    self.rewrite_rhs(class, rewrite)
                } else {
                    self.operation(class, view, inputs)
                };
                self.bind(id, class, rhs)
            },
        };
        self.tokens[id] = Some(token.clone());
        token
    }

    fn region_sum(&mut self, class: Class, inputs: &[usize]) -> String {
        let pieces = self.plan.sum_pieces(inputs, class);
        if inputs.len() < 4 && !pieces.iter().any(|piece| matches!(piece, Piece::Dot { .. })) {
            self.signed_sum(class, inputs)
        } else {
            self.rewrite_rhs(class, Rewrite::Sum(pieces))
        }
    }

    fn fragment(&mut self, id: usize) -> Token {
        if let Some(token) = &self.fragment_tokens[id] {
            return token.clone();
        }
        let fragment = &self.preparation.fragments[id];
        let class = fragment.class;
        let slot = fragment.slot;
        let inputs = fragment.inputs.clone();
        let token = if !self.preparing
            && let Some(slot) = slot
        {
            self.hoist(Class::Ext, format!("terms[{slot}].dup()"))
        } else {
            let rhs = self.region_sum(class, &inputs);
            self.hoist(class, rhs)
        };
        self.fragment_tokens[id] = Some(token.clone());
        token
    }

    fn product_factor(&mut self, factor: products::Factor) -> Token {
        match factor {
            products::Factor::Source(id) => self.token(id),
            products::Factor::Fragment(id) => self.product_fragment(id),
        }
    }

    fn product_fragment(&mut self, id: usize) -> Token {
        if let Some(token) = &self.product_tokens[id] {
            return token.clone();
        }
        let fragment = &self.preparation.products.fragments[id];
        let class = fragment.class;
        let factors = fragment.factors;
        let slot = fragment.slot;
        let token = if !self.preparing
            && let Some(slot) = slot
        {
            self.hoist(Class::Ext, format!("terms[{slot}].dup()"))
        } else {
            let x = self.product_factor(factors[0]);
            let rhs = if factors[0] == factors[1] {
                format!("{}.square()", operand(&x))
            } else {
                let y = self.product_factor(factors[1]);
                self.binary_tokens(class, OpKind::Mul, &x, &y)
            };
            self.hoist(class, rhs)
        };
        self.product_tokens[id] = Some(token.clone());
        token
    }

    fn product_rhs(&mut self, class: Class, factors: &[products::Factor]) -> String {
        let mut factors = factors.iter().copied();
        let mut value = self.product_factor(factors.next().expect("nonempty product region"));
        let mut remaining = factors.peekable();
        while let Some(factor) = remaining.next() {
            let next = self.product_factor(factor);
            let product_class = plan::join(value.class, next.class);
            let rhs = self.binary_tokens(product_class, OpKind::Mul, &value, &next);
            if remaining.peek().is_none() {
                return if class == Class::Ext && product_class == Class::Base {
                    format!("{}::from({rhs})", self.types().ext)
                } else {
                    assert_eq!(class, product_class, "product result domain");
                    rhs
                };
            }
            value = self.hoist(product_class, rhs);
        }
        if class == Class::Ext && value.class == Class::Base {
            lift_base_to_ext(&value, self.types())
        } else {
            assert_eq!(class, value.class, "product result domain");
            operand(&value)
        }
    }

    fn hoist(&mut self, class: Class, rhs: String) -> Token {
        let name = format!("h{}", self.hoisted);
        self.hoisted += 1;
        self.lines.push(format!("    let {name}: {} = {rhs};", self.ty(class)));
        Token { class, code: name }
    }

    fn bind(&mut self, id: usize, class: Class, rhs: String) -> Token {
        let prefix = if class == Class::Base { 'b' } else { 'e' };
        let name = format!("{prefix}{id}");
        self.lines.push(format!("    let {name} = {rhs};"));
        Token { class, code: name }
    }

    fn expr(&mut self, id: usize, class: Class) -> String {
        let token = self.token(id);
        if class == Class::Ext && token.class == Class::Base {
            lift_base_to_ext(&token, self.types())
        } else {
            assert_eq!(token.class, class, "extension expression used in base arithmetic");
            operand(&token)
        }
    }

    fn leaf(&mut self, view: ExprView<'_, Felt, QuadFelt>) -> Token {
        match view {
            ExprView::BaseInput(input) => match input {
                BaseInput::Preprocessed { row, column } => {
                    self.hoist(Class::Base, format!("p{}[{column}].dup()", row.index()))
                },
                BaseInput::Main { row, column } => {
                    self.hoist(Class::Base, format!("m{}[{column}].dup()", row.index()))
                },
                BaseInput::Public { index } => {
                    self.hoist(Class::Base, format!("inputs.public_values[{index}].dup()"))
                },
                BaseInput::Periodic { index } => {
                    self.hoist(Class::Base, format!("frame.periodic[{index}].dup()"))
                },
            },
            ExprView::IsFirstRow => self.hoist(Class::Base, "frame.selectors.first.dup()".into()),
            ExprView::IsLastRow => self.hoist(Class::Base, "frame.selectors.last.dup()".into()),
            ExprView::IsTransition => {
                self.hoist(Class::Base, "frame.selectors.transition.dup()".into())
            },
            ExprView::BaseConstant(value) => self.hoist(
                Class::Base,
                format!(
                    "{}::from(Felt::from_u64({}))",
                    self.types().base,
                    value.as_canonical_u64()
                ),
            ),
            ExprView::AuxInput(input) => match input {
                AuxInput::Trace { row, column } => {
                    self.hoist(Class::Ext, format!("a{}[{column}].dup()", row.index()))
                },
                AuxInput::Challenge { index } => {
                    let source = if self.preparing {
                        "challenges"
                    } else {
                        "inputs.challenges"
                    };
                    self.hoist(Class::Ext, format!("{source}[{index}].dup()"))
                },
                AuxInput::Export { index } => {
                    self.hoist(Class::Ext, format!("inputs.exports[{index}].dup()"))
                },
            },
            ExprView::ExtensionConstant(value) => {
                let coefficients: &[Felt] = value.as_basis_coefficients_slice();
                assert_eq!(
                    coefficients[1].as_canonical_u64(),
                    0,
                    "ext constant with non-base coefficients"
                );
                let value = coefficients[0].as_canonical_u64();
                let types = self.types();
                self.hoist(
                    Class::Ext,
                    format!("{}::from({}::from(Felt::from_u64({value})))", types.ext, types.base),
                )
            },
            _ => unreachable!("operation passed to leaf emitter"),
        }
    }

    fn binary(&mut self, class: Class, op: OpKind, x: usize, y: usize) -> String {
        let x = self.token(x);
        let y = self.token(y);
        self.binary_tokens(class, op, &x, &y)
    }

    fn binary_tokens(&self, class: Class, op: OpKind, x: &Token, y: &Token) -> String {
        if class == Class::Base {
            assert_eq!(x.class, Class::Base);
            assert_eq!(y.class, Class::Base);
            return format!("{} {} {}", operand(x), sym(op), operand(y));
        }
        match (x.class, y.class) {
            (Class::Ext, _) => format!("{} {} {}", operand(x), sym(op), operand(y)),
            (Class::Base, Class::Ext) if op != OpKind::Sub => {
                format!("{} {} {}", operand(y), sym(op), operand(x))
            },
            (Class::Base, _) => {
                format!("{} {} {}", lift_base_to_ext(x, self.types()), sym(op), operand(y))
            },
        }
    }

    fn operation(
        &mut self,
        class: Class,
        view: ExprView<'_, Felt, QuadFelt>,
        inputs: &[usize],
    ) -> String {
        let ty = self.ty(class);
        match view {
            ExprView::Mul { .. } => self.binary(class, OpKind::Mul, inputs[0], inputs[1]),
            ExprView::Neg { .. } => format!("-{}", self.expr(inputs[0], class)),
            ExprView::Sum { .. } => self.signed_sum(class, inputs),
            ExprView::Product { .. } => {
                let values: Vec<_> = inputs.iter().map(|&id| self.expr(id, class)).collect();
                format!("[{}].into_iter().product::<{ty}>()", values.join(", "))
            },
            ExprView::Exp { power, .. } => {
                let value = self.expr(inputs[0], class);
                match power {
                    0 => format!("{ty}::ONE"),
                    1 => value,
                    2 => format!("{value}.square()"),
                    3 => format!("{value}.cube()"),
                    power => format!("{value}.exp_const_u64::<{power}>()"),
                }
            },
            ExprView::ExpPowerOf2 { power_log, .. } => {
                format!("{}.exp_power_of_2({power_log})", self.expr(inputs[0], class))
            },
            ExprView::ScalePow2 { exponent, .. } => {
                let value = self.expr(inputs[0], class);
                match exponent {
                    0 => value,
                    1 => format!("{value}.double()"),
                    -1 => format!("{value}.halve()"),
                    n if n > 0 => format!(
                        "{value}.mul_2exp_u64({})",
                        u64::try_from(n).expect("scaling magnitude fits u64")
                    ),
                    n => format!(
                        "{value}.div_2exp_u64({})",
                        u64::try_from(n.unsigned_abs()).expect("scaling magnitude fits u64")
                    ),
                }
            },
            ExprView::BoolCheck { .. } => format!("{}.bool_check()", self.expr(inputs[0], class)),
            ExprView::LinearCombination { .. } => {
                assert_eq!(inputs.len() % 2, 0, "linear combination arity");
                let n = inputs.len() / 2;
                let values: Vec<_> = inputs[..n].iter().map(|&id| self.expr(id, class)).collect();
                let (scalar_ty, coefficients) = self.coefficients(class, &inputs[n..]);
                let method = if scalar_ty == ty {
                    format!("{ty}::dot_product::<{n}>")
                } else if n <= MAX_TERMS {
                    format!("<{ty} as Algebra<{scalar_ty}>>::mixed_dot_product::<{n}>")
                } else {
                    format!("<{ty} as Algebra<{scalar_ty}>>::batched_linear_combination")
                };
                format!("{method}(&[{}], &[{}])", values.join(", "), coefficients.join(", "))
            },
            _ => unreachable!("leaf or lift passed to operation emitter"),
        }
    }

    /// Render a small sum through signed operators, retaining narrow base operands
    /// and materializing only negations that have a separate consumer.
    fn signed_sum(&mut self, class: Class, inputs: &[usize]) -> String {
        let mut terms = Vec::with_capacity(inputs.len());
        for &id in inputs {
            let (mut negative, value) = match self.plan.negated(id) {
                Some(value) => (true, value),
                None => (false, id),
            };
            let literal = self.graph.constant(value).map(|value| {
                if value > Felt::ORDER / 2 {
                    negative = !negative;
                    Felt::ORDER - value
                } else {
                    value
                }
            });
            let token = match literal {
                Some(value) => Token {
                    class: Class::Base,
                    code: format!("{}::from(Felt::from_u64({value}))", self.types().base),
                },
                None => self.token(value),
            };
            terms.push((negative, token, literal));
        }
        let mut terms = terms.into_iter();
        let Some((negative, token, _)) = terms.next() else {
            return format!("{}::ZERO", self.ty(class));
        };
        let mut result_class = token.class;
        let mut result = if negative {
            format!("-{}", operand(&token))
        } else {
            operand(&token)
        };
        for (negative, token, literal) in terms {
            let symbol = if negative { '-' } else { '+' };
            let right = if result_class == Class::Base && token.class == Class::Base {
                literal.map_or_else(|| operand(&token), |value| format!("Felt::from_u64({value})"))
            } else {
                operand(&token)
            };
            match (result_class, token.class, negative) {
                (Class::Base, Class::Ext, false) => result = format!("{right} + ({result})"),
                (Class::Base, Class::Ext, true) => {
                    result = format!("{}::from({result}) - {right}", self.types().ext);
                },
                _ => result = format!("{result} {symbol} {right}"),
            }
            result_class = plan::join(result_class, token.class);
        }
        if class == Class::Ext && result_class == Class::Base {
            format!("{}::from({result})", self.types().ext)
        } else {
            result
        }
    }

    /// Bound arrays even when a source sum has accumulated many operands.
    fn sum_values(&mut self, class: Class, values: &[String]) -> String {
        if values.len() > MAX_TERMS {
            let partials: Vec<_> = values
                .chunks(MAX_TERMS)
                .map(|chunk| {
                    let rhs = self.sum_values(class, chunk);
                    operand(&self.hoist(class, rhs))
                })
                .collect();
            return self.sum_values(class, &partials);
        }
        match values.len() {
            0 => format!("{}::ZERO", self.ty(class)),
            1 => values[0].clone(),
            2 | 3 => {
                values.iter().map(|value| format!("({value})")).collect::<Vec<_>>().join(" + ")
            },
            n => format!("{}::sum_array::<{n}>(&[{}])", self.ty(class), values.join(", ")),
        }
    }

    fn coefficients(&mut self, class: Class, ids: &[usize]) -> (&'static str, Vec<String>) {
        let types = self.types();
        if class == Class::Base && ids.iter().all(|&id| self.graph.constant(id).is_some()) {
            return (
                "Felt",
                ids.iter()
                    .map(|&id| format!("Felt::from_u64({})", self.graph.constant(id).unwrap()))
                    .collect(),
            );
        }
        // ExtExpr is promised Algebra<BaseExpr>, not Algebra<Felt> or Algebra<EF>.
        // Explicit lifts and base constants can use the smaller coefficient type.
        let coefficient_class = if ids.iter().all(|&id| self.graph.value_class(id) == Class::Base) {
            Class::Base
        } else {
            class
        };
        (
            if coefficient_class == Class::Base {
                types.base
            } else {
                types.ext
            },
            ids.iter().map(|&id| self.expr(id, coefficient_class)).collect(),
        )
    }

    fn rewrite_rhs(&mut self, class: Class, rewrite: Rewrite) -> String {
        let ty = self.ty(class);
        match rewrite {
            Rewrite::Alias(id) => self.expr(id, class),
            Rewrite::Square(id) => format!("{}.square()", self.expr(id, class)),
            Rewrite::Scalar { value, scalar, op, reversed } => {
                let value = self.expr(value, Class::Base);
                if op == OpKind::Mul {
                    match scalar {
                        2 => return format!("{value}.double()"),
                        0x7fff_ffff_8000_0001 => return format!("{value}.halve()"),
                        c if c.is_power_of_two() => {
                            return format!("{value}.mul_2exp_u64({})", c.trailing_zeros());
                        },
                        _ => {},
                    }
                }
                if reversed && op == OpKind::Sub {
                    format!("-{value} + Felt::from_u64({scalar})")
                } else {
                    format!("{value} {} Felt::from_u64({scalar})", sym(op))
                }
            },
            Rewrite::Factor { common, scalar, left, right } => {
                if let Some(scalar) = scalar {
                    let left = self.expr(left, class);
                    let right = self.expr(right, class);
                    return format!("({left} + {right}) * Felt::from_u64({scalar})");
                }
                let factor = self.graph.value_class(common);
                let sum = plan::join(self.graph.value_class(left), self.graph.value_class(right));
                let common = self.expr(common, factor);
                let left = self.expr(left, sum);
                let right = self.expr(right, sum);
                if factor == Class::Base && sum == Class::Ext {
                    format!("({left} + {right}) * {common}")
                } else {
                    format!("{common} * ({left} + {right})")
                }
            },
            Rewrite::Sum(pieces) => {
                let mut values = Vec::with_capacity(pieces.len().min(MAX_TERMS));
                let mut partials = Vec::new();
                for piece in pieces {
                    values.push(match piece {
                        Piece::Node(id) => self.expr(id, class),
                        Piece::Factor { common, terms } => {
                            let sum_class = terms
                                .iter()
                                .map(|&id| self.graph.value_class(id))
                                .reduce(plan::join)
                                .expect("nonempty factor run");
                            let sum = self.region_sum(sum_class, &terms);
                            let rhs = if let Some(scalar) =
                                self.graph.constant(common).filter(|_| class == Class::Base)
                            {
                                format!("({sum}) * Felt::from_u64({scalar})")
                            } else {
                                let factor_class = self.graph.value_class(common);
                                let common = self.expr(common, factor_class);
                                if factor_class == Class::Base && sum_class == Class::Ext {
                                    format!("({sum}) * {common}")
                                } else {
                                    format!("{common} * ({sum})")
                                }
                            };
                            operand(&self.hoist(class, rhs))
                        },
                        Piece::Dot { kind, pairs } => {
                            let n = pairs.len();
                            let mut terms = Vec::with_capacity(n);
                            let mut coeffs = Vec::with_capacity(n);
                            for (id, coefficient) in pairs {
                                terms.push(self.expr(id, class));
                                coeffs.push(match coefficient {
                                    Coefficient::Scalar(c) => format!("Felt::from_u64({c})"),
                                    Coefficient::One => format!("{}::ONE", self.types().base),
                                    Coefficient::NegativeScalar(c) => {
                                        format!("-Felt::from_u64({c})")
                                    },
                                    Coefficient::NegativeOne => {
                                        format!("-{}::ONE", self.types().base)
                                    },
                                    Coefficient::NegativeNode(id) => format!(
                                        "-{}",
                                        self.expr(
                                            id,
                                            if kind == DotKind::Mixed {
                                                Class::Base
                                            } else {
                                                class
                                            },
                                        )
                                    ),
                                    Coefficient::Node(id) => self.expr(
                                        id,
                                        if kind == DotKind::Mixed { Class::Base } else { class },
                                    ),
                                });
                            }
                            let method = match kind {
                                DotKind::Same => format!("{ty}::dot_product::<{n}>"),
                                DotKind::Scalar => {
                                    format!("<{ty} as Algebra<Felt>>::mixed_dot_product::<{n}>")
                                },
                                DotKind::Mixed => format!(
                                    "<{ty} as Algebra<{}>>::mixed_dot_product::<{n}>",
                                    self.types().base
                                ),
                            };
                            let rhs = format!(
                                "{method}(&[{}], &[{}])",
                                terms.join(", "),
                                coeffs.join(", ")
                            );
                            // Finish this dot before loading the next region's
                            // operands, keeping its inputs out of later live ranges.
                            operand(&self.hoist(class, rhs))
                        },
                    });
                    if values.len() == MAX_TERMS {
                        let rhs = self.sum_values(class, &values);
                        partials.push(operand(&self.hoist(class, rhs)));
                        values.clear();
                    }
                }
                if partials.is_empty() {
                    return self.sum_values(class, &values);
                }
                if !values.is_empty() {
                    let rhs = self.sum_values(class, &values);
                    partials.push(operand(&self.hoist(class, rhs)));
                }
                self.sum_values(class, &partials)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, field::QuadFelt};
    use miden_crypto::field::{Algebra, PrimeCharacteristicRing};
    use miden_stark::air::{
        Assertion,
        symbolic::{AuxInput, BaseInput, RowOffset, SymbolicExpression, SymbolicExpressionExt},
    };
    use p3_field::Dup;

    use super::*;

    type B = SymbolicExpression<Felt, QuadFelt>;
    type E = SymbolicExpressionExt<Felt, QuadFelt>;

    fn main(index: usize) -> B {
        B::from(BaseInput::Main { row: RowOffset::Current, column: index })
    }
    fn challenge(index: usize) -> E {
        E::from(AuxInput::Challenge { index })
    }
    fn emit(assertions: &[Assertion<Felt, QuadFelt>]) -> String {
        let program = CapturedProgram::from_assertions(assertions.to_vec());
        assert_rewrites_preserve_values(&program);
        let descriptor = descriptor(assertions);
        let evaluators = [AirEvaluator {
            name: "fixture",
            air_label: "Fixture",
            program: &program,
            descriptor: &descriptor,
        }];
        let result = emit_native_optimized_module("//! Symbolic fixture.\n", &evaluators);
        assert_eq!(result, emit_native_optimized_module("//! Symbolic fixture.\n", &evaluators));
        result
    }

    fn descriptor(
        assertions: &[Assertion<Felt, QuadFelt>],
    ) -> miden_stark::air::AirDescriptor<Felt> {
        use miden_stark::air::{self, LiftedAirBuilder};
        use std::borrow::Cow;

        let index = ExpressionIndex::new(assertions);
        let mut spec = air::AirSpec {
            main_width: 1,
            aux_width: 0,
            num_public_values: 0,
            num_challenges: 0,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        };
        let mut periodic = 0;
        for id in 0..index.len() {
            match index.node(id).view() {
                ExprView::BaseInput(BaseInput::Main { column, .. }) => {
                    spec.main_width = spec.main_width.max(column + 1);
                },
                ExprView::BaseInput(BaseInput::Preprocessed { column, .. }) => {
                    let fixed = spec
                        .preprocessed
                        .get_or_insert(air::PreprocessedSpec { width: 0, log_height: 1 });
                    fixed.width = fixed.width.max(column + 1);
                },
                ExprView::BaseInput(BaseInput::Public { index }) => {
                    spec.num_public_values = spec.num_public_values.max(index + 1);
                },
                ExprView::BaseInput(BaseInput::Periodic { index }) => {
                    periodic = periodic.max(index + 1);
                },
                ExprView::AuxInput(AuxInput::Trace { column, .. }) => {
                    spec.aux_width = spec.aux_width.max(column + 1);
                },
                ExprView::AuxInput(AuxInput::Challenge { index }) => {
                    spec.num_challenges = spec.num_challenges.max(index + 1);
                },
                ExprView::AuxInput(AuxInput::Export { index }) => {
                    spec.num_exports = spec.num_exports.max(index + 1);
                },
                _ => {},
            }
        }
        spec.periodic_columns = Cow::Owned(vec![vec![Felt::ONE; 2]; periodic]);
        air::capture_from_spec::<Felt, QuadFelt>(spec, |_, _, sink| {
            for assertion in assertions {
                match assertion {
                    Assertion::Base(value) => sink.assert_zero(value.dup()),
                    Assertion::Extension(value) => sink.assert_zero_ext(value.dup()),
                }
            }
        })
        .expect("valid symbolic emitter fixture")
        .descriptor
    }

    #[test]
    #[should_panic(expected = "native base assertion positions")]
    fn native_rendering_rejects_an_accidentally_mismatched_layout() {
        let assertions = [Assertion::Base(main(0)), Assertion::Extension(challenge(0))];
        let program = CapturedProgram::from_assertions(assertions.to_vec());
        let descriptor = descriptor(&[assertions[1].clone(), assertions[0].clone()]);
        emit_native_optimized_module(
            "",
            &[AirEvaluator {
                name: "mismatch",
                air_label: "Mismatch",
                program: &program,
                descriptor: &descriptor,
            }],
        );
    }

    #[test]
    #[should_panic(expected = "native main input outside spec")]
    fn native_rendering_rejects_an_accidentally_mismatched_input_shape() {
        let program = CapturedProgram::from_assertions(vec![Assertion::Base(main(1))]);
        let descriptor = descriptor(&[Assertion::Base(main(0))]);
        emit_native_optimized_module(
            "",
            &[AirEvaluator {
                name: "mismatch",
                air_label: "Mismatch",
                program: &program,
                descriptor: &descriptor,
            }],
        );
    }

    // Retain the old optimizer's independent numerical oracle while exercising
    // the production source index and planner rather than a second emitter.
    fn assert_rewrites_preserve_values(program: &CapturedProgram) {
        let index = ExpressionIndex::new(program.assertions());
        let preparation = Preparation::new(&index);
        let plan = Plan::new(&index, &preparation.terms);
        for seed in [0, 1, 0x243f6a8885a308d3, u64::MAX] {
            let values: Vec<_> = index
                .nodes
                .iter()
                .map(|node| crate::testing::eval_expression(node.expression, seed))
                .collect();
            let mut product_values = Vec::new();
            for fragment in &preparation.products.fragments {
                let value = |factor| match factor {
                    products::Factor::Source(id) => values[id],
                    products::Factor::Fragment(id) => product_values[id],
                };
                product_values.push(value(fragment.factors[0]) * value(fragment.factors[1]));
            }
            for (id, factors) in preparation.products.replacements.iter().enumerate() {
                if let Some(factors) = factors {
                    let result: QuadFelt = factors
                        .iter()
                        .map(|factor| match *factor {
                            products::Factor::Source(id) => values[id],
                            products::Factor::Fragment(id) => product_values[id],
                        })
                        .product();
                    assert_eq!(result, values[id], "product region {id} with seed {seed}");
                }
            }
            for id in 0..index.len() {
                let Some(rewrite) = plan.rewrite(id) else {
                    continue;
                };
                let result = match rewrite {
                    Rewrite::Alias(x) => values[x],
                    Rewrite::Square(x) => values[x].square(),
                    Rewrite::Scalar { value, scalar, op, reversed } => {
                        let (mut x, mut y) =
                            (values[value], QuadFelt::from(Felt::from_u64(scalar)));
                        if reversed {
                            core::mem::swap(&mut x, &mut y);
                        }
                        match op {
                            OpKind::Add => x + y,
                            OpKind::Sub => x - y,
                            OpKind::Mul => x * y,
                            OpKind::Neg => unreachable!(),
                        }
                    },
                    Rewrite::Factor { common, left, right, .. } => {
                        values[common] * (values[left] + values[right])
                    },
                    Rewrite::Sum(pieces) => pieces
                        .into_iter()
                        .map(|piece| match piece {
                            Piece::Node(id) => values[id],
                            Piece::Factor { common, terms } => {
                                values[common]
                                    * terms.into_iter().map(|id| values[id]).sum::<QuadFelt>()
                            },
                            Piece::Dot { pairs, .. } => pairs
                                .into_iter()
                                .map(|(id, coefficient)| {
                                    values[id]
                                        * match coefficient {
                                            Coefficient::Node(coefficient) => values[coefficient],
                                            Coefficient::Scalar(value) => {
                                                QuadFelt::from(Felt::from_u64(value))
                                            },
                                            Coefficient::One => QuadFelt::ONE,
                                            Coefficient::NegativeNode(coefficient) => {
                                                -values[coefficient]
                                            },
                                            Coefficient::NegativeScalar(value) => {
                                                -QuadFelt::from(Felt::from_u64(value))
                                            },
                                            Coefficient::NegativeOne => -QuadFelt::ONE,
                                        }
                                })
                                .sum(),
                        })
                        .sum(),
                };
                assert_eq!(result, values[id], "rewrite of source node {id} with seed {seed}");
            }
        }
    }

    #[test]
    fn native_experiment_scopes_restore_the_production_policy() {
        assert_eq!(native_options(), NativeOptions::default());
        assert!(native_options().uniform && native_options().fragments);
        assert!(native_options().cancel_const_offsets);
        assert_eq!(native_options().products, products::Mode::PAIRS);
        assert_eq!(native_options().dot_min_terms, [4; 3]);
        assert_eq!(native_options().dot_max_terms, [16, 8, 16]);
        assert!(!native_options().left_sum_folding);
        with_native_experiment(NativeExperiment::LeftSumFolding, || {
            assert!(native_options().left_sum_folding);
            assert!(!native_options().uniform && !native_options().fragments);
        });
        with_native_experiment(NativeExperiment::UniformFragments, || {
            assert!(native_options().uniform && native_options().fragments);
            with_native_experiment(NativeExperiment::Baseline, || {
                assert_eq!(native_options(), NativeOptions::baseline());
            });
            assert!(native_options().uniform && native_options().fragments);
        });
        assert_eq!(native_options(), NativeOptions::default());
        let _ = std::panic::catch_unwind(|| {
            with_native_experiment(NativeExperiment::Uniform, || panic!("restore experiment"));
        });
        assert_eq!(native_options(), NativeOptions::default());
    }

    fn synthesized_dots(assertion: Assertion<Felt, QuadFelt>) -> Vec<(DotKind, usize)> {
        let program = CapturedProgram::from_assertions(vec![assertion]);
        assert_rewrites_preserve_values(&program);
        let index = ExpressionIndex::new(program.assertions());
        let preparation = Preparation::new(&index);
        let plan = Plan::new(&index, &preparation.terms);
        let (root, class) = index.roots[0];
        plan.sum_pieces(&plan.sum_terms(root), class)
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Dot { kind, pairs } => Some((kind, pairs.len())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn synthesized_dot_thresholds_are_independent_for_scalar_mixed_and_same_operands() {
        for (mode, minimums) in [
            (NativeExperiment::UniformFragments, [4, 4, 4]),
            (NativeExperiment::DotMin2, [2, 2, 2]),
            (NativeExperiment::DotMin3, [3, 3, 3]),
            (NativeExperiment::MixedDotMin2, [4, 2, 4]),
            (NativeExperiment::MixedDotMin3, [4, 3, 4]),
        ] {
            with_native_experiment(mode, || {
                for n in [2, 3, 4] {
                    let scalar = (0..n).map(|i| main(i) * Felt::from_u64(7 + 2 * i as u64));
                    let mixed = (0..n).map(|i| {
                        E::from(AuxInput::Trace { row: RowOffset::Current, column: i })
                            * E::from(main(i))
                    });
                    let same = (0..n).map(|i| main(2 * i) * main(2 * i + 1));
                    let assertions = [
                        Assertion::Base(scalar.sum()),
                        Assertion::Extension(mixed.sum()),
                        Assertion::Base(same.sum()),
                    ];
                    for ((assertion, kind), minimum) in assertions
                        .into_iter()
                        .zip([DotKind::Scalar, DotKind::Mixed, DotKind::Same])
                        .zip(minimums)
                    {
                        let expected = if n >= minimum { vec![(kind, n)] } else { Vec::new() };
                        assert_eq!(
                            synthesized_dots(assertion.clone()),
                            expected,
                            "{mode:?}, {kind:?}, n={n}"
                        );
                        // Exercise the emitter as well as the numerical planning oracle.
                        let output = emit(&[assertion]);
                        assert_eq!(
                            output.contains(&format!("dot_product::<{n}>")),
                            n >= minimum,
                            "{mode:?}, {kind:?}: {output}"
                        );
                    }
                }
            });
        }
    }

    #[test]
    fn synthesized_dot_caps_do_not_change_fragment_limits_or_operand_types() {
        for (mode, cap_by_kind) in [
            (NativeExperiment::DotCap6, [6, 6, 6]),
            (NativeExperiment::DotCap8, [8, 8, 8]),
            (NativeExperiment::MixedDotCap6, [16, 6, 16]),
            (NativeExperiment::MixedDotCap8, [16, 8, 16]),
        ] {
            with_native_experiment(mode, || {
                assert_eq!(MAX_TERMS, 16);
                let scalar: [B; 17] =
                    core::array::from_fn(|i| main(i) * Felt::from_u64(7 + 2 * i as u64));
                let mixed: [E; 17] = core::array::from_fn(|i| {
                    E::from(AuxInput::Trace { row: RowOffset::Current, column: i })
                        * E::from(main(i))
                });
                let same: [B; 17] = core::array::from_fn(|i| main(2 * i) * main(2 * i + 1));
                for ((assertion, kind), cap) in [
                    Assertion::Base(B::sum_array::<17>(&scalar)),
                    Assertion::Extension(E::sum_array::<17>(&mixed)),
                    Assertion::Base(B::sum_array::<17>(&same)),
                ]
                .into_iter()
                .zip([DotKind::Scalar, DotKind::Mixed, DotKind::Same])
                .zip(cap_by_kind)
                {
                    let sizes: &[usize] = match cap {
                        6 => &[6, 6, 5],
                        8 => &[8, 8],
                        16 => &[16],
                        _ => unreachable!(),
                    };
                    assert_eq!(
                        synthesized_dots(assertion.clone()),
                        sizes.iter().map(|&n| (kind, n)).collect::<Vec<_>>(),
                        "{mode:?}, {kind:?}"
                    );
                    let output = emit(&[assertion]);
                    let ty = match kind {
                        DotKind::Scalar => "<AB::Expr as Algebra<Felt>>::mixed_dot_product",
                        DotKind::Mixed => "<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product",
                        DotKind::Same => "AB::Expr::dot_product",
                    };
                    for &n in sizes {
                        assert!(output.contains(&format!("{ty}::<{n}>")), "{mode:?}: {output}");
                    }
                    assert!(!output.contains(&format!("{ty}::<17>")), "{output}");
                }
            });
        }
    }

    #[test]
    fn small_dot_experiments_keep_specialized_scalars_squares_and_authored_linear_combinations() {
        for mode in [
            NativeExperiment::DotMin2,
            NativeExperiment::DotMin3,
            NativeExperiment::DotCap6,
            NativeExperiment::MixedDotCap6,
        ] {
            with_native_experiment(mode, || {
                let x = main(0);
                let y = main(1);
                let values: [B; 9] = core::array::from_fn(main);
                let coefficients: [Felt; 9] =
                    core::array::from_fn(|i| Felt::from_u64(7 + 2 * i as u64));
                let assertions = [
                    Assertion::Base(x.clone() * Felt::TWO + y.clone() * Felt::from_u64(7)),
                    Assertion::Base(
                        x.clone() * Felt::from_u64(0x7fff_ffff_8000_0001)
                            + y.clone() * Felt::from_u64(9),
                    ),
                    Assertion::Base(x.clone() * Felt::from_u64(8) + y.clone() * Felt::from_u64(11)),
                    Assertion::Base(x.square() + y * main(2)),
                    Assertion::Base(<B as Algebra<Felt>>::mixed_dot_product(
                        &values,
                        &coefficients,
                    )),
                ];
                let output = emit(&assertions);
                for method in [
                    ".double()",
                    ".halve()",
                    ".mul_2exp_u64(3)",
                    ".square()",
                    "<AB::Expr as Algebra<Felt>>::mixed_dot_product::<9>",
                ] {
                    assert!(output.contains(method), "{mode:?}, missing {method}: {output}");
                }
            });
        }
    }

    #[test]
    fn inverse_literal_offsets_cancel_in_base_and_extension_arithmetic() {
        with_native_experiment(NativeExperiment::CancelConstOffsets, || {
            let c = Felt::from_u64(7);
            for ordering in 0..4 {
                let base = main(0).square();
                let ext = challenge(0) * E::from(main(1));
                let (base, ext) = match ordering {
                    0 => ((base + c) - c, (ext + c) - c),
                    1 => ((base - c) + c, (ext - c) + c),
                    2 => ((B::from(c) + base) - c, (E::from(c) + ext) - c),
                    3 => (B::from(c) + (base - c), E::from(c) + (ext - c)),
                    _ => unreachable!(),
                };
                // Separate captures keep the offset intermediates single-use.
                for assertion in [Assertion::Base(base), Assertion::Extension(ext)] {
                    let program = CapturedProgram::from_assertions(vec![assertion]);
                    let index = ExpressionIndex::new(program.assertions());
                    let preparation = Preparation::new(&index);
                    let plan = Plan::new(&index, &preparation.terms);
                    assert!(
                        matches!(plan.rewrite(index.roots[0].0), Some(Rewrite::Alias(_))),
                        "ordering {ordering}"
                    );
                    let output = emit(program.assertions());
                    assert!(!output.contains("Felt::from_u64(7)"), "{output}");
                    if ordering == 0 && matches!(&program.assertions()[0], Assertion::Base(_)) {
                        assert!(output.contains(".square()"), "{output}");
                    }
                }
            }
        });
    }

    #[test]
    fn inverse_offsets_are_removed_before_surrounding_sum_planning() {
        let value = main(0) * main(1);
        let inverse_pair = (value - Felt::ONE) + Felt::ONE;
        let assertion =
            Assertion::Base(B::sum_array::<4>(&[main(2), inverse_pair, main(3), main(4)]));
        let program = CapturedProgram::from_assertions(vec![assertion]);
        let baseline = with_native_experiment(NativeExperiment::UniformFragments, || {
            let index = ExpressionIndex::new(program.assertions());
            Plan::new(&index, &[]).sum_terms(index.roots[0].0).len()
        });
        with_native_experiment(NativeExperiment::CancelConstOffsets, || {
            let index = ExpressionIndex::new(program.assertions());
            assert_eq!(Plan::new(&index, &[]).sum_terms(index.roots[0].0).len(), baseline - 2);
            assert_rewrites_preserve_values(&program);
            let output = emit(program.assertions());
            assert!(!output.contains("Felt::from_u64(1)"), "{output}");
        });
    }

    #[test]
    fn inverse_offsets_preserve_shared_and_prepared_boundaries() {
        with_native_experiment(NativeExperiment::CancelConstOffsets, || {
            let inner = main(0) - Felt::ONE;
            let assertions = [Assertion::Base(inner.clone() + Felt::ONE), Assertion::Base(inner)];
            let index = ExpressionIndex::new(&assertions);
            assert!(!matches!(
                Plan::new(&index, &[]).rewrite(index.roots[0].0),
                Some(Rewrite::Alias(_))
            ));
            emit(&assertions);

            let value = main(1) + main(2);
            let assertions =
                [Assertion::Base((value.clone() - Felt::ONE) + Felt::ONE), Assertion::Base(value)];
            let index = ExpressionIndex::new(&assertions);
            // Cancellation must reuse this shared sum rather than opening it in
            // the fragment pass merely because its old parent was a region root.
            assert_eq!(Plan::new(&index, &[]).sum_terms(index.roots[0].0), vec![index.roots[1].0]);

            let assertions = [Assertion::Base((main(3) - Felt::ONE) + Felt::ONE)];
            let index = ExpressionIndex::new(&assertions);
            let root = index.roots[0].0;
            let inner = index.children(root)[0];
            // A preparation boundary is protected even with one source consumer.
            assert!(!matches!(Plan::new(&index, &[inner]).rewrite(root), Some(Rewrite::Alias(_))));
        });
    }

    #[test]
    fn inverse_offsets_retain_uniform_slots_and_builder_constant_rejections() {
        with_native_experiment(NativeExperiment::CancelConstOffsets, || {
            let prepared = (challenge(0) - Felt::ONE) + Felt::ONE;
            let assertions = [Assertion::Extension(prepared * E::from(main(0)))];
            let program = CapturedProgram::from_assertions(assertions.to_vec());
            let index = ExpressionIndex::new(program.assertions());
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.terms.len(), 1);
            assert_eq!(preparation.capacity(), 1);
            let output = emit(&assertions);
            assert!(output.contains("terms[0].dup()"), "{output}");
            assert!(!output.contains("Felt::from_u64(1)"), "{output}");
        });
    }

    #[test]
    #[should_panic(expected = "ext constant with non-base coefficients")]
    fn inverse_offsets_do_not_erase_unsupported_extension_constants() {
        with_native_experiment(NativeExperiment::CancelConstOffsets, || {
            let c = E::extension_constant(QuadFelt::new([Felt::ONE, Felt::ONE]));
            emit(&[Assertion::Extension((challenge(0) + c.clone()) - c)]);
        });
    }

    #[test]
    fn factor_runs_extract_contiguous_products_without_swallowing_dot_boundaries() {
        with_native_experiment(NativeExperiment::FactorRuns, || {
            let common = main(0);
            let values: [B; 11] = core::array::from_fn(|i| {
                if (4..7).contains(&i) {
                    common.clone() * main(i + 1)
                } else {
                    main(20 + i * 2) * main(21 + i * 2)
                }
            });
            let assertion = Assertion::Base(B::sum_array::<11>(&values));
            let program = CapturedProgram::from_assertions(vec![assertion]);
            let index = ExpressionIndex::new(program.assertions());
            let preparation = Preparation::new(&index);
            let plan = Plan::new(&index, &preparation.terms);
            let root = index.roots[0].0;
            let pieces = plan.sum_pieces(&plan.sum_terms(root), Class::Base);
            assert!(
                matches!(&pieces[..], [Piece::Dot { pairs: before, .. }, Piece::Factor { terms, .. }, Piece::Dot { pairs: after, .. }]
                if before.len() == 4 && terms.len() == 3 && after.len() == 4)
            );
            assert_rewrites_preserve_values(&program);
            let output = emit(program.assertions());
            assert_eq!(output.matches(" * ").count(), 1, "{output}");
        });
    }

    #[test]
    fn factor_runs_preserve_base_and_extension_operand_types_and_shared_products() {
        with_native_experiment(NativeExperiment::FactorRuns, || {
            let shared = challenge(0) * E::from(main(9));
            let base_residuals: [E; 3] = core::array::from_fn(|i| challenge(0) * E::from(main(i)));
            let aux = |column| E::from(AuxInput::Trace { row: RowOffset::Current, column });
            let extension_residuals: [E; 3] = core::array::from_fn(|i| E::from(main(3)) * aux(i));
            let homogeneous: [E; 3] = core::array::from_fn(|i| challenge(4) * aux(i));
            let assertions = [
                Assertion::Extension(E::sum_array::<3>(&base_residuals)),
                Assertion::Extension(E::sum_array::<3>(&extension_residuals)),
                Assertion::Extension(E::sum_array::<3>(&homogeneous)),
                Assertion::Extension(
                    shared.clone()
                        + challenge(0) * E::from(main(10))
                        + challenge(0) * E::from(main(11)),
                ),
                Assertion::Extension(shared),
            ];
            let output = emit(&assertions);
            assert!(!output.is_empty());
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            let plan = Plan::new(&index, &preparation.terms);
            for (root_index, expected) in [
                (0, (Class::Ext, Class::Base)),
                (1, (Class::Base, Class::Ext)),
                (2, (Class::Ext, Class::Ext)),
            ] {
                let root = index.roots[root_index].0;
                let pieces = plan.sum_pieces(&plan.sum_terms(root), Class::Ext);
                let [Piece::Factor { common, terms }] = &pieces[..] else {
                    panic!("expected typed factor run: {pieces:?}");
                };
                assert_eq!((index.value_class(*common), index.value_class(terms[0])), expected);
                assert_eq!(terms.len(), 3);
            }
            let root = index.roots[3].0;
            assert!(
                !plan
                    .sum_pieces(&plan.sum_terms(root), Class::Ext)
                    .iter()
                    .any(|piece| matches!(piece, Piece::Factor { .. }))
            );
        });
    }

    #[test]
    fn ring_operations_reemit_specialized_methods() {
        let x = main(0);
        let terms = [main(0), main(1), main(2), main(3)];
        let assertions = vec![
            Assertion::Base(x.square()),
            Assertion::Base(x.cube()),
            Assertion::Base(x.exp_u64(7)),
            Assertion::Base(x.exp_power_of_2(4)),
            Assertion::Base(x.double()),
            Assertion::Base(x.halve()),
            Assertion::Base(x.mul_2exp_u64(5)),
            Assertion::Base(x.div_2exp_u64(5)),
            Assertion::Base(x.bool_check()),
            Assertion::Base(B::sum_array::<4>(&terms)),
            Assertion::Base(terms.into_iter().product()),
        ];
        let output = emit(&assertions);
        for method in [
            ".square()",
            ".cube()",
            ".exp_const_u64::<7>()",
            ".exp_power_of_2(4)",
            ".double()",
            ".halve()",
            ".mul_2exp_u64(5)",
            ".div_2exp_u64(5)",
            ".bool_check()",
            "::sum_array::<4>",
            ".product::<AB::Expr>()",
        ] {
            assert!(output.contains(method), "missing {method}: {output}");
        }
    }

    #[test]
    fn linear_combinations_infer_scalar_types_and_batch_large_mixed_calls() {
        let values: [B; 4] = core::array::from_fn(main);
        let coefficients: [Felt; 4] = core::array::from_fn(|i| Felt::from_u64(i as u64 + 3));
        let ext_values: [E; 4] = core::array::from_fn(challenge);
        let long_values: [E; 17] = core::array::from_fn(|i| challenge(i % 4));
        let long_coefficients: [B; 17] = core::array::from_fn(main);
        let assertions = [
            Assertion::Base(B::dot_product(&values, &values)),
            Assertion::Base(<B as Algebra<Felt>>::mixed_dot_product(&values, &coefficients)),
            Assertion::Extension(<E as Algebra<B>>::mixed_dot_product(&ext_values, &values)),
            Assertion::Extension(<E as Algebra<B>>::batched_linear_combination(
                &long_values,
                &long_coefficients,
            )),
        ];
        let output = emit(&assertions);
        assert!(output.contains("AB::Expr::dot_product::<4>"), "{output}");
        assert!(
            output.contains("<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>"),
            "{output}"
        );
        assert!(
            output.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"),
            "{output}"
        );
        assert!(
            output.contains("<AB::ExtExpr as Algebra<AB::Expr>>::batched_linear_combination"),
            "{output}"
        );
    }

    #[test]
    fn equivalent_constant_spellings_share_native_arithmetic() {
        let scalar = Felt::from_u64(7);
        let x = main(0);
        let e = aux(0);
        let output = emit(&[
            Assertion::Base(x.dup() * scalar),
            Assertion::Base(x * B::from(scalar)),
            Assertion::Extension(e.dup() * scalar),
            Assertion::Extension(e.dup() * B::from(scalar)),
            Assertion::Extension(e.dup() * E::from(scalar)),
            Assertion::Extension(e * E::extension_constant(QuadFelt::from(scalar))),
        ]);
        assert_eq!(output.matches(" * Felt::from_u64(7)").count(), 1, "{output}");
        let base_assertions: Vec<_> =
            row(&output).lines().filter(|line| line.contains("builder.emit_base")).collect();
        assert_eq!(base_assertions.len(), 2);
        assert_eq!(base_assertions[0], base_assertions[1]);
        let ext_assertions: Vec<_> =
            row(&output).lines().filter(|line| line.contains("builder.emit_ext")).collect();
        assert_eq!(ext_assertions.len(), 4);
        assert!(ext_assertions.iter().all(|line| *line == ext_assertions[0]));
        assert!(!output.contains("<AB::ExtExpr as Algebra<Felt>>"), "{output}");
    }

    #[test]
    fn equivalent_linear_combination_coefficients_share_native_dispatch() {
        let values: [B; 4] = core::array::from_fn(main);
        let extension_values: [E; 4] = core::array::from_fn(aux);
        let coefficients = [7, 11, 13, 17].map(Felt::from_u64);
        let base_coefficients = coefficients.map(B::from);
        let extension_coefficients = coefficients.map(E::from);
        let output = emit(&[
            Assertion::Base(B::dot_product(&values, &base_coefficients)),
            Assertion::Base(<B as Algebra<Felt>>::mixed_dot_product(&values, &coefficients)),
            Assertion::Extension(E::dot_product(&extension_values, &extension_coefficients)),
            Assertion::Extension(<E as Algebra<B>>::mixed_dot_product(
                &extension_values,
                &base_coefficients,
            )),
            Assertion::Extension(<E as Algebra<Felt>>::mixed_dot_product(
                &extension_values,
                &coefficients,
            )),
        ]);
        assert_eq!(
            output.matches("<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>").count(),
            1,
            "{output}"
        );
        assert_eq!(
            output
                .matches("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>")
                .count(),
            1,
            "{output}"
        );
        assert!(!output.contains("<AB::ExtExpr as Algebra<Felt>>"), "{output}");
    }

    #[test]
    fn degree_zero_public_coefficients_remain_dynamic_expressions() {
        let values: [B; 4] = core::array::from_fn(main);
        let extension_values: [E; 4] = core::array::from_fn(aux);
        let coefficients: [B; 4] = core::array::from_fn(|index| BaseInput::Public { index }.into());
        let lifted_coefficients = coefficients.clone().map(E::from);
        let output = emit(&[
            Assertion::Base(B::dot_product(&values, &coefficients)),
            Assertion::Extension(E::dot_product(&extension_values, &lifted_coefficients)),
        ]);
        assert!(output.contains("AB::Expr::dot_product::<4>"), "{output}");
        assert!(
            output.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"),
            "{output}"
        );
        assert!(output.contains("inputs.public_values[0]"), "{output}");
        assert!(!output.contains("<AB::Expr as Algebra<Felt>>"), "{output}");
        assert!(!output.contains("<AB::ExtExpr as Algebra<Felt>>"), "{output}");
    }

    #[test]
    fn quadratic_default_expansion_retains_scalar_operations_with_symbolic_non_residue() {
        let [first, second] =
            <E as Algebra<B>>::quadratic_extension_square(&[challenge(0), challenge(1)], main(0));
        let output = emit(&[
            Assertion::Extension(first.dup()),
            Assertion::Extension(second),
            Assertion::Extension(first),
        ]);
        assert!(!output.contains("::quadratic_extension_square("), "{output}");
        assert_eq!(output.matches("::dot_product::<2>").count(), 1, "{output}");
        assert!(output.contains(".double()"), "{output}");
        let (_, row) = output.split_once("pub fn eval_fixture").unwrap();
        assert!(row.contains("::dot_product::<2>"), "{output}");
        assert_eq!(row.matches("builder.emit_ext").count(), 3);
    }

    #[test]
    fn quadratic_default_expansion_prepares_challenge_only_results() {
        let [first, second] = <E as Algebra<B>>::quadratic_extension_square(
            &[challenge(0), challenge(1)],
            B::from(Felt::from_u64(7)),
        );
        let output =
            emit(&[Assertion::Extension(first * main(0)), Assertion::Extension(second * main(1))]);
        let (preparation, row) = output.split_once("pub fn eval_fixture").unwrap();
        assert!(!output.contains("::quadratic_extension_square("), "{output}");
        assert_eq!(preparation.matches("::dot_product::<2>").count(), 1, "{output}");
        assert!(preparation.contains(".double()"), "{output}");
        assert!(!row.contains("::dot_product::<2>"), "{output}");
        assert!(!row.contains(".double()"), "{output}");
        assert!(row.contains("terms[0]"));
        assert!(row.contains("terms[1]"));
    }

    #[test]
    fn arithmetic_optimization_retains_explicit_sum_boundary() {
        let terms = [main(0), main(1), main(2), main(3)];
        let structured = B::sum_array::<4>(&terms);
        let output = emit(&[Assertion::Base(structured.dup() + structured)]);
        assert_eq!(output.matches("::sum_array::<4>").count(), 1, "{output}");
    }

    fn aux(index: usize) -> E {
        E::from(AuxInput::Trace { row: RowOffset::Current, column: index })
    }
    fn base_sum(terms: impl IntoIterator<Item = B>) -> B {
        terms.into_iter().reduce(|a, b| a + b).unwrap()
    }
    fn ext_sum(terms: impl IntoIterator<Item = E>) -> E {
        terms.into_iter().reduce(|a, b| a + b).unwrap()
    }
    fn row(output: &str) -> &str {
        output.split_once("pub fn eval_fixture").unwrap().1
    }

    #[test]
    fn preprocessed_inputs_and_assertion_order_use_the_production_emitter() {
        let preprocessed: B = BaseInput::Preprocessed { row: RowOffset::Next, column: 2 }.into();
        let output = emit(&[
            Assertion::Extension(aux(0)),
            Assertion::Base(preprocessed.dup()),
            Assertion::Extension(E::from(preprocessed)),
        ]);
        assert!(output.contains("let p0 = frame.preprocessed.current;"));
        assert!(output.contains("p1[2].dup()"));
        let methods: Vec<_> =
            row(&output).lines().filter(|line| line.contains("builder.emit_")).collect();
        assert_eq!(methods.len(), 3);
        assert!(methods[0].contains("emit_ext"));
        assert!(methods[1].contains("emit_base"));
        assert!(methods[2].contains("emit_ext(AB::ExtExpr::from("));
    }

    #[test]
    #[should_panic(expected = "ext constant with non-base coefficients")]
    fn extension_constants_unavailable_through_builder_bounds_are_rejected() {
        let value = QuadFelt::from_basis_coefficients_fn(|i| Felt::from_u64(i as u64 + 1));
        emit(&[Assertion::Extension(E::extension_constant(value))]);
    }

    #[test]
    fn scalar_arithmetic_recovers_square_and_field_scalings() {
        let x = main(0);
        let output = emit(&[
            Assertion::Base(x.dup() * x.dup()),
            Assertion::Base(x.dup() * Felt::from_u64(2)),
            Assertion::Base(x.dup() * Felt::from_u64(8)),
            Assertion::Base(x.dup() * Felt::from_u64(0x7fff_ffff_8000_0001)),
            Assertion::Base(B::from_u64(2) - x),
        ]);
        for method in [".square()", ".double()", ".mul_2exp_u64(3)", ".halve()"] {
            assert!(output.contains(method), "{output}");
        }
        assert!(output.contains("AB::Expr::from(Felt::from_u64(2)).dup() - "), "{output}");
    }

    #[test]
    fn small_signed_sums_emit_subtraction_without_negation_bindings() {
        for expression in [
            main(0) - main(1),
            -main(0) - main(1),
            main(0) - main(1) + main(2),
            main(0) - B::ONE,
        ] {
            let output = emit(&[Assertion::Base(expression)]);
            assert!(row(&output).contains(" - "), "{output}");
            assert!(!row(&output).contains("sum_array"), "{output}");
            assert!(
                !row(&output).lines().any(|line| {
                    line.contains(" = -") && !line.contains(" - ") && !line.contains(" + ")
                }),
                "single-use signs should stay in the sum: {output}"
            );
        }
        let output = emit(&[Assertion::Base(main(0) - B::ONE)]);
        assert!(row(&output).contains(" - Felt::from_u64(1)"), "{output}");
    }

    #[test]
    fn signed_sums_preserve_shared_negations_and_mixed_operand_types() {
        let negative = -main(0);
        let output = emit(&[Assertion::Base(negative.dup()), Assertion::Base(main(1) + negative)]);
        assert_eq!(row(&output).matches(" = -").count(), 1, "{output}");
        assert!(!row(&output).contains("sum_array"), "{output}");

        let output = emit(&[
            Assertion::Extension(aux(0) - main(0)),
            Assertion::Extension(E::from(main(0)) - aux(0)),
            Assertion::Extension(aux(1) + main(1)),
        ]);
        assert!(!row(&output).contains("sum_array"), "{output}");
        assert!(row(&output).contains(" - h"), "{output}");
        assert_eq!(row(&output).matches("AB::ExtExpr::from(").count(), 1, "{output}");
    }

    #[test]
    fn signed_product_regions_recover_typed_dots() {
        with_native_experiment(NativeExperiment::SignedDots, || {
            let scalar = base_sum((0..4).map(|i| {
                let value = main(i) * Felt::from_u64(i as u64 + 7);
                if i % 2 == 0 { value } else { -value }
            }));
            let mixed = ext_sum((0..4).map(|i| {
                let value = aux(i) * main(i);
                if i % 2 == 0 { value } else { -value }
            }));
            let same = ext_sum((0..4).map(|i| {
                let value = aux(i) * aux(i + 4);
                if i % 2 == 0 { value } else { -value }
            }));
            let output = emit(&[
                Assertion::Base(scalar),
                Assertion::Extension(mixed),
                Assertion::Extension(same),
            ]);
            assert!(
                output.contains("<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>"),
                "{output}"
            );
            assert!(
                output.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"),
                "{output}"
            );
            assert!(output.contains("AB::ExtExpr::dot_product::<4>"), "{output}");
            assert!(output.contains("-Felt::from_u64("), "{output}");
            assert!(!row(&output).contains(" = -"), "{output}");
        });
    }

    #[test]
    fn scalar_sum_patterns_recover_homogeneous_scalar_and_mixed_dots() {
        let values: Vec<_> = (0..8).map(main).collect();
        let plain = base_sum(values[..4].iter().cloned());
        let dot = base_sum((0..4).map(|i| values[2 * i].dup() * values[2 * i + 1].dup()));
        let scalar = base_sum((0..4).map(|i| values[i].dup() * Felt::from_u64(i as u64 + 7)));
        let mixed = ext_sum((0..4).map(|i| aux(i) * values[i].dup()));
        let output = emit(&[
            Assertion::Base(plain),
            Assertion::Base(dot),
            Assertion::Base(scalar),
            Assertion::Extension(mixed),
        ]);
        for method in [
            "AB::Expr::sum_array::<4>",
            "AB::Expr::dot_product::<4>",
            "<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>",
            "<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>",
        ] {
            assert!(output.contains(method), "missing {method}: {output}");
        }
    }

    #[test]
    fn factoring_respects_shared_factors_and_assertion_roots() {
        let u = main(0) * main(0);
        let p = u.dup() * main(1);
        let q = main(2) * u;
        let output = emit(&[Assertion::Base(p.dup() + q.dup())]);
        assert!(output.contains(" * ("), "{output}");
        assert_eq!(output.matches(".square()").count(), 1, "{output}");
        assert!(!output.contains("dot_product"));

        let output = emit(&[Assertion::Base(p.dup()), Assertion::Base(p + q)]);
        assert!(!output.contains(" * ("), "asserted product must remain materialized: {output}");
        assert_eq!(row(&output).matches("builder.emit_base").count(), 2);
    }

    #[test]
    fn product_regions_after_a_prefix_still_form_dots() {
        let sum = base_sum(
            core::iter::once(main(0)).chain((0..4).map(|i| main(2 * i + 1) * main(2 * i + 2))),
        );
        let output = emit(&[Assertion::Base(sum)]);
        assert!(output.contains("AB::Expr::dot_product::<4>"), "{output}");
    }

    #[test]
    fn extension_patterns_keep_expression_coefficients_and_unit_terms() {
        let same = ext_sum((0..4).map(|i| aux(i) * aux(i + 4)));
        let mixed = ext_sum(core::iter::once(aux(0)).chain((1..4).map(|i| aux(i) * main(i))));
        let output = emit(&[Assertion::Extension(same), Assertion::Extension(mixed)]);
        assert!(output.contains("AB::ExtExpr::dot_product::<4>"), "{output}");
        assert!(
            output.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"),
            "{output}"
        );
        assert!(output.contains("AB::Expr::ONE"), "{output}");
        assert!(!output.contains("<AB::ExtExpr as Algebra<Felt>>"));
    }

    #[test]
    fn scalar_sum_arrays_are_bounded_and_shared_prefixes_stay_materialized() {
        let mut sum = main(0);
        let mut prefix = sum.dup();
        for i in 1..40 {
            sum += main(i);
            if i == 7 {
                prefix = sum.dup();
            }
        }
        let output =
            emit(&[Assertion::Base(sum), Assertion::Base(prefix.dup()), Assertion::Base(prefix)]);
        for n in 17..=40 {
            assert!(!output.contains(&format!("sum_array::<{n}>")), "{output}");
        }
        let assertions: Vec<_> =
            row(&output).lines().filter(|line| line.contains("builder.emit_base")).collect();
        assert_eq!(assertions.len(), 3);
        assert_eq!(assertions[1], assertions[2], "shared assertion roots must reuse the binding");
    }

    #[test]
    fn long_flat_product_sums_keep_dot_arrays_bounded() {
        let output =
            emit(&[Assertion::Base(base_sum((0..40).map(|i| main(2 * i) * main(2 * i + 1))))]);
        assert!(output.contains("dot_product::<16>"), "{output}");
        let row = row(&output);
        assert!(
            row.find("dot_product::<16>").unwrap() < row.find("m0[32]").unwrap(),
            "finish the first dot before loading the next chunk: {output}"
        );
        for n in 17..=40 {
            assert!(!output.contains(&format!("dot_product::<{n}>")), "{output}");
            assert!(!output.contains(&format!("sum_array::<{n}>")), "{output}");
        }
    }

    #[test]
    fn factoring_keeps_literal_scalars_and_cross_field_operands_typed() {
        let literal = main(0) * Felt::from_u64(7) + main(1) * Felt::from_u64(7);
        let output = emit(&[Assertion::Base(literal)]);
        assert!(output.contains(") * Felt::from_u64(7)"), "{output}");
        assert!(!output.contains("AB::Expr::from(Felt::from_u64(7))"), "{output}");

        let common_base = main(0);
        let base_factor = aux(0) * common_base.dup() + aux(1) * common_base;
        let common_ext = aux(2);
        let ext_factor = common_ext.dup() * main(1) + common_ext * main(2);
        let literal_factor = aux(3) * Felt::from_u64(7) + aux(4) * Felt::from_u64(7);
        let output = emit(&[
            Assertion::Extension(base_factor),
            Assertion::Extension(ext_factor),
            Assertion::Extension(literal_factor),
        ]);
        assert!(output.contains(") * h"), "base factor should stay a base expression: {output}");
        assert!(
            output.contains(" * ("),
            "extension factor should drive multiplication: {output}"
        );
        assert!(!output.contains("* Felt::from_u64(7)"), "{output}");
        assert!(output.contains("AB::Expr::from(Felt::from_u64(7))"), "{output}");
    }

    #[test]
    fn tiny_scalar_product_regions_keep_plain_arithmetic() {
        for n in [2, 3] {
            let cases = [
                Assertion::Base(base_sum((0..n).map(|i| main(i) * main(i + n)))),
                Assertion::Base(base_sum((0..n).map(|i| main(i) * Felt::from_u64(i as u64 + 7)))),
                Assertion::Extension(ext_sum((0..n).map(|i| aux(i) * aux(i + n)))),
                Assertion::Extension(ext_sum((0..n).map(|i| aux(i) * main(i)))),
            ];
            for assertion in cases {
                let output = emit(&[assertion]);
                assert!(!output.contains("dot_product"), "{n} terms: {output}");
            }
        }
    }

    #[test]
    fn public_and_export_extension_computations_are_prepared_once() {
        with_native_experiment(NativeExperiment::Uniform, || {
            let public: B = BaseInput::Public { index: 0 }.into();
            let export: E = AuxInput::Export { index: 0 }.into();
            let uniform = (export + E::from(public.square())).square();
            let output = emit(&[Assertion::Extension(aux(0) * uniform)]);
            let (preparation, rows) = output.split_once("pub fn eval_fixture").unwrap();
            assert!(preparation.contains("inputs.public_values[0]"), "{output}");
            assert!(preparation.contains("inputs.exports[0]"), "{output}");
            assert!(rows.contains("terms[0]"), "{output}");
            assert!(!rows.contains("inputs.public_values"), "{output}");
            assert!(!rows.contains("inputs.exports"), "{output}");
        });
    }

    #[test]
    fn base_uniform_coefficients_do_not_enter_extension_preparation_slots() {
        with_native_experiment(NativeExperiment::Uniform, || {
            let public: B = BaseInput::Public { index: 0 }.into();
            let output = emit(&[Assertion::Base(main(0) * public.square())]);
            assert!(output.contains("FIXTURE_PREPARED_TERMS: usize = 0"), "{output}");
            assert!(row(&output).contains("inputs.public_values[0]"), "{output}");
            assert!(!row(&output).contains("terms[0]"), "{output}");
        });
    }

    #[test]
    fn contiguous_row_sum_fragments_are_shared_without_source_nodes() {
        with_native_experiment(NativeExperiment::UniformFragments, || {
            let a = main(0);
            let b = main(1);
            let c = main(2);
            let first: B = [main(3), a.dup(), b.dup(), c.dup()].into_iter().sum();
            let second: B = [main(4), a, b, c].into_iter().sum();
            let assertions = vec![Assertion::Base(first), Assertion::Base(second)];
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.fragments.len(), 1);
            assert_eq!(preparation.fragments[0].inputs.len(), 3);
            assert!(preparation.fragments[0].slot.is_none());
            let output = emit(&assertions);
            assert_eq!(row(&output).matches("builder.emit_base").count(), 2, "{output}");
        });
    }

    #[test]
    fn a_uniform_segment_inside_a_flat_row_sum_is_prepared() {
        with_native_experiment(NativeExperiment::UniformFragments, || {
            let expression: E = [E::from(main(0)), challenge(0), challenge(1), E::from(main(1))]
                .into_iter()
                .sum();
            let assertions = vec![Assertion::Extension(expression)];
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.capacity(), 1);
            assert_eq!(preparation.fragments.len(), 1);
            assert_eq!(preparation.fragments[0].slot, Some(0));
            let output = emit(&assertions);
            assert!(row(&output).contains("terms[0]"), "{output}");
            assert!(!row(&output).contains("inputs.challenges"), "{output}");
        });
    }

    #[test]
    fn opposite_signed_fragments_are_not_aliased() {
        with_native_experiment(NativeExperiment::UniformFragments, || {
            let a = main(0);
            let b = main(1);
            let assertions = vec![
                Assertion::Base([main(2), a.dup(), b.dup()].into_iter().sum()),
                Assertion::Base([main(3), a, -b].into_iter().sum()),
            ];
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert!(preparation.fragments.is_empty());
            let _ = emit(&assertions);
        });
    }

    #[test]
    fn prepared_scalar_sums_and_products_are_not_recomputed_in_rows() {
        let sum = ext_sum(core::iter::once(challenge(0) + challenge(1)).chain((0..3).map(aux)));
        let products = ext_sum(
            core::iter::once(challenge(0) * challenge(1))
                .chain((0..3).map(|i| aux(2 * i + 3) * aux(2 * i + 4))),
        );
        let output = emit(&[Assertion::Extension(sum), Assertion::Extension(products)]);
        let row = row(&output);
        assert!(row.contains("terms[0]") && row.contains("terms[1]"), "{output}");
        assert!(!row.contains("inputs.challenges"), "{output}");
    }

    #[test]
    fn product_pairs_share_a_nested_gate_across_eighteen_ordered_assertions() {
        let transition = B::is_transition();
        let not_boundary = B::ONE - main(0);
        let assertions: Vec<_> = (1..=18)
            .map(|i| Assertion::Base(transition.dup() * (not_boundary.dup() * main(i))))
            .collect();
        let baseline =
            with_native_experiment(NativeExperiment::UniformFragments, || emit(&assertions));
        assert_eq!(row(&baseline).matches(" * ").count(), 36, "{baseline}");
        for mode in [NativeExperiment::ProductPairs, NativeExperiment::ProductSubsets] {
            let output = with_native_experiment(mode, || emit(&assertions));
            assert_eq!(row(&output).matches(" * ").count(), 19, "{output}");
            assert_eq!(row(&output).matches("builder.emit_base").count(), 18, "{output}");
            let columns: Vec<_> = row(&output)
                .lines()
                .filter_map(|line| line.split("m0[").nth(1))
                .map(|tail| tail.split(']').next().unwrap().parse::<usize>().unwrap())
                .collect();
            assert_eq!(columns, (0..=18).collect::<Vec<_>>(), "{output}");
        }
        assert_eq!(native_options().products, products::Mode::PAIRS);
    }

    #[test]
    fn product_subsets_grow_pairs_only_when_selected_reuse_remains_profitable() {
        let (a, b, c) = (main(0), main(1), main(2));
        let assertions = vec![
            Assertion::Base(((a.dup() * main(3)) * b.dup()) * c.dup()),
            Assertion::Base(((b.dup() * main(4)) * c.dup()) * a.dup()),
            Assertion::Base(((c * main(5)) * a) * b),
        ];
        let pairs = with_native_experiment(NativeExperiment::ProductPairs, || emit(&assertions));
        let subsets =
            with_native_experiment(NativeExperiment::ProductSubsets, || emit(&assertions));
        assert_eq!(row(&pairs).matches(" * ").count(), 7, "{pairs}");
        assert_eq!(row(&subsets).matches(" * ").count(), 5, "{subsets}");

        let (a, b, c) = (main(0), main(1), main(2));
        let overlapping = vec![
            Assertion::Base((a.dup() * b.dup()) * c.dup()),
            Assertion::Base((a.dup() * b) * main(3)),
            Assertion::Base((a * c) * main(4)),
        ];
        with_native_experiment(NativeExperiment::ProductPairs, || {
            let index = ExpressionIndex::new(&overlapping);
            let preparation = Preparation::new(&index);
            // a*b already exists and is shared. It remains an atom; the
            // overlapping, merely apparent a*c opportunity has only one use.
            assert!(preparation.products.fragments.is_empty());
            let _ = emit(&overlapping);
        });
    }

    #[test]
    fn product_pairs_preserve_shared_intermediates_and_repeated_factor_multiplicity() {
        let shared = main(0) * main(1);
        let assertions: Vec<_> = (2..5)
            .map(|i| Assertion::Base(B::is_transition() * (shared.dup() * main(i))))
            .collect();
        with_native_experiment(NativeExperiment::ProductPairs, || {
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            let shared_id = index
                .nodes
                .iter()
                .position(|node| node.expression.identity() == shared.as_ref().identity())
                .unwrap();
            assert_eq!(preparation.products.fragments.len(), 1);
            assert!(
                preparation.products.fragments[0]
                    .factors
                    .contains(&products::Factor::Source(shared_id))
            );
            assert!(preparation.products.replacements[shared_id].is_none());
            let output = emit(&assertions);
            assert_eq!(row(&output).matches(" * ").count(), 5, "{output}");
        });

        let x = main(0);
        let repeated = vec![
            Assertion::Base((main(1) * x.dup()) * x.dup()),
            Assertion::Base((main(2) * x.dup()) * x),
        ];
        let output = with_native_experiment(NativeExperiment::ProductPairs, || emit(&repeated));
        assert_eq!(row(&output).matches(".square()").count(), 1, "{output}");
        assert_eq!(row(&output).matches(" * ").count(), 2, "{output}");
    }

    #[test]
    fn product_pair_threshold_uses_actual_disjoint_occurrences() {
        let gate = B::is_transition();
        let a = main(0);
        let assertions = vec![
            Assertion::Base(gate.dup() * (main(1) * a.dup())),
            Assertion::Base(a * (main(2) * gate)),
        ];
        let pairs = with_native_experiment(NativeExperiment::ProductPairs, || emit(&assertions));
        let frequent =
            with_native_experiment(NativeExperiment::FrequentProductPairs, || emit(&assertions));
        assert_eq!(row(&pairs).matches(" * ").count(), 3, "{pairs}");
        assert_eq!(row(&frequent).matches(" * ").count(), 4, "{frequent}");
        let _ = std::panic::catch_unwind(|| {
            with_native_experiment(NativeExperiment::ProductSubsets, || panic!("restore products"));
        });
        assert_eq!(native_options().products, products::Mode::PAIRS);
    }

    #[test]
    fn product_pairs_do_not_count_products_already_consumed_by_dot_rewrites() {
        let (a, b) = (main(0), main(1));
        let terms = core::array::from_fn::<_, 4, _>(|i| (main(i + 2) * a.dup()) * b.dup());
        let assertions = [Assertion::Base(B::sum_array::<4>(&terms))];
        let baseline =
            with_native_experiment(NativeExperiment::UniformFragments, || emit(&assertions));
        assert!(row(&baseline).contains("::dot_product::<4>"), "{baseline}");
        with_native_experiment(NativeExperiment::ProductPairs, || {
            let index = ExpressionIndex::new(&assertions);
            assert!(Preparation::new(&index).products.fragments.is_empty());
            assert_eq!(emit(&assertions), baseline);
        });
    }

    #[test]
    fn product_pairs_keep_base_factors_narrow_and_extension_factors_in_extension_arithmetic() {
        let a = main(0);
        let b = main(1);
        let assertions = vec![
            Assertion::Extension((aux(0) * a.dup()) * b.dup()),
            Assertion::Extension((aux(1) * b) * a),
            Assertion::Base(B::ZERO),
            Assertion::Extension(E::ZERO),
        ];
        with_native_experiment(NativeExperiment::ProductPairs, || {
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.products.fragments.len(), 1);
            assert_eq!(preparation.products.fragments[0].class, Class::Base);
            let output = emit(&assertions);
            let classes: Vec<_> = row(&output)
                .lines()
                .filter(|line| line.contains("builder.emit_"))
                .map(|line| {
                    if line.contains("emit_base") {
                        Class::Base
                    } else {
                        Class::Ext
                    }
                })
                .collect();
            assert_eq!(classes, [Class::Ext, Class::Ext, Class::Base, Class::Ext]);
            let base_products = row(&output)
                .lines()
                .filter(|line| line.contains(": AB::Expr =") && line.contains(" * "))
                .count();
            assert_eq!(base_products, 1, "{output}");
        });
        let assertions = vec![
            Assertion::Extension((aux(0) * main(0)) * aux(1)),
            Assertion::Extension((aux(1) * main(1)) * aux(0)),
        ];
        with_native_experiment(NativeExperiment::ProductPairs, || {
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.products.fragments.len(), 1);
            assert_eq!(preparation.products.fragments[0].class, Class::Ext);
            let _ = emit(&assertions);
        });
    }

    #[test]
    fn product_pairs_preserve_preparation_and_structured_boundaries() {
        let uniform = challenge(0) * challenge(1);
        let assertions = vec![
            Assertion::Extension((aux(0) * uniform.dup()) * main(0)),
            Assertion::Extension((aux(1) * uniform) * main(0)),
        ];
        let output = with_native_experiment(NativeExperiment::ProductSubsets, || emit(&assertions));
        let rows = row(&output);
        assert!(rows.contains("terms[0]"), "{output}");
        assert!(!rows.contains("inputs.challenges"), "{output}");

        let structured: B = [main(0), main(1), main(2)].into_iter().product();
        let assertions = vec![
            Assertion::Base(B::is_transition() * (structured.dup() * main(3))),
            Assertion::Base(B::is_transition() * (structured * main(4))),
        ];
        let output = with_native_experiment(NativeExperiment::ProductSubsets, || emit(&assertions));
        assert_eq!(row(&output).matches(".product::<AB::Expr>()").count(), 1, "{output}");
    }

    #[test]
    fn a_new_uniform_product_pair_is_prepared_without_loading_challenges_in_rows() {
        let assertions = vec![
            Assertion::Extension((challenge(0) * aux(0)) * challenge(1)),
            Assertion::Extension((challenge(1) * aux(1)) * challenge(0)),
        ];
        with_native_experiment(NativeExperiment::ProductSubsets, || {
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.products.fragments.len(), 1);
            assert_eq!(preparation.products.fragments[0].slot, Some(0));
            assert_eq!(preparation.capacity(), 1);
            let output = emit(&assertions);
            assert!(!row(&output).contains("inputs.challenges"), "{output}");
            assert_eq!(row(&output).matches(" * ").count(), 2, "{output}");
        });
        let assertions = vec![
            Assertion::Extension(((challenge(0) * aux(0)) * challenge(1)) * challenge(2)),
            Assertion::Extension(((challenge(1) * aux(1)) * challenge(2)) * challenge(0)),
        ];
        with_native_experiment(NativeExperiment::ProductSubsets, || {
            let index = ExpressionIndex::new(&assertions);
            let preparation = Preparation::new(&index);
            assert_eq!(preparation.products.fragments.len(), 2);
            assert_eq!(preparation.products.fragments[0].slot, None);
            assert_eq!(preparation.products.fragments[1].slot, Some(0));
            assert_eq!(preparation.capacity(), 1);
            let output = emit(&assertions);
            assert!(!row(&output).contains("inputs.challenges"), "{output}");
        });
    }
}
