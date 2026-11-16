//! Rust-evaluator backend: emits a captured constraint graph as a flat,
//! builder-generic Rust module.
//!
//! Each evaluator memoizes node results and emits bindings at first use: leaves named `h{n}`
//! in first-use order, operations named `b{id}` (base) or `e{id}` (ext). Each constraint assertion
//! follows its root in the exact global order of the captured eval, preserving `ConstraintLayout`
//! and alpha assignment.
//!
//! Interleaving assertions with node bindings lets results die after their last use. Emitting all
//! assertions at the end would keep every constraint result live until then, increasing register
//! pressure. That layout caused register spills and slower proving in benchmarks on
//! register-starved and cache-contended targets.
//!
//! Emission is deterministic: the same graph always produces byte-identical
//! output (crate invariant 3).
//!
//! Frame elements are expressions duplicated into owned bindings. One native ABI uses the
//! shared preparation, global assertion scheduler and arithmetic specialization machinery.
//!
//! Class handling: base subexpressions stay in `AB::Expr` and are promoted to
//! `AB::ExtExpr` exactly where an ext op consumes them. Since the builder bound
//! does not name `EF`, only ext constants liftable from the base field can be
//! emitted (enforced at generation time).
//!
//! Challenge-only expressions can be prepared once and reused across row evaluations. Shared IR
//! analysis identifies their dependencies; a native preparation plan assigns cached results to
//! slots. Preparation and row emission consume that same plan.
//! [`emit_native_optimized_module`] also specializes single-use arithmetic while preserving cached
//! terms.

use std::fmt::Write as _;

use miden_core::Felt;
use miden_stark::air::native::AirDescriptor;

use self::preparation::PreparationPlan;
use crate::ir::{CapturedConstraints, Class, Graph, Leaf, Node, NodeId, OpKind};

mod plan;
mod preparation;

use plan::{Coefficient, DotKind, Piece, Plan, Rewrite};

/// One AIR to emit an evaluator function for.
struct GraphEvaluator<'a> {
    /// Suffix of the emitted function name (`eval_{name}`).
    name: &'a str,
    /// Label used in the function's doc comment, e.g. `MidenAir::CORE`.
    air_label: &'a str,
    graph: &'a Graph,
    constraints: &'a CapturedConstraints,
}

/// One native evaluator paired with the original descriptor from its authored capture.
///
/// Graph, roots and descriptor must come from the same canonical source capture. Cheap layout
/// and address checks catch accidental mismatches; they do not prove arbitrary code equivalence.
/// Never substitute a descriptor reconstructed by capturing optimized/generated execution.
pub struct AirEvaluator<'a> {
    pub name: &'a str,
    pub air_label: &'a str,
    pub graph: &'a Graph,
    pub constraints: &'a CapturedConstraints,
    pub descriptor: &'a AirDescriptor<Felt>,
}

/// Emit native frame/input/sink evaluators from canonical authored captures.
///
/// Each input carries its original checked descriptor. Evaluator and descriptor must come
/// from the same capture. Preparation, arithmetic specialization and global assertion order
/// share one plan. Non-base extension constants are not supported by this builder contract.
///
/// # Panics
///
/// Panics if roots, classes, global positions or input addresses disagree with their checked
/// source descriptor, or an emitted extension constant has a nonzero second coefficient.
pub fn emit_native_optimized_module(header: &str, evals: &[AirEvaluator<'_>]) -> String {
    let mut out = module_start(header);
    for eval in evals {
        validate_native(eval);
        let graph = GraphEvaluator {
            name: eval.name,
            air_label: eval.air_label,
            graph: eval.graph,
            constraints: eval.constraints,
        };
        emit_air(&graph, &mut out, true);
    }
    out
}

fn module_start(header: &str) -> String {
    let mut out = String::from(header);
    out.push_str(NATIVE_MODULE_IMPORTS);
    out.push_str("use p3_field::Algebra;\n");
    out
}

fn emit_air(eval: &GraphEvaluator<'_>, out: &mut String, optimized: bool) {
    let plan = PreparationPlan::new(eval.graph, eval.constraints);
    let terms = plan.terms();
    let mut preparation = Emitter::new(EmissionMode::Preparation(&plan));
    let values: Vec<_> = terms.iter().map(|&id| operand(&preparation.token(id))).collect();
    writeln!(
        out,
        "\npub const {}_PREPARED_TERMS: usize = {};",
        eval.name.to_ascii_uppercase(),
        terms.len()
    )
    .unwrap();
    writeln!(out, "\n/// Prepare the challenge-only expressions for `{}`.", eval.air_label)
        .unwrap();
    writeln!(out, "pub fn precompute_{}<B: Algebra<Felt>, E: Algebra<B>>(inputs: UniformInputs<'_, B, E>) -> [E; {}] {{", eval.name, terms.len()).unwrap();
    writeln!(out, "    let challenges = inputs.challenges;\n    let _ = challenges;").unwrap();
    for line in preparation.lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(out, "    [{}]\n}}", values.join(", ")).unwrap();

    emit_evaluator(eval, out, &plan, optimized);
}

fn validate_native(native: &AirEvaluator<'_>) {
    let eval = native;
    let layout = native.descriptor.analysis().layout();
    assert_eq!(
        eval.constraints.base_roots.len(),
        layout.base_indices().len(),
        "native base root count"
    );
    assert_eq!(
        eval.constraints.ext_roots.len(),
        layout.ext_indices().len(),
        "native extension root count"
    );
    assert_eq!(
        eval.constraints.base_global_indices.as_slice(),
        layout.base_indices(),
        "native base assertion positions"
    );
    assert_eq!(
        eval.constraints.ext_global_indices.as_slice(),
        layout.ext_indices(),
        "native extension assertion positions"
    );

    let mut pending: Vec<_> = eval
        .constraints
        .base_roots
        .iter()
        .chain(&eval.constraints.ext_roots)
        .copied()
        .collect();
    for &root in &eval.constraints.base_roots {
        assert!(root.index() < eval.graph.len(), "native base root outside graph");
        assert_eq!(eval.graph.class(root), Class::Base, "native base root class");
    }
    let spec = native.descriptor.spec();
    let mut seen = vec![false; eval.graph.len()];
    while let Some(id) = pending.pop() {
        assert!(id.index() < eval.graph.len(), "native operand outside graph");
        if core::mem::replace(&mut seen[id.index()], true) {
            continue;
        }
        match eval.graph.node(id) {
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

const NATIVE_MODULE_IMPORTS: &str = r"
use miden_core::Felt;
use miden_crypto::field::PrimeCharacteristicRing as _;
use miden_stark::air::native::{LiftedAirBuilder, Frame, Inputs, UniformInputs};
use p3_field::Dup as _;
";

const NATIVE_FN_PROLOGUE: &str = r"    let m0 = frame.main.current;
    let m1 = frame.main.next;
    let a0 = frame.aux.current;
    let a1 = frame.aux.next;
    let _ = (&m0, &m1, &a0, &a1, &inputs, &terms);";

const NATIVE_PREPROCESSED_PROLOGUE: &str = r"    let p0 = frame.preprocessed.current;
    let p1 = frame.preprocessed.next;
    let _ = (&p0, &p1);";

/// One emitted graph node: its class, representation, and identifier.
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

/// Every native operand already owns an expression; reuse it by Dup.
fn operand(t: &Token) -> String {
    format!("{}.dup()", t.code)
}

#[derive(Clone, Copy)]
enum EmissionMode<'g> {
    Preparation(&'g PreparationPlan<'g>),
    Row(&'g PreparationPlan<'g>),
}

impl<'g> EmissionMode<'g> {
    fn graph(self) -> &'g Graph {
        match self {
            Self::Preparation(plan) | Self::Row(plan) => plan.graph(),
        }
    }
}

struct Emitter<'g> {
    mode: EmissionMode<'g>,
    plan: Option<Plan<'g>>,
    /// Token per emitted node, memoized on first use.
    tokens: Vec<Option<Token>>,
    /// Emitted lines — node `let`s and constraint asserts, interleaved in
    /// evaluation order.
    lines: Vec<String>,
    /// Number of hoisted leaf `let`s so far, for `h{n}` naming.
    hoisted: usize,
}

impl<'g> Emitter<'g> {
    fn new(mode: EmissionMode<'g>) -> Self {
        Self {
            mode,
            plan: None,
            tokens: vec![None; mode.graph().len()],
            lines: Vec::new(),
            hoisted: 0,
        }
    }

    fn types(&self) -> ExprTypes {
        match self.mode {
            EmissionMode::Preparation(_) => ExprTypes { base: "B", ext: "E" },
            EmissionMode::Row(_) => ExprTypes { base: "AB::Expr", ext: "AB::ExtExpr" },
        }
    }

    /// Token for `id`, emitting the node — and, recursively, any children not
    /// yet emitted — at its first use.
    fn token(&mut self, id: NodeId) -> Token {
        if let Some(tok) = &self.tokens[id.index()] {
            return tok.clone();
        }
        if let EmissionMode::Row(plan) = self.mode
            && let Some(index) = plan.slot(id)
        {
            let tok = self.ext_leaf(format!("terms[{index}].dup()"));
            self.tokens[id.index()] = Some(tok.clone());
            return tok;
        }
        let tok = match self.mode.graph().node(id) {
            Node::Leaf(leaf) => self.leaf_token(leaf),
            Node::Op { class, op, x, y } => self.op_token(id, class, op, x, y),
        };
        self.tokens[id.index()] = Some(tok.clone());
        tok
    }

    /// Emit `let h{n} = expr;` — or `let h{n}: ty = expr;` when `ty` is given —
    /// with a fresh `h{n}` name that it returns.
    fn hoist(&mut self, ty: Option<&str>, expr: String) -> String {
        let name = format!("h{}", self.hoisted);
        self.hoisted += 1;
        match ty {
            Some(ty) => self.lines.push(format!("    let {name}: {ty} = {expr};")),
            None => self.lines.push(format!("    let {name} = {expr};")),
        }
        name
    }

    /// A materialized base `Expr` leaf.
    fn base_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Base,
            code: self.hoist(Some(self.types().base), expr),
        }
    }

    /// A materialized extension expression leaf.
    fn ext_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Ext,
            code: self.hoist(Some(self.types().ext), expr),
        }
    }

    fn leaf_token(&mut self, leaf: Leaf) -> Token {
        if matches!(self.mode, EmissionMode::Row(_)) {
            // Native rows already contain expressions. Materialize them by Dup so no borrowed
            // input element is moved or accidentally treated as a Copy upstream variable.
            match leaf {
                Leaf::Preprocessed { offset, index } => {
                    return self.base_leaf(format!("p{offset}[{index}].dup()"));
                },
                Leaf::Main { offset, index } => {
                    return self.base_leaf(format!("m{offset}[{index}].dup()"));
                },
                Leaf::Aux { offset, index } => {
                    return self.ext_leaf(format!("a{offset}[{index}].dup()"));
                },
                Leaf::Public(index) => {
                    return self.base_leaf(format!("inputs.public_values[{index}].dup()"));
                },
                Leaf::Periodic(index) => {
                    return self.base_leaf(format!("frame.periodic[{index}].dup()"));
                },
                Leaf::IsFirst => return self.base_leaf("frame.first_row()".to_string()),
                Leaf::IsLast => return self.base_leaf("frame.last_row()".to_string()),
                Leaf::IsTransition => return self.base_leaf("frame.transition()".to_string()),
                Leaf::Challenge(index) => {
                    return self.ext_leaf(format!("inputs.challenges[{index}].dup()"));
                },
                Leaf::PermValue(index) => {
                    return self.ext_leaf(format!("inputs.exports[{index}].dup()"));
                },
                Leaf::BaseConst(_) | Leaf::ExtConst(_) | Leaf::ExtBase(_) => (),
            }
        }
        match leaf {
            Leaf::Preprocessed { .. }
            | Leaf::Main { .. }
            | Leaf::Public(_)
            | Leaf::Periodic(_)
            | Leaf::IsFirst
            | Leaf::IsLast
            | Leaf::IsTransition
            | Leaf::Aux { .. }
            | Leaf::PermValue(_) => unreachable!("row-dependent leaf in preparation"),
            Leaf::BaseConst(raw) => {
                if matches!(self.mode, EmissionMode::Preparation(_)) {
                    self.base_leaf(format!("B::from_u64({raw})"))
                } else {
                    self.base_leaf(format!("AB::Expr::from(Felt::from_u64({raw}))"))
                }
            },
            Leaf::Challenge(index) => self.ext_leaf(format!("challenges[{index}].dup()")),
            Leaf::ExtConst([c0, c1]) => {
                // The builder bound does not name EF, so only constants liftable
                // from the base field can be emitted.
                assert_eq!(c1, 0, "ext constant with non-base coefficients");
                if matches!(self.mode, EmissionMode::Preparation(_)) {
                    self.ext_leaf(format!("E::from(B::from_u64({c0}))"))
                } else {
                    let types = self.types();
                    self.ext_leaf(format!(
                        "{}::from({}::from(Felt::from_u64({c0})))",
                        types.ext, types.base
                    ))
                }
            },
            Leaf::ExtBase(inner) => self.token(inner),
        }
    }

    fn op_token(
        &mut self,
        id: NodeId,
        class: Class,
        op: OpKind,
        x: NodeId,
        y: Option<NodeId>,
    ) -> Token {
        if let Some(rewrite) = self.plan.as_ref().and_then(|p| p.rewrite(id)) {
            let rhs = self.rewrite_rhs(class, rewrite);
            return self.bind_op(id, class, rhs);
        }
        let xt = self.token(x);
        let yt = y.map(|y| self.token(y));
        let types = self.types();
        let rhs = match class {
            Class::Base => match &yt {
                None => format!("-{}", operand(&xt)),
                Some(yt) => format!("{} {} {}", operand(&xt), sym(op), operand(yt)),
            },
            Class::Ext => match &yt {
                None => match xt.class {
                    Class::Ext => format!("-{}", operand(&xt)),
                    Class::Base => format!("-{}", lift_base_to_ext(&xt, types)),
                },
                Some(yt) => match (xt.class, yt.class) {
                    // The ext operand drives; the other side is rendered as an
                    // `Expr` in its own class (`AB::ExtExpr: Algebra<AB::Expr>`
                    // consumes a base `Expr`).
                    (Class::Ext, _) => format!("{} {} {}", operand(&xt), sym(op), operand(yt)),
                    // Commutative ops flip so the ext operand drives the
                    // mixed-op impl; subtraction promotes the base operand.
                    (Class::Base, Class::Ext) if op != OpKind::Sub => {
                        format!("{} {} {}", operand(yt), sym(op), operand(&xt))
                    },
                    (Class::Base, _) => {
                        format!("{} {} {}", lift_base_to_ext(&xt, types), sym(op), operand(yt))
                    },
                },
            },
        };
        self.bind_op(id, class, rhs)
    }
    fn bind_op(&mut self, id: NodeId, class: Class, rhs: String) -> Token {
        let prefix = match class {
            Class::Base => 'b',
            Class::Ext => 'e',
        };
        self.lines.push(format!("    let {prefix}{} = {rhs};", id.index()));
        Token {
            class,
            code: format!("{prefix}{}", id.index()),
        }
    }

    fn expr(&mut self, id: NodeId, class: Class) -> String {
        let token = self.token(id);
        if class == Class::Ext && token.class == Class::Base {
            lift_base_to_ext(&token, self.types())
        } else {
            operand(&token)
        }
    }

    fn rewrite_rhs(&mut self, class: Class, rewrite: Rewrite) -> String {
        let types = self.types();
        let ty = match class {
            Class::Base => types.base,
            Class::Ext => types.ext,
        };
        match rewrite {
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
                let factor = self.mode.graph().class(common);
                let sum = plan::join(self.mode.graph().class(left), self.mode.graph().class(right));
                let common = self.expr(common, factor);
                let left = self.expr(left, sum);
                let right = self.expr(right, sum);
                // `AB::ExtExpr: Algebra<AB::Expr>` takes a base factor on the right.
                if factor == Class::Base && sum == Class::Ext {
                    format!("({left} + {right}) * {common}")
                } else {
                    format!("{common} * ({left} + {right})")
                }
            },
            Rewrite::Sum(pieces) => {
                let values: Vec<_> = pieces
                    .into_iter()
                    .map(|piece| match piece {
                        Piece::Node(id) => self.expr(id, class),
                        Piece::Dot { kind, pairs } => {
                            let n = pairs.len();
                            let values: Vec<_> =
                                pairs.iter().map(|&(id, _)| self.expr(id, class)).collect();
                            let coefficients: Vec<_> = pairs
                                .iter()
                                .map(|&(_, coefficient)| match coefficient {
                                    Coefficient::Scalar(c) => format!("Felt::from_u64({c})"),
                                    Coefficient::One => format!("{}::ONE", types.base),
                                    Coefficient::Node(id) => self.expr(
                                        id,
                                        if kind == DotKind::Mixed { Class::Base } else { class },
                                    ),
                                })
                                .collect();
                            let method = match kind {
                                DotKind::Same => format!("{ty}::dot_product::<{n}>"),
                                DotKind::Scalar => {
                                    format!("<{ty} as Algebra<Felt>>::mixed_dot_product::<{n}>")
                                },
                                DotKind::Mixed => {
                                    format!(
                                        "<{ty} as Algebra<{}>>::mixed_dot_product::<{n}>",
                                        types.base
                                    )
                                },
                            };
                            format!(
                                "{method}(&[{}], &[{}])",
                                values.join(", "),
                                coefficients.join(", ")
                            )
                        },
                    })
                    .collect();
                match values.len() {
                    1 => values[0].clone(),
                    2 | 3 => {
                        values.into_iter().map(|v| format!("({v})")).collect::<Vec<_>>().join(" + ")
                    },
                    n => format!("{ty}::sum_array::<{n}>(&[{}])", values.join(", ")),
                }
            },
        }
    }
}

/// Place a value at its global constraint index, validating range and
/// uniqueness. With every index placed exactly once, index density follows by
/// pigeonhole.
fn place<T>(slots: &mut [Option<T>], global: usize, value: T) {
    assert!(
        global < slots.len(),
        "global constraint index {global} out of range ({} constraints)",
        slots.len()
    );
    assert!(slots[global].is_none(), "duplicate global constraint index {global}");
    slots[global] = Some(value);
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

/// Append a row evaluator that loads the cached results selected by the preparation plan.
fn emit_evaluator(
    eval: &GraphEvaluator<'_>,
    out: &mut String,
    preparation: &PreparationPlan<'_>,
    optimized: bool,
) {
    // Order the constraint roots by global index; emission then walks them in
    // that order, so the asserts replay the hand-written eval's layout (and
    // alpha assignment) exactly.
    let cons = eval.constraints;
    let total = cons.base_roots.len() + cons.ext_roots.len();
    let mut roots: Vec<Option<(NodeId, bool)>> = vec![None; total];
    for (local, &global) in cons.base_global_indices.iter().enumerate() {
        place(&mut roots, global, (cons.base_roots[local], false));
    }
    for (local, &global) in cons.ext_global_indices.iter().enumerate() {
        place(&mut roots, global, (cons.ext_roots[local], true));
    }

    let mut e = Emitter::new(EmissionMode::Row(preparation));
    if optimized {
        e.plan = Some(Plan::new(eval.graph, cons, preparation.terms()));
    }
    for entry in roots {
        let (root, is_ext) = entry.expect("every global constraint index must be assigned");
        let t = e.token(root);
        let sink = "sink";
        let line = if is_ext {
            match t.class {
                Class::Ext => format!("    {sink}.assert_zero_ext({});", operand(&t)),
                Class::Base => {
                    format!("    {sink}.assert_zero_ext({});", lift_base_to_ext(&t, e.types()))
                },
            }
        } else {
            assert!(t.class == Class::Base, "base constraint root must be base-class");
            format!("    {sink}.assert_zero({});", operand(&t))
        };
        e.lines.push(line);
    }

    let term_count = preparation.terms().len();
    let schedule = if optimized {
        "with single-use arithmetic specialized at its first use."
    } else {
        "with each node's `let` placed at its first use."
    };
    let signature = format!(
        "pub fn eval_{}<AB: LiftedAirBuilder<F = Felt>>(frame: &Frame<'_, AB>, inputs: Inputs<'_, AB>, sink: &mut AB, terms: &[AB::ExtExpr; {term_count}]) {{",
        eval.name
    );
    writeln!(
        out,
        "\n/// Generated globally-CSE'd evaluator for `{}`.\n\
         ///\n\
         /// Emits constraints in the exact global order of the hand-written `eval`,\n\
         /// {schedule}\n\
         #[inline(never)]\n\
         {signature}",
        eval.air_label,
    )
    .unwrap();
    writeln!(out, "{}", NATIVE_FN_PROLOGUE).unwrap();
    if eval
        .graph
        .iter()
        .any(|(_, node)| matches!(node, Node::Leaf(Leaf::Preprocessed { .. })))
    {
        writeln!(out, "{}", NATIVE_PREPROCESSED_PROLOGUE).unwrap();
    }
    for line in &e.lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(out, "}}").unwrap();
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use miden_core::{Felt, field::QuadFelt};
    use miden_crypto::field::PrimeCharacteristicRing;
    use miden_stark::air::native;
    use p3_field::Dup;

    use super::*;
    use crate::{
        ir::{GraphBuilder, OpCounts},
        testing::eval_graph,
    };

    fn emit_graph_module(header: &str, evals: &[GraphEvaluator<'_>]) -> String {
        let mut out = module_start(header);
        for eval in evals {
            emit_air(eval, &mut out, false);
        }
        out
    }

    fn emit_graph_optimized(header: &str, evals: &[GraphEvaluator<'_>]) -> String {
        let mut out = module_start(header);
        for eval in evals {
            emit_air(eval, &mut out, true);
        }
        out
    }

    fn constraints(base: Vec<(NodeId, usize)>, ext: Vec<(NodeId, usize)>) -> CapturedConstraints {
        CapturedConstraints {
            base_roots: base.iter().map(|&(r, _)| r).collect(),
            ext_roots: ext.iter().map(|&(r, _)| r).collect(),
            base_global_indices: base.iter().map(|&(_, g)| g).collect(),
            ext_global_indices: ext.iter().map(|&(_, g)| g).collect(),
            naive_base: OpCounts::default(),
            naive_ext: OpCounts::default(),
        }
    }

    struct NativeRewrites;

    impl native::LiftedAir for NativeRewrites {
        type F = Felt;

        fn spec(&self) -> native::AirSpec<'_, Felt> {
            native::AirSpec {
                main_width: 4,
                aux_width: 4,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 0,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&[]),
            }
        }

        fn eval<B: native::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &native::Frame<'_, B>,
            _inputs: native::Inputs<'_, B>,
            sink: &mut B,
        ) {
            let sum: B::Expr = frame.main.current[..4].iter().map(Dup::dup).sum();
            sink.assert_zero(sum);
            let mixed: B::ExtExpr =
                (0..4).map(|i| frame.aux.current[i].dup() * frame.main.current[i].dup()).sum();
            sink.assert_zero_ext(mixed);
            sink.assert_zero(
                frame.main.current[0].dup() * frame.main.current[1].dup()
                    + frame.main.current[0].dup() * frame.main.current[2].dup(),
            );
        }
    }

    #[test]
    fn native_rendering_uses_the_shared_optimizer_with_owned_expression_leaves() {
        let mut shared = GraphBuilder::new();
        // Shared graphs may contain another AIR's inputs; native validation must inspect only
        // nodes reachable from this source's roots.
        shared.leaf(Leaf::Main { offset: 0, index: usize::MAX });
        let (cons, descriptor) =
            crate::ir::capture_native_into(&NativeRewrites, &mut shared).unwrap();
        let graph = shared.freeze();
        let out = emit_native_optimized_module(
            "//! Native renderer.\n",
            &[AirEvaluator {
                name: "rewrites",
                air_label: "NativeRewrites",
                graph: &graph,
                constraints: &cons,
                descriptor: &descriptor,
            }],
        );
        assert!(out.contains("pub const REWRITES_PREPARED_TERMS: usize = 0;"), "{out}");
        assert!(out.contains("AB::Expr::sum_array::<4>"), "{out}");
        assert!(out.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"));
        assert!(out.contains(" * ("), "factored products: {out}");
        for input in ["m0[0].dup()", "a0[0].dup()"] {
            assert!(out.contains(input), "missing native read {input}: {out}");
        }
        assert!(!out.contains("AB::ExprEF"));
        assert!(!out.contains("builder."));
        assert!(!out.contains("WindowAccess"));
        assert!(!out.contains(&format!("m0[{}]", usize::MAX)));
    }

    #[test]
    #[should_panic(expected = "native base assertion positions")]
    fn native_rendering_rejects_an_accidentally_mismatched_layout() {
        let (graph, mut cons, descriptor) = crate::ir::capture_native(&NativeRewrites).unwrap();
        cons.base_global_indices.swap(0, 1);
        emit_native_optimized_module(
            "",
            &[AirEvaluator {
                name: "mismatch",
                air_label: "Mismatch",
                graph: &graph,
                constraints: &cons,
                descriptor: &descriptor,
            }],
        );
    }

    #[test]
    fn native_base_liftable_extension_constant_uses_the_native_type() {
        let output = render_native_extension_constant(0);
        assert!(
            output.contains("AB::ExtExpr::from(AB::Expr::from(Felt::from_u64(1)))"),
            "{output}"
        );
        assert!(!output.contains("AB::ExprEF"));
    }

    #[test]
    #[should_panic(expected = "ext constant with non-base coefficients")]
    fn native_rendering_keeps_the_nonbase_extension_constant_rejection() {
        render_native_extension_constant(2);
    }

    fn render_native_extension_constant(second_coefficient: u64) -> String {
        let mut builder = GraphBuilder::new();
        let (cons, descriptor) =
            crate::ir::capture_native_into_with(&NativeRewrites, &mut builder, |_, _, sink| {
                native::LiftedAirBuilder::assert_zero_ext(
                    sink,
                    native::symbolic::SymbolicExpressionExt::<Felt, QuadFelt>::from(QuadFelt::new(
                        [Felt::ONE, Felt::from_u64(second_coefficient)],
                    )),
                );
            })
            .unwrap();
        let graph = builder.freeze();
        emit_native_optimized_module(
            "",
            &[AirEvaluator {
                name: "nonbase",
                air_label: "Nonbase",
                graph: &graph,
                constraints: &cons,
                descriptor: &descriptor,
            }],
        )
    }

    #[test]
    fn preprocessed_rows_are_borrowed_before_assertions() {
        let mut builder = GraphBuilder::new();
        let preprocessed = builder.leaf(Leaf::Preprocessed { offset: 0, index: 0 });
        let graph = builder.freeze();
        let constraints = constraints(vec![(preprocessed, 0)], vec![]);
        let out = emit_graph_module(
            "//! Test module.\n",
            &[GraphEvaluator {
                name: "preprocessed_mock",
                air_label: "MockAir::PREPROCESSED",
                graph: &graph,
                constraints: &constraints,
            }],
        );

        assert!(out.contains("let p0 = frame.preprocessed.current;"));
        assert!(out.contains("p0[0].dup()"));
    }

    #[test]
    #[should_panic(expected = "duplicate global constraint index")]
    fn duplicate_global_index_is_rejected() {
        let mut b = GraphBuilder::new();
        let x = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let (r, _) = b.op(Class::Base, OpKind::Neg, x, None);
        let graph = b.freeze();
        let cons = constraints(vec![(r, 0), (r, 0)], vec![]);
        emit_graph_module(
            "//! h.\n",
            &[GraphEvaluator {
                name: "dup",
                air_label: "MockAir::DUP",
                graph: &graph,
                constraints: &cons,
            }],
        );
    }

    #[test]
    #[should_panic(expected = "ext constant with non-base coefficients")]
    fn ext_constant_outside_base_field_is_rejected() {
        let mut b = GraphBuilder::new();
        let c = b.leaf(Leaf::ExtConst([1, 2]));
        let graph = b.freeze();
        let cons = constraints(vec![], vec![(c, 0)]);
        emit_graph_module(
            "//! h.\n",
            &[GraphEvaluator {
                name: "bad",
                air_label: "MockAir::BAD",
                graph: &graph,
                constraints: &cons,
            }],
        );
    }
    /// Value of a planned rewrite. Scalar multiplications use the specialized
    /// field methods that the emitted source calls.
    fn eval_rewrite(values: &[QuadFelt], rewrite: &Rewrite) -> QuadFelt {
        let value = |id: NodeId| values[id.index()];
        let scalar = |c: u64| QuadFelt::from(Felt::from_u64(c));
        match rewrite {
            Rewrite::Square(x) => value(*x).square(),
            Rewrite::Scalar { value: x, scalar: c, op, reversed } => {
                let x = value(*x);
                match (op, *c) {
                    (OpKind::Mul, 2) => x.double(),
                    (OpKind::Mul, 0x7fff_ffff_8000_0001) => x.halve(),
                    (OpKind::Mul, c) if c.is_power_of_two() => {
                        x.mul_2exp_u64(c.trailing_zeros().into())
                    },
                    (OpKind::Mul, c) => x * scalar(c),
                    (OpKind::Add, c) => x + scalar(c),
                    (OpKind::Sub, c) if *reversed => scalar(c) - x,
                    (OpKind::Sub, c) => x - scalar(c),
                    (OpKind::Neg, _) => unreachable!("scalar rewrites are binary"),
                }
            },
            Rewrite::Factor { common, scalar: c, left, right } => {
                c.map_or(value(*common), scalar) * (value(*left) + value(*right))
            },
            Rewrite::Sum(pieces) => pieces
                .iter()
                .map(|piece| match piece {
                    Piece::Node(id) => value(*id),
                    Piece::Dot { pairs, .. } => pairs
                        .iter()
                        .map(|&(id, coefficient)| {
                            value(id)
                                * match coefficient {
                                    Coefficient::Node(c) => value(c),
                                    Coefficient::Scalar(c) => scalar(c),
                                    Coefficient::One => QuadFelt::ONE,
                                }
                        })
                        .sum(),
                })
                .sum(),
        }
    }

    /// Every planned rewrite must evaluate to the value of the node it replaces.
    fn assert_rewrites_preserve_values(graph: &Graph, cons: &CapturedConstraints) {
        let plan = Plan::new(graph, cons, &[]);
        for seed in [0x243f6a8885a308d3, 0x13198a2e03707344] {
            let values = eval_graph(graph, seed);
            for (id, _) in graph.iter() {
                if let Some(rewrite) = plan.rewrite(id) {
                    assert_eq!(
                        eval_rewrite(&values, &rewrite),
                        values[id.index()],
                        "node {} rewritten as {rewrite:?} (seed {seed:#x})",
                        id.index(),
                    );
                }
            }
        }
    }

    fn optimized(b: GraphBuilder, base: Vec<NodeId>, ext: Vec<NodeId>) -> String {
        let graph = b.freeze();
        let cons = constraints(
            base.iter().enumerate().map(|(i, &r)| (r, i)).collect(),
            ext.iter().enumerate().map(|(i, &r)| (r, base.len() + i)).collect(),
        );
        assert_rewrites_preserve_values(&graph, &cons);
        let out = emit_graph_optimized(
            "//! Test.\n",
            &[GraphEvaluator {
                name: "optimized",
                air_label: "TEST",
                graph: &graph,
                constraints: &cons,
            }],
        );
        assert_eq!(
            out,
            emit_graph_optimized(
                "//! Test.\n",
                &[GraphEvaluator {
                    name: "optimized",
                    air_label: "TEST",
                    graph: &graph,
                    constraints: &cons,
                }],
            )
        );
        out
    }

    #[test]
    fn optimized_square_and_scalar_scaling() {
        let mut b = GraphBuilder::new();
        let x = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let (sq, _) = b.op(Class::Base, OpKind::Mul, x, Some(x));
        let two = b.leaf(Leaf::BaseConst(2));
        let eight = b.leaf(Leaf::BaseConst(8));
        let half = b.leaf(Leaf::BaseConst(0x7fff_ffff_8000_0001));
        let (double, _) = b.op(Class::Base, OpKind::Mul, two, Some(x));
        let (scale, _) = b.op(Class::Base, OpKind::Mul, x, Some(eight));
        let (halve, _) = b.op(Class::Base, OpKind::Mul, half, Some(x));
        let (sub, _) = b.op(Class::Base, OpKind::Sub, two, Some(x));
        let out = optimized(b, vec![sq, double, scale, halve, sub], vec![]);
        assert!(out.contains(".square()"), "{out}");
        assert!(out.contains(".double()"));
        assert!(out.contains(".mul_2exp_u64(3)"));
        assert!(out.contains(".halve()"));
        assert!(out.contains("-h0.dup() + Felt::from_u64(2)"), "{out}");
    }

    #[test]
    fn optimized_sum_and_typed_dots() {
        let mut b = GraphBuilder::new();
        let xs: Vec<_> = (0..8).map(|index| b.leaf(Leaf::Main { offset: 0, index })).collect();
        let left = b.op(Class::Base, OpKind::Add, xs[0], Some(xs[1])).0;
        let right = b.op(Class::Base, OpKind::Add, xs[2], Some(xs[3])).0;
        let sum = b.op(Class::Base, OpKind::Add, left, Some(right)).0;
        let products: Vec<_> = xs
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| b.op(Class::Base, OpKind::Mul, pair[0], Some(pair[1])).0)
            .collect();
        let dot = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Base, OpKind::Add, x, Some(y)).0)
            .unwrap();
        let mut lc = xs[0];
        for i in 1..4 {
            let coefficient = b.leaf(Leaf::BaseConst(7 + i as u64));
            let weighted = b.op(Class::Base, OpKind::Mul, coefficient, Some(xs[2 * i])).0;
            lc = b.op(Class::Base, OpKind::Add, lc, Some(weighted)).0;
        }
        let mut products = Vec::new();
        for i in 0..4 {
            let challenge = b.leaf(Leaf::Challenge(i));
            products.push(b.op(Class::Ext, OpKind::Mul, xs[4 + i], Some(challenge)).0);
        }
        let mixed = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Ext, OpKind::Add, x, Some(y)).0)
            .unwrap();
        let out = optimized(b, vec![sum, dot, lc], vec![mixed]);
        assert!(out.contains("AB::Expr::sum_array::<4>"), "{out}");
        assert!(out.contains("AB::Expr::dot_product::<4>"));
        assert!(out.contains("<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>"));
        assert!(out.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"));
        assert!(!out.contains("Algebra<Felt>>::mixed_dot_product::<4>(&[Into::<AB::ExtExpr>"));
    }

    #[test]
    fn optimized_factoring_respects_edges_and_assertion_roots() {
        let mut b = GraphBuilder::new();
        let input = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let u = b.op(Class::Base, OpKind::Mul, input, Some(input)).0;
        let a = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let p = b.op(Class::Base, OpKind::Mul, u, Some(a)).0;
        let q = b.op(Class::Base, OpKind::Mul, c, Some(u)).0;
        let factored = b.op(Class::Base, OpKind::Add, p, Some(q)).0;
        let out = optimized(b, vec![factored], vec![]);
        assert!(out.contains(" * ("), "{out}");
        assert!(!out.contains("dot_product"));
        assert_eq!(out.matches(".square()").count(), 1, "shared factor evaluated once");
        assert!(!out.contains(&format!("let b{} =", p.index())));
        assert!(!out.contains(&format!("let b{} =", q.index())));

        let mut b = GraphBuilder::new();
        let u = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let a = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let p = b.op(Class::Base, OpKind::Mul, u, Some(a)).0;
        let q = b.op(Class::Base, OpKind::Mul, c, Some(u)).0;
        let sum = b.op(Class::Base, OpKind::Add, p, Some(q)).0;
        // A constraint root is a use too: p must be computed once and retained.
        let out = optimized(b, vec![p, sum], vec![]);
        assert!(out.contains(&format!("let b{} =", p.index())));
        assert!(out.contains(&format!("b{}.dup() +", p.index())));
        assert!(!out.contains("dot_product"));
    }
    #[test]
    fn optimized_dots_recover_product_regions_after_a_prefix() {
        let mut b = GraphBuilder::new();
        let xs: Vec<_> = (0..9).map(|index| b.leaf(Leaf::Main { offset: 0, index })).collect();
        let products: Vec<_> = xs[1..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| b.op(Class::Base, OpKind::Mul, pair[0], Some(pair[1])).0)
            .collect();
        let mut sum = xs[0];
        for &product in &products {
            sum = b.op(Class::Base, OpKind::Add, sum, Some(product)).0;
        }
        let out = optimized(b, vec![sum], vec![]);
        assert!(out.contains("AB::Expr::dot_product::<4>"), "{out}");
        for product in products {
            assert!(!out.contains(&format!("let b{} =", product.index())));
        }
    }

    #[test]
    fn optimized_extension_dots_keep_coefficient_types() {
        let mut b = GraphBuilder::new();
        let es: Vec<_> = (0..8).map(|index| b.leaf(Leaf::Aux { offset: 0, index })).collect();
        let products: Vec<_> = (0..4)
            .map(|i| b.op(Class::Ext, OpKind::Mul, es[i], Some(es[4 + i])).0)
            .collect();
        let sum = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Ext, OpKind::Add, x, Some(y)).0)
            .unwrap();
        let mut mixed = es[0];
        for (i, &value) in es.iter().enumerate().take(4).skip(1) {
            let base = b.leaf(Leaf::Main { offset: 0, index: i - 1 });
            let lift = b.leaf(Leaf::ExtBase(base));
            let weighted = b.op(Class::Ext, OpKind::Mul, lift, Some(value)).0;
            mixed = b.op(Class::Ext, OpKind::Add, mixed, Some(weighted)).0;
        }
        let out = optimized(b, vec![], vec![sum, mixed]);
        assert!(out.contains("AB::ExtExpr::dot_product::<4>"), "{out}");
        assert!(out.contains("<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>"));
        assert!(out.contains("AB::Expr::ONE"));
        assert!(!out.contains("Algebra<Felt>"));
    }

    #[test]
    fn optimized_sums_bound_arrays_and_keep_shared_prefixes() {
        let mut b = GraphBuilder::new();
        let xs: Vec<_> = (0..40).map(|index| b.leaf(Leaf::Main { offset: 0, index })).collect();
        let mut sum = xs[0];
        let mut shared = xs[0];
        for (i, &x) in xs.iter().enumerate().skip(1) {
            sum = b.op(Class::Base, OpKind::Add, sum, Some(x)).0;
            if i == 7 {
                shared = sum;
            }
        }
        let out = optimized(b, vec![sum, shared, shared], vec![]);
        assert!(out.contains(&format!("let b{} =", shared.index())));
        assert_eq!(out.matches(&format!("assert_zero(b{}.dup())", shared.index())).count(), 2);
        for n in 17..=40 {
            assert!(!out.contains(&format!("sum_array::<{n}>")), "{out}");
        }
    }

    #[test]
    fn optimized_factored_literal_coefficients_stay_scalar() {
        let mut b = GraphBuilder::new();
        let c = b.leaf(Leaf::BaseConst(7));
        let a = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let z = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let p = b.op(Class::Base, OpKind::Mul, c, Some(a)).0;
        let q = b.op(Class::Base, OpKind::Mul, c, Some(z)).0;
        let sum = b.op(Class::Base, OpKind::Add, p, Some(q)).0;
        let out = optimized(b, vec![sum], vec![]);
        assert!(out.contains(") * Felt::from_u64(7)"), "{out}");
        assert!(!out.contains("AB::Expr::from(Felt::from_u64(7))"));
    }

    #[test]
    fn optimized_factoring_spans_field_classes() {
        let mut b = GraphBuilder::new();
        // s*x + y*s: a base multiplicity shared by extension terms.
        let s = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let x = b.leaf(Leaf::PermValue(0));
        let y = b.leaf(Leaf::Aux { offset: 0, index: 0 });
        let p = b.op(Class::Ext, OpKind::Mul, s, Some(x)).0;
        let q = b.op(Class::Ext, OpKind::Mul, y, Some(s)).0;
        let base_factor = b.op(Class::Ext, OpKind::Add, p, Some(q)).0;
        // e*a + c*e: an extension factor shared by base terms.
        let e = b.leaf(Leaf::Challenge(1));
        let a = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let r = b.op(Class::Ext, OpKind::Mul, e, Some(a)).0;
        let t = b.op(Class::Ext, OpKind::Mul, c, Some(e)).0;
        let ext_factor = b.op(Class::Ext, OpKind::Add, r, Some(t)).0;
        // All-base operands would factor to a base value for an extension node.
        let u = b.op(Class::Ext, OpKind::Mul, s, Some(a)).0;
        let v = b.op(Class::Ext, OpKind::Mul, c, Some(s)).0;
        let base_only = b.op(Class::Ext, OpKind::Add, u, Some(v)).0;
        // `AB::ExtExpr` has no `Felt` product, so a literal factor stays an `AB::Expr`.
        let seven = b.leaf(Leaf::BaseConst(7));
        let w = b.op(Class::Ext, OpKind::Mul, seven, Some(x)).0;
        let z = b.op(Class::Ext, OpKind::Mul, y, Some(seven)).0;
        let literal_factor = b.op(Class::Ext, OpKind::Add, w, Some(z)).0;
        let out = optimized(b, vec![], vec![base_factor, ext_factor, base_only, literal_factor]);
        assert!(
            out.contains(&format!(
                "let e{} = (h1.dup() + h2.dup()) * h0.dup();",
                base_factor.index()
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "let e{} = h3.dup() * (h4.dup() + h5.dup());",
                ext_factor.index()
            ))
        );
        assert!(out.contains(&format!(
            "let e{} = (h1.dup() + h2.dup()) * h6.dup();",
            literal_factor.index()
        )));
        assert!(!out.contains("* Felt::from_u64(7)"));
        for product in [p, q, r, t, w, z] {
            assert!(!out.contains(&format!("let e{} =", product.index())));
        }
        for product in [u, v] {
            assert!(out.contains(&format!("let e{} =", product.index())));
        }
    }

    #[test]
    fn optimized_tiny_dots_keep_plain_arithmetic() {
        // Array setup and coordinate gathers need enough terms to amortize
        // their cost, including on builders with lane-wise dot fallbacks.
        for n in [2, 3] {
            for kind in 0..4 {
                let mut b = GraphBuilder::new();
                let class = if kind < 2 { Class::Base } else { Class::Ext };
                let mut products = Vec::new();
                for i in 0..n {
                    let left = if class == Class::Base {
                        b.leaf(Leaf::Main { offset: 0, index: i })
                    } else {
                        b.leaf(Leaf::Challenge(i))
                    };
                    let right = match kind {
                        0 => b.leaf(Leaf::Main { offset: 0, index: n + i }),
                        1 => b.leaf(Leaf::BaseConst(7 + i as u64)),
                        2 => b.leaf(Leaf::Challenge(n + i)),
                        3 => b.leaf(Leaf::Main { offset: 0, index: i }),
                        _ => unreachable!(),
                    };
                    products.push(b.op(class, OpKind::Mul, left, Some(right)).0);
                }
                let sum = products
                    .iter()
                    .copied()
                    .reduce(|x, y| b.op(class, OpKind::Add, x, Some(y)).0)
                    .unwrap();
                let out = if class == Class::Base {
                    optimized(b, vec![sum], vec![])
                } else {
                    optimized(b, vec![], vec![sum])
                };
                assert!(!out.contains("dot_product"), "{n} terms, kind {kind}: {out}");
                let prefix = if class == Class::Base { 'b' } else { 'e' };
                for id in products {
                    assert!(out.contains(&format!("let {prefix}{} =", id.index())));
                }
            }
        }
    }
    #[test]
    fn optimized_rows_preserve_prepared_sums_and_products() {
        let mut b = GraphBuilder::new();
        let alpha = b.leaf(Leaf::Challenge(0));
        let beta = b.leaf(Leaf::Challenge(1));
        let aux: [_; 9] = core::array::from_fn(|index| b.leaf(Leaf::Aux { offset: 0, index }));
        let (mut sum, _) = b.op(Class::Ext, OpKind::Add, alpha, Some(beta));
        for value in &aux[..3] {
            (sum, _) = b.op(Class::Ext, OpKind::Add, sum, Some(*value));
        }
        let (mut products, _) = b.op(Class::Ext, OpKind::Mul, alpha, Some(beta));
        for pair in aux[3..].as_chunks::<2>().0 {
            let (product, _) = b.op(Class::Ext, OpKind::Mul, pair[0], Some(pair[1]));
            (products, _) = b.op(Class::Ext, OpKind::Add, products, Some(product));
        }
        let out = optimized(b, vec![], vec![sum, products]);
        let row = out.split("pub fn eval_optimized").nth(1).unwrap();
        assert!(row.contains("terms[0]") && row.contains("terms[1]"), "{row}");
        assert!(!row.contains("permutation_randomness"), "{row}");
    }
}
