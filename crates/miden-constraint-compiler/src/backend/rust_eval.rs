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
//! Representation: trace-window reads stay the builder's Copy `Var`/`VarEF`
//! rather than promoting to `Expr`, mirroring the hand-written eval and avoiding
//! an `Expr` materialization per trace cell on builders where the two differ.
//!
//! Class handling: base subexpressions stay in `AB::Expr` and are promoted to
//! `AB::ExprEF` exactly where an ext op consumes them. Since the builder bound
//! does not name `EF`, only ext constants liftable from the base field can be
//! emitted (enforced at generation time).
//!
//! Challenge-only expressions can be prepared once and reused across row evaluations. Shared IR
//! analysis identifies their dependencies; a native preparation plan assigns cached results to
//! slots. Preparation and row emission consume that same plan.
//! [`emit_optimized_module`] also specializes single-use arithmetic while preserving cached terms.

use std::fmt::Write as _;

use self::preparation::PreparationPlan;
use crate::ir::{CapturedConstraints, Class, Graph, Leaf, Node, NodeId, OpKind};

mod plan;
mod preparation;

use plan::{Coefficient, DotKind, Piece, Plan, Rewrite};

/// One AIR to emit an evaluator function for.
///
/// The graph and constraint roots must come from the same authored AIR capture.
pub struct AirEvaluator<'a> {
    /// Suffix of the emitted function name (`eval_{name}`).
    pub name: &'a str,
    /// Label used in the function's doc comment, e.g. `MidenAir::CORE`.
    pub air_label: &'a str,
    pub graph: &'a Graph,
    pub constraints: &'a CapturedConstraints,
}

/// Emit evaluators with a reusable preparation step for challenge-only expressions.
///
/// The module begins with `header` (a newline-terminated doc block) and imports, followed by
/// `precompute_{name}<B, E>` and `eval_{name}` for each AIR. Preparation reads only challenges
/// and constants. The evaluator requires terms prepared for the same AIR and challenge values.
///
/// # Panics
///
/// Panics for extension constants with non-base coefficients: the builder bound does not name
/// an extension field in which to construct them.
pub fn emit_module(header: &str, evals: &[AirEvaluator<'_>]) -> String {
    emit_module_with_plan(header, evals, false)
}

/// Emit prepared evaluators with typed arithmetic specializations.
///
/// Single-use products and sums may be fused or factored. Shared nodes, prepared terms, and
/// assertion metadata are preserved; the captured graph is unchanged.
pub fn emit_optimized_module(header: &str, evals: &[AirEvaluator<'_>]) -> String {
    emit_module_with_plan(header, evals, true)
}

fn emit_module_with_plan(header: &str, evals: &[AirEvaluator<'_>], optimized: bool) -> String {
    let mut out = String::from(header);
    out.push_str(MODULE_IMPORTS);
    out.push_str("use p3_field::Algebra;\n");
    for eval in evals {
        let plan = PreparationPlan::new(eval.graph, eval.constraints);
        let terms = plan.terms();
        let mut preparation = Emitter::new(EmissionMode::Preparation(&plan));
        let values: Vec<_> = terms
            .iter()
            .map(|&id| as_expr(&preparation.token(id), preparation.types()))
            .collect();
        writeln!(out, "\n/// Prepare the challenge-only expressions for `{}`.", eval.air_label)
            .unwrap();
        writeln!(out, "pub fn precompute_{}<B: PrimeCharacteristicRing, E: Algebra<B>>(challenges: &[E]) -> [E; {}] {{", eval.name, terms.len()).unwrap();
        writeln!(out, "    let _ = challenges;").unwrap();
        for line in preparation.lines {
            writeln!(out, "{line}").unwrap();
        }
        writeln!(out, "    [{}]\n}}", values.join(", ")).unwrap();

        emit_evaluator(eval, &mut out, &plan, optimized);
    }
    out
}

const MODULE_IMPORTS: &str = r"
use miden_core::Felt;
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air::{LiftedAirBuilder, WindowAccess};
use p3_field::Dup;
";

/// Opens every evaluator function: window handles over the main and aux trace
/// slices. `m1`/`a0`/`a1` may be unused by a given AIR, hence the `let _`.
const FN_PROLOGUE: &str = r"    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);";

const PREPROCESSED_PROLOGUE: &str = r"    let preprocessed = builder.preprocessed().clone();
    let p0 = preprocessed.current_slice();
    let p1 = preprocessed.next_slice();
    let _ = &p1;";

/// Whether a binding is a Copy builder `Var`/`VarEF` (a trace-window read) or a
/// materialized `Expr`/`ExprEF` (every op result and every non-trace leaf).
///
/// A `Var` reuses for free (Copy) and stays bare in base arithmetic; an `Expr`
/// is reused via `.dup()`. The [`operand`], [`as_expr`], and [`lift_base_to_ext`]
/// renderers turn a [`Token`] into source under this distinction.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repr {
    Var,
    Expr,
}

/// One emitted graph node: its class, representation, and identifier.
#[derive(Clone)]
struct Token {
    class: Class,
    repr: Repr,
    /// The emitted identifier — `h{n}` for a leaf, `b{id}`/`e{id}` for an op.
    code: String,
}

#[derive(Clone, Copy)]
struct ExprTypes {
    base: &'static str,
    ext: &'static str,
}

/// Render an expression in its own field class, promoting trace variables where necessary.
/// Extension variables use `Into` because their builder contract does not require `From`.
fn as_expr(t: &Token, types: ExprTypes) -> String {
    match t.repr {
        Repr::Expr => format!("{}.dup()", t.code),
        Repr::Var => match t.class {
            Class::Base => format!("{}::from({})", types.base, t.code),
            Class::Ext => format!("Into::<{}>::into({})", types.ext, t.code),
        },
    }
}

/// Lift a base-class token into the extension expression type. Promote a base variable to a
/// base expression first; `Algebra` supplies both conversions.
fn lift_base_to_ext(t: &Token, types: ExprTypes) -> String {
    match t.repr {
        Repr::Expr => format!("{}::from({}.dup())", types.ext, t.code),
        Repr::Var => format!("{}::from({}::from({}))", types.ext, types.base, t.code),
    }
}

/// Render `t` as an operand that may stay a `Var`: bare when it is a Copy `Var`
/// leaf, else `.dup()`. Valid only where the consuming context accepts the `Var`
/// directly — base arithmetic, or `Into`-bounded sinks (`assert_zero`,
/// `assert_zero_ext`).
fn operand(t: &Token) -> String {
    match t.repr {
        Repr::Var => t.code.clone(),
        Repr::Expr => format!("{}.dup()", t.code),
    }
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
            EmissionMode::Row(_) => ExprTypes { base: "AB::Expr", ext: "AB::ExprEF" },
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
    /// with a fresh `h{n}` name that it returns. A `Var` leaf passes no `ty` so
    /// its type is inferred from the trace-window read and stays `Copy`.
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
            repr: Repr::Expr,
            code: self.hoist(Some(self.types().base), expr),
        }
    }

    /// A materialized ext `ExprEF` leaf.
    fn ext_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Ext,
            repr: Repr::Expr,
            code: self.hoist(Some(self.types().ext), expr),
        }
    }

    /// A Copy base `Var` leaf (a main trace-window read), bound bare.
    fn base_var_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Base,
            repr: Repr::Var,
            code: self.hoist(None, expr),
        }
    }

    /// A Copy ext `VarEF` leaf (an aux trace-window read), bound bare.
    fn ext_var_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Ext,
            repr: Repr::Var,
            code: self.hoist(None, expr),
        }
    }

    fn leaf_token(&mut self, leaf: Leaf) -> Token {
        match leaf {
            Leaf::Preprocessed { offset, index } => {
                self.base_var_leaf(format!("p{offset}[{index}]"))
            },
            Leaf::Main { offset, index } => self.base_var_leaf(format!("m{offset}[{index}]")),
            Leaf::Public(index) => {
                self.base_leaf(format!("builder.public_values()[{index}].into()"))
            },
            Leaf::Periodic(index) => {
                self.base_leaf(format!("builder.periodic_values()[{index}].into()"))
            },
            Leaf::IsFirst => self.base_leaf("builder.is_first_row()".to_string()),
            Leaf::IsLast => self.base_leaf("builder.is_last_row()".to_string()),
            Leaf::IsTransition => self.base_leaf("builder.is_transition()".to_string()),
            Leaf::BaseConst(raw) => {
                if matches!(self.mode, EmissionMode::Preparation(_)) {
                    self.base_leaf(format!("B::from_u64({raw})"))
                } else {
                    self.base_leaf(format!("AB::Expr::from(Felt::from_u64({raw}))"))
                }
            },
            Leaf::Aux { offset, index } => self.ext_var_leaf(format!("a{offset}[{index}]")),
            Leaf::Challenge(index) => {
                if matches!(self.mode, EmissionMode::Preparation(_)) {
                    self.ext_leaf(format!("challenges[{index}].dup()"))
                } else {
                    self.ext_leaf(format!("builder.permutation_randomness()[{index}].into()"))
                }
            },
            Leaf::PermValue(index) => {
                // PermutationVar is Clone-only (not Copy), so it cannot be kept as
                // a reusable Var; it stays a materialized ExprEF via `.clone().into()`.
                self.ext_leaf(format!("builder.permutation_values()[{index}].clone().into()"))
            },
            Leaf::ExtConst([c0, c1]) => {
                // The builder bound does not name EF, so only constants liftable
                // from the base field can be emitted.
                assert_eq!(
                    c1, 0,
                    "the builder bound cannot construct extension constants outside the base field"
                );
                if matches!(self.mode, EmissionMode::Preparation(_)) {
                    self.ext_leaf(format!("E::from(B::from_u64({c0}))"))
                } else {
                    self.ext_leaf(format!("AB::ExprEF::from(AB::Expr::from(Felt::from_u64({c0})))"))
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
                // `AB::Var` has no `Neg`, so a Var operand is promoted by `as_expr`.
                None => format!("-{}", as_expr(&xt, types)),
                // Base arithmetic accepts a `Var` on either side directly
                // (`AB::Var`'s own ops and `AB::Expr: Algebra<AB::Var>`), so
                // operands stay bare where they are Vars.
                Some(yt) => format!("{} {} {}", operand(&xt), sym(op), operand(yt)),
            },
            Class::Ext => match &yt {
                None => match xt.class {
                    Class::Ext => format!("-{}", as_expr(&xt, types)),
                    Class::Base => format!("-{}", lift_base_to_ext(&xt, types)),
                },
                Some(yt) => match (xt.class, yt.class) {
                    // The ext operand drives; the other side is rendered as an
                    // `Expr` in its own class (`AB::ExprEF: Algebra<AB::Expr>`
                    // consumes a base `Expr`).
                    (Class::Ext, _) => {
                        format!("{} {} {}", as_expr(&xt, types), sym(op), as_expr(yt, types))
                    },
                    // Commutative ops flip so the ext operand drives the
                    // mixed-op impl; subtraction promotes the base operand.
                    (Class::Base, Class::Ext) if op != OpKind::Sub => {
                        format!("{} {} {}", as_expr(yt, types), sym(op), as_expr(&xt, types))
                    },
                    (Class::Base, _) => {
                        format!(
                            "{} {} {}",
                            lift_base_to_ext(&xt, types),
                            sym(op),
                            as_expr(yt, types)
                        )
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
            repr: Repr::Expr,
            code: format!("{prefix}{}", id.index()),
        }
    }

    fn expr(&mut self, id: NodeId, class: Class) -> String {
        let token = self.token(id);
        if class == Class::Ext && token.class == Class::Base {
            lift_base_to_ext(&token, self.types())
        } else {
            as_expr(&token, self.types())
        }
    }

    fn rewrite_rhs(&mut self, class: Class, rewrite: Rewrite) -> String {
        let ty = match class {
            Class::Base => "AB::Expr",
            Class::Ext => "AB::ExprEF",
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
                // `AB::ExprEF: Algebra<AB::Expr>` takes a base factor on the right.
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
                                    Coefficient::One => "AB::Expr::ONE".to_string(),
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
                                    format!("<{ty} as Algebra<AB::Expr>>::mixed_dot_product::<{n}>")
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
    eval: &AirEvaluator<'_>,
    out: &mut String,
    preparation: &PreparationPlan<'_>,
    optimized: bool,
) {
    // Order the constraint roots by global index; emission then walks them in
    // that order, so the asserts replay the hand-written eval's layout (and
    // alpha assignment) exactly.
    let cons = eval.constraints;
    let mut roots: Vec<_> = cons
        .base_roots
        .iter()
        .zip(&cons.base_global_indices)
        .map(|(&root, &global)| (global, root, false))
        .chain(
            cons.ext_roots
                .iter()
                .zip(&cons.ext_global_indices)
                .map(|(&root, &global)| (global, root, true)),
        )
        .collect();
    roots.sort_unstable_by_key(|&(global, ..)| global);

    let mut e = Emitter::new(EmissionMode::Row(preparation));
    if optimized {
        e.plan = Some(Plan::new(eval.graph, cons, preparation.terms()));
    }
    for (_, root, is_ext) in roots {
        let t = e.token(root);
        let line = if is_ext {
            match t.class {
                Class::Ext => format!("    builder.assert_zero_ext({});", operand(&t)),
                Class::Base => {
                    format!("    builder.assert_zero_ext({});", lift_base_to_ext(&t, e.types()))
                },
            }
        } else {
            format!("    builder.assert_zero({});", operand(&t))
        };
        e.lines.push(line);
    }

    let term_count = preparation.terms().len();
    let schedule = if optimized {
        "with single-use arithmetic specialized at its first use."
    } else {
        "with each node's `let` placed at its first use."
    };
    writeln!(
        out,
        "\n/// Generated globally-CSE'd evaluator for `{}`.\n\
         ///\n\
         /// Emits constraints in the exact global order of the hand-written `eval`,\n\
         /// {schedule}\n\
         #[inline(never)]\n\
         pub fn eval_{}<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, terms: &[AB::ExprEF]) {{",
        eval.air_label, eval.name,
    )
    .unwrap();
    writeln!(out, "    assert_eq!(terms.len(), {term_count});").unwrap();
    writeln!(out, "{FN_PROLOGUE}").unwrap();
    if eval
        .graph
        .iter()
        .any(|(_, node)| matches!(node, Node::Leaf(Leaf::Preprocessed { .. })))
    {
        writeln!(out, "{PREPROCESSED_PROLOGUE}").unwrap();
    }
    for line in &e.lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(out, "}}").unwrap();
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, field::QuadFelt};
    use miden_crypto::field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        ir::{GraphBuilder, OpCounts},
        testing::eval_graph,
    };

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

    #[test]
    fn preprocessed_window_is_owned_before_assertions() {
        let mut builder = GraphBuilder::new();
        let preprocessed = builder.leaf(Leaf::Preprocessed { offset: 0, index: 0 });
        let graph = builder.freeze();
        let constraints = constraints(vec![(preprocessed, 0)], vec![]);
        let out = emit_module(
            "//! Test module.\n",
            &[AirEvaluator {
                name: "preprocessed_mock",
                air_label: "MockAir::PREPROCESSED",
                graph: &graph,
                constraints: &constraints,
            }],
        );

        assert!(out.contains("let preprocessed = builder.preprocessed().clone();"));
    }

    /// Base-class emission: every base leaf kind, each binary op, unary neg,
    /// leaf hoisting in first-use order, and assert replay in global (not local)
    /// constraint order.
    #[test]
    fn golden_base_evaluator() {
        let mut b = GraphBuilder::new();
        let cur = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let next = b.leaf(Leaf::Main { offset: 1, index: 0 });
        let diff = b.op(Class::Base, OpKind::Sub, next, Some(cur));
        let first = b.leaf(Leaf::IsFirst);
        let gated = b.op(Class::Base, OpKind::Mul, first, Some(diff));
        let neg = b.op(Class::Base, OpKind::Neg, gated, None);
        let public = b.leaf(Leaf::Public(2));
        let periodic = b.leaf(Leaf::Periodic(1));
        let sum = b.op(Class::Base, OpKind::Add, public, Some(periodic));
        let last = b.leaf(Leaf::IsLast);
        let transition = b.leaf(Leaf::IsTransition);
        let edges = b.op(Class::Base, OpKind::Mul, last, Some(transition));
        let three = b.leaf(Leaf::BaseConst(3));
        let offset = b.op(Class::Base, OpKind::Add, edges, Some(three));
        let graph = b.freeze();

        // Local order (neg, sum, offset) deliberately differs from global order
        // (sum, offset, neg): the emitted asserts must follow the global one.
        let cons = constraints(vec![(neg, 2), (sum, 0), (offset, 1)], vec![]);
        let evals = [AirEvaluator {
            name: "base_mock",
            air_label: "MockAir::BASE",
            graph: &graph,
            constraints: &cons,
        }];
        let out = emit_module("//! Golden test module.\n", &evals);
        assert_eq!(out, emit_module("//! Golden test module.\n", &evals), "must be deterministic");

        let expected = r"//! Golden test module.

use miden_core::Felt;
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air::{LiftedAirBuilder, WindowAccess};
use p3_field::Dup;
use p3_field::Algebra;

/// Prepare the challenge-only expressions for `MockAir::BASE`.
pub fn precompute_base_mock<B: PrimeCharacteristicRing, E: Algebra<B>>(challenges: &[E]) -> [E; 0] {
    let _ = challenges;
    []
}

/// Generated globally-CSE'd evaluator for `MockAir::BASE`.
///
/// Emits constraints in the exact global order of the hand-written `eval`,
/// with each node's `let` placed at its first use.
#[inline(never)]
pub fn eval_base_mock<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, terms: &[AB::ExprEF]) {
    assert_eq!(terms.len(), 0);
    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);
    let h0: AB::Expr = builder.public_values()[2].into();
    let h1: AB::Expr = builder.periodic_values()[1].into();
    let b8 = h0.dup() + h1.dup();
    builder.assert_zero(b8.dup());
    let h2: AB::Expr = builder.is_last_row();
    let h3: AB::Expr = builder.is_transition();
    let b11 = h2.dup() * h3.dup();
    let h4: AB::Expr = AB::Expr::from(Felt::from_u64(3));
    let b13 = b11.dup() + h4.dup();
    builder.assert_zero(b13.dup());
    let h5: AB::Expr = builder.is_first_row();
    let h6 = m1[0];
    let h7 = m0[0];
    let b2 = h6 - h7;
    let b4 = h5.dup() * b2.dup();
    let b5 = -b4.dup();
    builder.assert_zero(b5.dup());
}
";
        assert_eq!(out, expected);
    }

    /// Ext-class emission: ext leaf kinds, class promotion at every site an ext
    /// op consumes a base operand (commutative flip, subtraction, negation),
    /// `ExtBase` pass-through, and promotion of a base-class ext-constraint root
    /// at its assert.
    #[test]
    fn golden_ext_evaluator() {
        let mut b = GraphBuilder::new();
        let aux = b.leaf(Leaf::Aux { offset: 0, index: 0 });
        let alpha = b.leaf(Leaf::Challenge(0));
        let acc = b.op(Class::Ext, OpKind::Add, aux, Some(alpha));
        let main = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let lift = b.leaf(Leaf::ExtBase(main));
        let flip = b.op(Class::Ext, OpKind::Mul, lift, Some(acc));
        let sub_promote = b.op(Class::Ext, OpKind::Sub, lift, Some(acc));
        let sub_plain = b.op(Class::Ext, OpKind::Sub, acc, Some(lift));
        let neg_promote = b.op(Class::Ext, OpKind::Neg, lift, None);
        let seven = b.leaf(Leaf::ExtConst([7, 0]));
        let shifted = b.op(Class::Ext, OpKind::Add, sub_promote, Some(seven));
        let bound = b.leaf(Leaf::PermValue(0));
        let closed = b.op(Class::Ext, OpKind::Sub, shifted, Some(bound));
        let graph = b.freeze();

        let cons = constraints(
            vec![],
            vec![(flip, 0), (sub_plain, 1), (neg_promote, 2), (closed, 3), (lift, 4)],
        );
        let out = emit_module(
            "//! Golden test module.\n",
            &[AirEvaluator {
                name: "ext_mock",
                air_label: "MockAir::EXT",
                graph: &graph,
                constraints: &cons,
            }],
        );

        let body = r"pub fn eval_ext_mock<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, terms: &[AB::ExprEF]) {
    assert_eq!(terms.len(), 0);
    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);
    let h0 = m0[1];
    let h1 = a0[0];
    let h2: AB::ExprEF = builder.permutation_randomness()[0].into();
    let e2 = Into::<AB::ExprEF>::into(h1) + h2.dup();
    let e5 = e2.dup() * AB::Expr::from(h0);
    builder.assert_zero_ext(e5.dup());
    let e7 = e2.dup() - AB::Expr::from(h0);
    builder.assert_zero_ext(e7.dup());
    let e8 = -AB::ExprEF::from(AB::Expr::from(h0));
    builder.assert_zero_ext(e8.dup());
    let e6 = AB::ExprEF::from(AB::Expr::from(h0)) - e2.dup();
    let h3: AB::ExprEF = AB::ExprEF::from(AB::Expr::from(Felt::from_u64(7)));
    let e10 = e6.dup() + h3.dup();
    let h4: AB::ExprEF = builder.permutation_values()[0].clone().into();
    let e12 = e10.dup() - h4.dup();
    builder.assert_zero_ext(e12.dup());
    builder.assert_zero_ext(AB::ExprEF::from(AB::Expr::from(h0)));
}
";
        // The module wrapper (header + imports) is pinned by the base golden;
        // compare only the emitted function here.
        let signature = "pub fn eval_ext_mock";
        let (_, tail) = out.split_once(signature).expect("prepared evaluator emitted");
        let tail = format!("{signature}{tail}");
        assert_eq!(tail, body);
    }

    #[test]
    #[should_panic(
        expected = "the builder bound cannot construct extension constants outside the base field"
    )]
    fn ext_constant_outside_base_field_is_rejected() {
        let mut b = GraphBuilder::new();
        let c = b.leaf(Leaf::ExtConst([1, 2]));
        let graph = b.freeze();
        let cons = constraints(vec![], vec![(c, 0)]);
        emit_module(
            "//! h.\n",
            &[AirEvaluator {
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
        let out = emit_optimized_module(
            "//! Test.\n",
            &[AirEvaluator {
                name: "optimized",
                air_label: "TEST",
                graph: &graph,
                constraints: &cons,
            }],
        );
        assert_eq!(
            out,
            emit_optimized_module(
                "//! Test.\n",
                &[AirEvaluator {
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
        let sq = b.op(Class::Base, OpKind::Mul, x, Some(x));
        let two = b.leaf(Leaf::BaseConst(2));
        let eight = b.leaf(Leaf::BaseConst(8));
        let half = b.leaf(Leaf::BaseConst(0x7fff_ffff_8000_0001));
        let double = b.op(Class::Base, OpKind::Mul, two, Some(x));
        let scale = b.op(Class::Base, OpKind::Mul, x, Some(eight));
        let halve = b.op(Class::Base, OpKind::Mul, half, Some(x));
        let sub = b.op(Class::Base, OpKind::Sub, two, Some(x));
        let out = optimized(b, vec![sq, double, scale, halve, sub], vec![]);
        assert!(out.contains(".square()"), "{out}");
        assert!(out.contains(".double()"));
        assert!(out.contains(".mul_2exp_u64(3)"));
        assert!(out.contains(".halve()"));
        assert!(out.contains("-AB::Expr::from(h0) + Felt::from_u64(2)"), "{out}");
    }

    #[test]
    fn optimized_sum_and_typed_dots() {
        let mut b = GraphBuilder::new();
        let xs: Vec<_> = (0..8).map(|index| b.leaf(Leaf::Main { offset: 0, index })).collect();
        let left = b.op(Class::Base, OpKind::Add, xs[0], Some(xs[1]));
        let right = b.op(Class::Base, OpKind::Add, xs[2], Some(xs[3]));
        let sum = b.op(Class::Base, OpKind::Add, left, Some(right));
        let products: Vec<_> = xs
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| b.op(Class::Base, OpKind::Mul, pair[0], Some(pair[1])))
            .collect();
        let dot = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Base, OpKind::Add, x, Some(y)))
            .unwrap();
        let mut lc = xs[0];
        for i in 1..4 {
            let coefficient = b.leaf(Leaf::BaseConst(7 + i as u64));
            let weighted = b.op(Class::Base, OpKind::Mul, coefficient, Some(xs[2 * i]));
            lc = b.op(Class::Base, OpKind::Add, lc, Some(weighted));
        }
        let mut products = Vec::new();
        for i in 0..4 {
            let challenge = b.leaf(Leaf::Challenge(i));
            products.push(b.op(Class::Ext, OpKind::Mul, xs[4 + i], Some(challenge)));
        }
        let mixed = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Ext, OpKind::Add, x, Some(y)))
            .unwrap();
        let out = optimized(b, vec![sum, dot, lc], vec![mixed]);
        assert!(out.contains("AB::Expr::sum_array::<4>"), "{out}");
        assert!(out.contains("AB::Expr::dot_product::<4>"));
        assert!(out.contains("<AB::Expr as Algebra<Felt>>::mixed_dot_product::<4>"));
        assert!(out.contains("<AB::ExprEF as Algebra<AB::Expr>>::mixed_dot_product::<4>"));
        assert!(!out.contains("Algebra<Felt>>::mixed_dot_product::<4>(&[Into::<AB::ExprEF>"));
    }

    #[test]
    fn optimized_factoring_respects_edges_and_assertion_roots() {
        let mut b = GraphBuilder::new();
        let input = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let u = b.op(Class::Base, OpKind::Mul, input, Some(input));
        let a = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let p = b.op(Class::Base, OpKind::Mul, u, Some(a));
        let q = b.op(Class::Base, OpKind::Mul, c, Some(u));
        let factored = b.op(Class::Base, OpKind::Add, p, Some(q));
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
        let p = b.op(Class::Base, OpKind::Mul, u, Some(a));
        let q = b.op(Class::Base, OpKind::Mul, c, Some(u));
        let sum = b.op(Class::Base, OpKind::Add, p, Some(q));
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
            .map(|pair| b.op(Class::Base, OpKind::Mul, pair[0], Some(pair[1])))
            .collect();
        let mut sum = xs[0];
        for &product in &products {
            sum = b.op(Class::Base, OpKind::Add, sum, Some(product));
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
        let products: Vec<_> =
            (0..4).map(|i| b.op(Class::Ext, OpKind::Mul, es[i], Some(es[4 + i]))).collect();
        let sum = products
            .into_iter()
            .reduce(|x, y| b.op(Class::Ext, OpKind::Add, x, Some(y)))
            .unwrap();
        let mut mixed = es[0];
        for (i, &value) in es.iter().enumerate().take(4).skip(1) {
            let base = b.leaf(Leaf::Main { offset: 0, index: i - 1 });
            let lift = b.leaf(Leaf::ExtBase(base));
            let weighted = b.op(Class::Ext, OpKind::Mul, lift, Some(value));
            mixed = b.op(Class::Ext, OpKind::Add, mixed, Some(weighted));
        }
        let out = optimized(b, vec![], vec![sum, mixed]);
        assert!(out.contains("AB::ExprEF::dot_product::<4>"), "{out}");
        assert!(out.contains("<AB::ExprEF as Algebra<AB::Expr>>::mixed_dot_product::<4>"));
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
            sum = b.op(Class::Base, OpKind::Add, sum, Some(x));
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
        let p = b.op(Class::Base, OpKind::Mul, c, Some(a));
        let q = b.op(Class::Base, OpKind::Mul, c, Some(z));
        let sum = b.op(Class::Base, OpKind::Add, p, Some(q));
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
        let p = b.op(Class::Ext, OpKind::Mul, s, Some(x));
        let q = b.op(Class::Ext, OpKind::Mul, y, Some(s));
        let base_factor = b.op(Class::Ext, OpKind::Add, p, Some(q));
        // e*a + c*e: an extension factor shared by base terms.
        let e = b.leaf(Leaf::Challenge(1));
        let a = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let r = b.op(Class::Ext, OpKind::Mul, e, Some(a));
        let t = b.op(Class::Ext, OpKind::Mul, c, Some(e));
        let ext_factor = b.op(Class::Ext, OpKind::Add, r, Some(t));
        // All-base operands would factor to a base value for an extension node.
        let u = b.op(Class::Ext, OpKind::Mul, s, Some(a));
        let v = b.op(Class::Ext, OpKind::Mul, c, Some(s));
        let base_only = b.op(Class::Ext, OpKind::Add, u, Some(v));
        // `AB::ExprEF` has no `Felt` product, so a literal factor stays an `AB::Expr`.
        let seven = b.leaf(Leaf::BaseConst(7));
        let w = b.op(Class::Ext, OpKind::Mul, seven, Some(x));
        let z = b.op(Class::Ext, OpKind::Mul, y, Some(seven));
        let literal_factor = b.op(Class::Ext, OpKind::Add, w, Some(z));
        let out = optimized(b, vec![], vec![base_factor, ext_factor, base_only, literal_factor]);
        assert!(
            out.contains(&format!(
                "let e{} = (h1.dup() + Into::<AB::ExprEF>::into(h2)) * AB::Expr::from(h0);",
                base_factor.index()
            )),
            "{out}"
        );
        assert!(out.contains(&format!(
            "let e{} = h3.dup() * (AB::Expr::from(h4) + AB::Expr::from(h5));",
            ext_factor.index()
        )));
        assert!(out.contains(&format!(
            "let e{} = (h1.dup() + Into::<AB::ExprEF>::into(h2)) * h6.dup();",
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
                    products.push(b.op(class, OpKind::Mul, left, Some(right)));
                }
                let sum = products
                    .iter()
                    .copied()
                    .reduce(|x, y| b.op(class, OpKind::Add, x, Some(y)))
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
        let mut sum = b.op(Class::Ext, OpKind::Add, alpha, Some(beta));
        for value in &aux[..3] {
            sum = b.op(Class::Ext, OpKind::Add, sum, Some(*value));
        }
        let mut products = b.op(Class::Ext, OpKind::Mul, alpha, Some(beta));
        for pair in aux[3..].as_chunks::<2>().0 {
            let product = b.op(Class::Ext, OpKind::Mul, pair[0], Some(pair[1]));
            products = b.op(Class::Ext, OpKind::Add, products, Some(product));
        }
        let out = optimized(b, vec![], vec![sum, products]);
        let row = out.split("pub fn eval_optimized").nth(1).unwrap();
        assert!(row.contains("terms[0]") && row.contains("terms[1]"), "{row}");
        assert!(!row.contains("permutation_randomness"), "{row}");
    }
}
