//! Rust-evaluator backend: emits a captured constraint graph as a flat,
//! builder-generic Rust module.
//!
//! Per AIR, one `eval_{name}<AB: LiftedAirBuilder<F = Felt>>` function. Every
//! unique graph node gets one `let` (global CSE), emitted at its first use —
//! leaf reads named `h{n}` in first-use order, ops named `b{id}` (base) /
//! `e{id}` (ext) — and each constraint assert is placed directly after its
//! root, replayed in the exact global order of the captured eval, so
//! `ConstraintLayout` (and hence alpha assignment and all proof artifacts) is
//! unchanged.
//!
//! Interleaving the asserts with the node `let`s bounds value live ranges:
//! each constraint root dies at its assert. The alternative — all `let`s
//! first, all asserts last — keeps every root live to the end of the
//! function, and the resulting register spills measurably regress the prover
//! on register-starved or cache-contended targets.
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

use std::fmt::Write as _;

use crate::ir::{CapturedConstraints, Class, Graph, Leaf, Node, NodeId, OpKind};

/// One AIR to emit an evaluator function for.
pub struct AirEvaluator<'a> {
    /// Suffix of the emitted function name (`eval_{name}`).
    pub name: &'a str,
    /// Label used in the function's doc comment, e.g. `MidenAir::CORE`.
    pub air_label: &'a str,
    pub graph: &'a Graph,
    pub constraints: &'a CapturedConstraints,
}

/// Emit the complete generated-evaluators module: `header` (a `//!` doc block,
/// newline-terminated) followed by imports and one evaluator function per entry.
///
/// # Panics
///
/// Panics if the inputs break capture's guarantees: a class-invariant violation,
/// an out-of-range or duplicate global constraint index, or an ext constant with
/// non-base coefficients (not representable under the builder bound).
pub fn emit_module(header: &str, evals: &[AirEvaluator<'_>]) -> String {
    let mut out = String::from(header);
    out.push_str(MODULE_IMPORTS);
    for eval in evals {
        emit_evaluator(eval, &mut out);
    }
    out
}

const MODULE_IMPORTS: &str = r"
use miden_core::Felt;
use miden_crypto::{
    field::{Dup, PrimeCharacteristicRing},
    stark::air::{LiftedAirBuilder, WindowAccess},
};
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

/// Render `t` as an `Expr` value **in its own class** (`AB::Expr` for base,
/// `AB::ExprEF` for ext): `.dup()` a materialized `Expr`, else promote the Copy
/// `Var` leaf. A base `Var` promotes with `AB::Expr::from` (`AB::Expr:
/// Algebra<AB::Var>` gives `From<AB::Var>`); an ext `VarEF` has no such `From`
/// (only `VarEF: Into<ExprEF>`), so it uses an explicit `Into::<ExprEF>` — a
/// bare `.into()` would be ambiguous against the reflexive `Into` impl.
fn as_expr(t: &Token) -> String {
    match t.repr {
        Repr::Expr => format!("{}.dup()", t.code),
        Repr::Var => match t.class {
            Class::Base => format!("AB::Expr::from({})", t.code),
            Class::Ext => format!("Into::<AB::ExprEF>::into({})", t.code),
        },
    }
}

/// Render a base-class `t` lifted into `AB::ExprEF`. `AB::ExprEF: From<AB::Expr>`
/// (via `Algebra<AB::Expr>`), so a base `Expr` lifts with `from`; a base `Var` is
/// promoted to `AB::Expr` (also `from`) and then lifted.
fn lift_base_to_ext(t: &Token) -> String {
    debug_assert!(matches!(t.class, Class::Base), "lift_base_to_ext on a non-base token");
    match t.repr {
        Repr::Expr => format!("AB::ExprEF::from({}.dup())", t.code),
        Repr::Var => format!("AB::ExprEF::from(AB::Expr::from({}))", t.code),
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

struct Emitter<'g> {
    graph: &'g Graph,
    /// Token per emitted node, memoized on first use.
    tokens: Vec<Option<Token>>,
    /// Emitted lines — node `let`s and constraint asserts, interleaved in
    /// evaluation order.
    lines: Vec<String>,
    /// Number of hoisted leaf `let`s so far, for `h{n}` naming.
    hoisted: usize,
}

impl<'g> Emitter<'g> {
    fn new(graph: &'g Graph) -> Self {
        Self {
            graph,
            tokens: vec![None; graph.len()],
            lines: Vec::new(),
            hoisted: 0,
        }
    }

    /// Token for `id`, emitting the node — and, recursively, any children not
    /// yet emitted — at its first use.
    fn token(&mut self, id: NodeId) -> Token {
        if let Some(tok) = &self.tokens[id.index()] {
            return tok.clone();
        }
        let tok = match self.graph.node(id) {
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
            code: self.hoist(Some("AB::Expr"), expr),
        }
    }

    /// A materialized ext `ExprEF` leaf.
    fn ext_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Ext,
            repr: Repr::Expr,
            code: self.hoist(Some("AB::ExprEF"), expr),
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
                self.base_leaf(format!("AB::Expr::from(Felt::from_u64({raw}))"))
            },
            Leaf::Aux { offset, index } => self.ext_var_leaf(format!("a{offset}[{index}]")),
            Leaf::Challenge(index) => {
                self.ext_leaf(format!("builder.permutation_randomness()[{index}].into()"))
            },
            Leaf::PermValue(index) => {
                // PermutationVar is Clone-only (not Copy), so it cannot be kept as
                // a reusable Var; it stays a materialized ExprEF via `.clone().into()`.
                self.ext_leaf(format!("builder.permutation_values()[{index}].clone().into()"))
            },
            Leaf::ExtConst([c0, c1]) => {
                // The builder bound does not name EF, so only constants liftable
                // from the base field can be emitted.
                assert_eq!(c1, 0, "ext constant with non-base coefficients");
                self.ext_leaf(format!("AB::ExprEF::from(AB::Expr::from(Felt::from_u64({c0})))"))
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
        let xt = self.token(x);
        let yt = y.map(|y| self.token(y));
        let rhs = match class {
            Class::Base => match &yt {
                // `AB::Var` has no `Neg`, so a Var operand is promoted by `as_expr`.
                None => format!("-{}", as_expr(&xt)),
                // Base arithmetic accepts a `Var` on either side directly
                // (`AB::Var`'s own ops and `AB::Expr: Algebra<AB::Var>`), so
                // operands stay bare where they are Vars.
                Some(yt) => format!("{} {} {}", operand(&xt), sym(op), operand(yt)),
            },
            Class::Ext => match &yt {
                None => match xt.class {
                    Class::Ext => format!("-{}", as_expr(&xt)),
                    Class::Base => format!("-{}", lift_base_to_ext(&xt)),
                },
                Some(yt) => match (xt.class, yt.class) {
                    // The ext operand drives; the other side is rendered as an
                    // `Expr` in its own class (`AB::ExprEF: Algebra<AB::Expr>`
                    // consumes a base `Expr`).
                    (Class::Ext, _) => {
                        format!("{} {} {}", as_expr(&xt), sym(op), as_expr(yt))
                    },
                    // Commutative ops flip so the ext operand drives the
                    // mixed-op impl; subtraction promotes the base operand.
                    (Class::Base, Class::Ext) if op != OpKind::Sub => {
                        format!("{} {} {}", as_expr(yt), sym(op), as_expr(&xt))
                    },
                    (Class::Base, _) => {
                        format!("{} {} {}", lift_base_to_ext(&xt), sym(op), as_expr(yt))
                    },
                },
            },
        };
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

/// Append one `eval_{name}` function (preceded by a blank line) to `out`.
fn emit_evaluator(eval: &AirEvaluator<'_>, out: &mut String) {
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

    let mut e = Emitter::new(eval.graph);
    for entry in roots {
        let (root, is_ext) = entry.expect("every global constraint index must be assigned");
        let t = e.token(root);
        let line = if is_ext {
            match t.class {
                Class::Ext => format!("    builder.assert_zero_ext({});", operand(&t)),
                Class::Base => {
                    format!("    builder.assert_zero_ext({});", lift_base_to_ext(&t))
                },
            }
        } else {
            assert!(t.class == Class::Base, "base constraint root must be base-class");
            format!("    builder.assert_zero({});", operand(&t))
        };
        e.lines.push(line);
    }

    writeln!(
        out,
        "\n/// Generated globally-CSE'd evaluator for `{}`.\n\
         ///\n\
         /// Emits constraints in the exact global order of the hand-written `eval`,\n\
         /// with each node's `let` placed at its first use.\n\
         #[inline(never)]\n\
         pub fn eval_{}<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {{",
        eval.air_label, eval.name,
    )
    .unwrap();
    writeln!(out, "{FN_PROLOGUE}").unwrap();
    for line in &e.lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(out, "}}").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{GraphBuilder, OpCounts};

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

    /// Base-class emission: every base leaf kind, each binary op, unary neg,
    /// leaf hoisting in first-use order, and assert replay in global (not local)
    /// constraint order.
    #[test]
    fn golden_base_evaluator() {
        let mut b = GraphBuilder::new();
        let cur = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let next = b.leaf(Leaf::Main { offset: 1, index: 0 });
        let (diff, _) = b.op(Class::Base, OpKind::Sub, next, Some(cur));
        let first = b.leaf(Leaf::IsFirst);
        let (gated, _) = b.op(Class::Base, OpKind::Mul, first, Some(diff));
        let (neg, _) = b.op(Class::Base, OpKind::Neg, gated, None);
        let public = b.leaf(Leaf::Public(2));
        let periodic = b.leaf(Leaf::Periodic(1));
        let (sum, _) = b.op(Class::Base, OpKind::Add, public, Some(periodic));
        let last = b.leaf(Leaf::IsLast);
        let transition = b.leaf(Leaf::IsTransition);
        let (edges, _) = b.op(Class::Base, OpKind::Mul, last, Some(transition));
        let three = b.leaf(Leaf::BaseConst(3));
        let (offset, _) = b.op(Class::Base, OpKind::Add, edges, Some(three));
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
use miden_crypto::{
    field::{Dup, PrimeCharacteristicRing},
    stark::air::{LiftedAirBuilder, WindowAccess},
};

/// Generated globally-CSE'd evaluator for `MockAir::BASE`.
///
/// Emits constraints in the exact global order of the hand-written `eval`,
/// with each node's `let` placed at its first use.
#[inline(never)]
pub fn eval_base_mock<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
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
        let (acc, _) = b.op(Class::Ext, OpKind::Add, aux, Some(alpha));
        let main = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let lift = b.leaf(Leaf::ExtBase(main));
        let (flip, _) = b.op(Class::Ext, OpKind::Mul, lift, Some(acc));
        let (sub_promote, _) = b.op(Class::Ext, OpKind::Sub, lift, Some(acc));
        let (sub_plain, _) = b.op(Class::Ext, OpKind::Sub, acc, Some(lift));
        let (neg_promote, _) = b.op(Class::Ext, OpKind::Neg, lift, None);
        let seven = b.leaf(Leaf::ExtConst([7, 0]));
        let (shifted, _) = b.op(Class::Ext, OpKind::Add, sub_promote, Some(seven));
        let bound = b.leaf(Leaf::PermValue(0));
        let (closed, _) = b.op(Class::Ext, OpKind::Sub, shifted, Some(bound));
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

        let body = r"pub fn eval_ext_mock<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
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
        let tail = out
            .split("pub fn ")
            .nth(1)
            .map(|s| format!("pub fn {s}"))
            .expect("one function emitted");
        assert_eq!(tail, body);
    }

    #[test]
    #[should_panic(expected = "duplicate global constraint index")]
    fn duplicate_global_index_is_rejected() {
        let mut b = GraphBuilder::new();
        let x = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let (r, _) = b.op(Class::Base, OpKind::Neg, x, None);
        let graph = b.freeze();
        let cons = constraints(vec![(r, 0), (r, 0)], vec![]);
        emit_module(
            "//! h.\n",
            &[AirEvaluator {
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
}
