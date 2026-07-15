//! Rust-evaluator backend: emits a captured constraint graph as a flat,
//! builder-generic Rust module.
//!
//! Per AIR, one `eval_{name}<AB: LiftedAirBuilder<F = Felt>>` function containing
//! one `let` per unique graph node in topological id order — leaf reads named
//! `h{n}` in first-use order, ops named `b{id}` (base) / `e{id}` (ext) — followed
//! by the constraint asserts replayed in the exact global order of the captured
//! eval, so `ConstraintLayout` (and hence alpha assignment and all proof
//! artifacts) is unchanged.
//!
//! Emission is deterministic: the same graph always produces byte-identical
//! output (crate invariant 3).
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
    field::PrimeCharacteristicRing,
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

/// The emitted variable name for one graph node, and the class it evaluates in.
#[derive(Clone)]
struct Token {
    class: Class,
    code: String,
}

struct Emitter<'g> {
    graph: &'g Graph,
    /// Token per node, filled in id order (children precede parents).
    tokens: Vec<Option<Token>>,
    /// Emitted `let` lines, in evaluation order.
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

    /// Emit every node in topological (id) order.
    fn emit_all(&mut self) {
        for (id, node) in self.graph.iter() {
            match node {
                Node::Leaf(leaf) => {
                    let tok = self.leaf_token(leaf);
                    self.tokens[id.index()] = Some(tok);
                },
                Node::Op { class, op, x, y } => self.emit_op(id, class, op, x, y),
            }
        }
    }

    fn token(&self, id: NodeId) -> Token {
        self.tokens[id.index()].clone().expect("children precede parents in id order")
    }

    /// Emit a `let` for a leaf value. Hash-consing guarantees each leaf node is
    /// visited exactly once, so every hoist gets a fresh name.
    fn hoist(&mut self, ty: &str, expr: String) -> String {
        let name = format!("h{}", self.hoisted);
        self.hoisted += 1;
        self.lines.push(format!("    let {name}: {ty} = {expr};"));
        name
    }

    fn base_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Base,
            code: self.hoist("AB::Expr", expr),
        }
    }

    fn ext_leaf(&mut self, expr: String) -> Token {
        Token {
            class: Class::Ext,
            code: self.hoist("AB::ExprEF", expr),
        }
    }

    fn leaf_token(&mut self, leaf: Leaf) -> Token {
        match leaf {
            Leaf::Main { offset, index } => self.base_leaf(format!("m{offset}[{index}].into()")),
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
            Leaf::Aux { offset, index } => self.ext_leaf(format!("a{offset}[{index}].into()")),
            Leaf::Challenge(index) => {
                self.ext_leaf(format!("builder.permutation_randomness()[{index}].into()"))
            },
            Leaf::PermValue(index) => {
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

    fn emit_op(&mut self, id: NodeId, class: Class, op: OpKind, x: NodeId, y: Option<NodeId>) {
        let rhs = match class {
            Class::Base => {
                let xt = self.token(x);
                match y {
                    None => format!("-{}.clone()", xt.code),
                    Some(y) => {
                        let yt = self.token(y);
                        format!("{}.clone() {} {}.clone()", xt.code, sym(op), yt.code)
                    },
                }
            },
            Class::Ext => {
                let xt = self.token(x);
                match y {
                    None => match xt.class {
                        Class::Ext => format!("-{}.clone()", xt.code),
                        Class::Base => format!("-AB::ExprEF::from({}.clone())", xt.code),
                    },
                    Some(y) => {
                        let yt = self.token(y);
                        match (xt.class, yt.class) {
                            (Class::Ext, _) => {
                                format!("{}.clone() {} {}.clone()", xt.code, sym(op), yt.code)
                            },
                            // Commutative ops flip so the ext operand drives the
                            // mixed-op impl; subtraction promotes the base operand.
                            (Class::Base, Class::Ext) if op != OpKind::Sub => {
                                format!("{}.clone() {} {}.clone()", yt.code, sym(op), xt.code)
                            },
                            (Class::Base, _) => format!(
                                "AB::ExprEF::from({}.clone()) {} {}.clone()",
                                xt.code,
                                sym(op),
                                yt.code
                            ),
                        }
                    },
                }
            },
        };
        let prefix = match class {
            Class::Base => 'b',
            Class::Ext => 'e',
        };
        self.lines.push(format!("    let {prefix}{} = {rhs};", id.index()));
        self.tokens[id.index()] = Some(Token {
            class,
            code: format!("{prefix}{}", id.index()),
        });
    }
}

/// Place an assert line at its global constraint index, validating range and
/// uniqueness. With every index placed exactly once, index density follows by
/// pigeonhole.
fn place(asserts: &mut [Option<String>], global: usize, line: String) {
    assert!(
        global < asserts.len(),
        "global constraint index {global} out of range ({} constraints)",
        asserts.len()
    );
    assert!(asserts[global].is_none(), "duplicate global constraint index {global}");
    asserts[global] = Some(line);
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
    let mut e = Emitter::new(eval.graph);
    e.emit_all();

    // Replay asserts in the exact global order of the captured eval so the
    // constraint layout (and alpha assignment) is unchanged.
    let cons = eval.constraints;
    let total = cons.base_roots.len() + cons.ext_roots.len();
    let mut asserts: Vec<Option<String>> = vec![None; total];
    for (local, &global) in cons.base_global_indices.iter().enumerate() {
        let t = e.token(cons.base_roots[local]);
        assert!(t.class == Class::Base, "base constraint root must be base-class");
        place(&mut asserts, global, format!("    builder.assert_zero({}.clone());", t.code));
    }
    for (local, &global) in cons.ext_global_indices.iter().enumerate() {
        let t = e.token(cons.ext_roots[local]);
        let line = match t.class {
            Class::Ext => format!("    builder.assert_zero_ext({}.clone());", t.code),
            Class::Base => {
                format!("    builder.assert_zero_ext(AB::ExprEF::from({}.clone()));", t.code)
            },
        };
        place(&mut asserts, global, line);
    }

    writeln!(
        out,
        "\n/// Generated globally-CSE'd evaluator for `{}`.\n\
         ///\n\
         /// Emits constraints in the exact global order of the hand-written `eval`.\n\
         #[inline(never)]\n\
         pub fn eval_{}<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {{",
        eval.air_label, eval.name,
    )
    .unwrap();
    writeln!(out, "{FN_PROLOGUE}").unwrap();
    for line in &e.lines {
        writeln!(out, "{line}").unwrap();
    }
    writeln!(
        out,
        "    // ---- constraint asserts, in the hand-written eval's global order ----"
    )
    .unwrap();
    for line in asserts.into_iter() {
        writeln!(out, "{}", line.expect("every global constraint index must be assigned")).unwrap();
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
    field::PrimeCharacteristicRing,
    stark::air::{LiftedAirBuilder, WindowAccess},
};

/// Generated globally-CSE'd evaluator for `MockAir::BASE`.
///
/// Emits constraints in the exact global order of the hand-written `eval`.
#[inline(never)]
pub fn eval_base_mock<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);
    let h0: AB::Expr = m0[0].into();
    let h1: AB::Expr = m1[0].into();
    let b2 = h1.clone() - h0.clone();
    let h2: AB::Expr = builder.is_first_row();
    let b4 = h2.clone() * b2.clone();
    let b5 = -b4.clone();
    let h3: AB::Expr = builder.public_values()[2].into();
    let h4: AB::Expr = builder.periodic_values()[1].into();
    let b8 = h3.clone() + h4.clone();
    let h5: AB::Expr = builder.is_last_row();
    let h6: AB::Expr = builder.is_transition();
    let b11 = h5.clone() * h6.clone();
    let h7: AB::Expr = AB::Expr::from(Felt::from_u64(3));
    let b13 = b11.clone() + h7.clone();
    // ---- constraint asserts, in the hand-written eval's global order ----
    builder.assert_zero(b8.clone());
    builder.assert_zero(b13.clone());
    builder.assert_zero(b5.clone());
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
    let h0: AB::ExprEF = a0[0].into();
    let h1: AB::ExprEF = builder.permutation_randomness()[0].into();
    let e2 = h0.clone() + h1.clone();
    let h2: AB::Expr = m0[1].into();
    let e5 = e2.clone() * h2.clone();
    let e6 = AB::ExprEF::from(h2.clone()) - e2.clone();
    let e7 = e2.clone() - h2.clone();
    let e8 = -AB::ExprEF::from(h2.clone());
    let h3: AB::ExprEF = AB::ExprEF::from(AB::Expr::from(Felt::from_u64(7)));
    let e10 = e6.clone() + h3.clone();
    let h4: AB::ExprEF = builder.permutation_values()[0].clone().into();
    let e12 = e10.clone() - h4.clone();
    // ---- constraint asserts, in the hand-written eval's global order ----
    builder.assert_zero_ext(e5.clone());
    builder.assert_zero_ext(e7.clone());
    builder.assert_zero_ext(e8.clone());
    builder.assert_zero_ext(e12.clone());
    builder.assert_zero_ext(AB::ExprEF::from(h2.clone()));
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
