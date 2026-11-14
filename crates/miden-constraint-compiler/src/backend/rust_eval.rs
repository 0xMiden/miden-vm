//! Native Rust evaluation emitted directly from authored symbolic expression views.
//!
//! One source index supplies sharing, use counts and preparation boundaries.
//! Structured operations remain intact until their specialized trait call is emitted.

use std::fmt::Write as _;

use crate::ir::{CapturedProgram, Class, Leaf, Node, OpKind};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::field::BasedVectorSpace;
use miden_stark::air::symbolic::{AuxInput, BaseInput, CoefficientDomain, ExprView};

mod index;
mod plan;
use index::ExpressionIndex;
use plan::{Coefficient, DotKind, MAX_TERMS, Piece, Plan, Rewrite};

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
/// Arithmetic-only regions retain the existing scalar optimizer. Explicit sums,
/// products, powers, and linear combinations remain opaque
/// operation boundaries, and their results are shared across all uses.
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
        let capacity = preparation.terms.len();
        let terms_name = format!("{}_PREPARED_TERMS", eval.name.to_ascii_uppercase());
        writeln!(out, "\npub const {terms_name}: usize = {capacity};").unwrap();
        let mut precompute = Emitter::new(graph, preparation, true);
        let mut results = Vec::with_capacity(capacity);
        for &id in &preparation.terms {
            results.push(precompute.expr(id, Class::Ext));
        }
        writeln!(out, "\n/// Prepare challenge-only results for `{}`.", eval.air_label).unwrap();
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

/// Whole expression results that cross from challenge-only preparation into row work.
struct Preparation {
    terms: Vec<usize>,
    slots: Vec<Option<usize>>,
}

impl Preparation {
    fn new(graph: &ExpressionIndex<'_>) -> Self {
        let challenge_only = graph.challenge_dependencies();
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
        Self { terms, slots }
    }
}

struct Emitter<'g, 'a> {
    graph: &'g ExpressionIndex<'a>,
    preparation: &'g Preparation,
    preparing: bool,
    plan: Plan<'g, 'a>,
    tokens: Vec<Option<Token>>,
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
                let rhs = if let Some(rewrite) = self.plan.rewrite(id) {
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

    fn hoist(&mut self, class: Class, rhs: String) -> Token {
        let name = format!("h{}", self.hoisted);
        self.hoisted += 1;
        self.lines.push(format!("    let {name}: {} = {rhs};", self.ty(class)));
        Token { class, code: name }
    }

    fn bind(&mut self, id: usize, class: Class, rhs: String) -> Token {
        let prefix = if class == Class::Base { 'b' } else { 'e' };
        let name = format!("{prefix}{}", id);
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
        if class == Class::Base {
            assert_eq!(x.class, Class::Base);
            assert_eq!(y.class, Class::Base);
            return format!("{} {} {}", operand(&x), sym(op), operand(&y));
        }
        match (x.class, y.class) {
            (Class::Ext, _) => format!("{} {} {}", operand(&x), sym(op), operand(&y)),
            (Class::Base, Class::Ext) if op != OpKind::Sub => {
                format!("{} {} {}", operand(&y), sym(op), operand(&x))
            },
            (Class::Base, _) => {
                format!("{} {} {}", lift_base_to_ext(&x, self.types()), sym(op), operand(&y))
            },
        }
    }

    fn scalar_binary(
        &mut self,
        class: Class,
        op: OpKind,
        domain: CoefficientDomain,
        x: usize,
        y: usize,
    ) -> String {
        if domain == CoefficientDomain::Same {
            return self.binary(class, op, x, y);
        }
        let value = self.expr(x, class);
        let (_, scalar) = self.coefficients(class, domain, &[y]);
        format!("{value} {} {}", sym(op), scalar[0])
    }

    fn operation(
        &mut self,
        class: Class,
        view: ExprView<'_, Felt, QuadFelt>,
        inputs: &[usize],
    ) -> String {
        let ty = self.ty(class);
        match view {
            ExprView::Add { coefficient_domain, .. } => {
                self.scalar_binary(class, OpKind::Add, coefficient_domain, inputs[0], inputs[1])
            },
            ExprView::Sub { coefficient_domain, .. } => {
                self.scalar_binary(class, OpKind::Sub, coefficient_domain, inputs[0], inputs[1])
            },
            ExprView::Mul { coefficient_domain, .. } => {
                self.scalar_binary(class, OpKind::Mul, coefficient_domain, inputs[0], inputs[1])
            },
            ExprView::Neg { .. } => format!("-{}", self.expr(inputs[0], class)),
            ExprView::Sum { .. } => {
                let values: Vec<_> = inputs.iter().map(|&id| self.expr(id, class)).collect();
                format!("{ty}::sum_array::<{}>(&[{}])", values.len(), values.join(", "))
            },
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
            ExprView::LinearCombination { coefficient_domain, .. } => {
                assert_eq!(inputs.len() % 2, 0, "linear combination arity");
                let n = inputs.len() / 2;
                let values: Vec<_> = inputs[..n].iter().map(|&id| self.expr(id, class)).collect();
                let (scalar_ty, coefficients) =
                    self.coefficients(class, coefficient_domain, &inputs[n..]);
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

    fn coefficients(
        &mut self,
        class: Class,
        domain: CoefficientDomain,
        ids: &[usize],
    ) -> (&'static str, Vec<String>) {
        let types = self.types();
        match domain {
            CoefficientDomain::Same => {
                (self.ty(class), ids.iter().map(|&id| self.expr(id, class)).collect())
            },
            CoefficientDomain::Base => {
                (types.base, ids.iter().map(|&id| self.expr(id, Class::Base)).collect())
            },
            CoefficientDomain::BaseConstant | CoefficientDomain::ExtensionConstant => {
                // ExtExpr is only promised Algebra<BaseExpr>, not Algebra<Felt>
                // or Algebra<EF>. A base-embedded coefficient remains usable by
                // constructing a BaseExpr, while a genuine EF constant is rejected.
                let scalar_ty = if class == Class::Base { "Felt" } else { types.base };
                let values = ids
                    .iter()
                    .map(|&id| {
                        let value = self
                            .graph
                            .constant(id)
                            .expect("ext constant with non-base coefficients");
                        if class == Class::Base {
                            format!("Felt::from_u64({value})")
                        } else {
                            format!("{}::from(Felt::from_u64({value}))", types.base)
                        }
                    })
                    .collect();
                (scalar_ty, values)
            },
        }
    }

    fn rewrite_rhs(&mut self, class: Class, rewrite: Rewrite) -> String {
        let ty = self.ty(class);
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
                let factor = self.graph.class(common);
                let sum = plan::join(self.graph.class(left), self.graph.class(right));
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
                let mut values = Vec::with_capacity(pieces.len());
                for piece in pieces {
                    values.push(match piece {
                        Piece::Node(id) => self.expr(id, class),
                        Piece::Dot { kind, pairs } => {
                            let n = pairs.len();
                            let mut terms = Vec::with_capacity(n);
                            let mut coeffs = Vec::with_capacity(n);
                            for (id, coefficient) in pairs {
                                terms.push(self.expr(id, class));
                                coeffs.push(match coefficient {
                                    Coefficient::Scalar(c) => format!("Felt::from_u64({c})"),
                                    Coefficient::One => format!("{}::ONE", self.types().base),
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
                            format!("{method}(&[{}], &[{}])", terms.join(", "), coeffs.join(", "))
                        },
                    });
                }
                match values.len() {
                    1 => values.pop().unwrap(),
                    2 | 3 => values
                        .into_iter()
                        .map(|value| format!("({value})"))
                        .collect::<Vec<_>>()
                        .join(" + "),
                    n => format!("{ty}::sum_array::<{n}>(&[{}])", values.join(", ")),
                }
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
            for id in 0..index.len() {
                let Some(rewrite) = plan.rewrite(id) else {
                    continue;
                };
                let result = match rewrite {
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
    fn linear_combinations_preserve_scalar_domains_and_batch_large_mixed_calls() {
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
        assert!(output.contains(" + Felt::from_u64(2)"), "{output}");
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
}
