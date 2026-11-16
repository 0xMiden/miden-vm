// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from p3-air 0.8.0; see mod.rs documentation for provenance.

//! Version-three wire graph. No cached degree is accepted from the wire: decoding
//! checks topological references, domains, operation arities, and recomputes all bounds.
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::{AuxInput, BaseInput, Domain, Expr, ExpressionDomain, Op, RawExpr};

const VERSION: u8 = 3;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExpression<F, EF> {
    version: u8,
    root: usize,
    nodes: Vec<WireNode<F, EF>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNode<F, EF> {
    domain: ExpressionDomain,
    op: WireOp<F, EF>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WireOp<F, EF> {
    BaseConstant(F),
    ExtensionConstant(EF),
    BaseInput(BaseInput),
    AuxInput(AuxInput),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Lift {
        value: usize,
    },
    Mul {
        x: usize,
        y: usize,
    },
    Neg {
        x: usize,
    },
    Sum {
        values: Vec<usize>,
    },
    Product {
        values: Vec<usize>,
    },
    LinearCombination {
        values: Vec<usize>,
        coefficients: Vec<usize>,
    },
    Exp {
        x: usize,
        power: u64,
    },
    ExpPowerOf2 {
        x: usize,
        power_log: usize,
    },
    ScalePow2 {
        x: usize,
        exponent: i128,
    },
    BoolCheck {
        x: usize,
    },
}
struct Encoder<F, EF> {
    nodes: Vec<WireNode<F, EF>>,
    expressions: BTreeMap<usize, usize>,
}
impl<F: Field, EF: ExtensionField<F>> Encoder<F, EF> {
    fn expression(&mut self, expression: &RawExpr<F, EF>) -> usize {
        let identity = match expression {
            RawExpr::Node(node) => Some(Arc::as_ptr(node) as usize),
            _ => None,
        };
        if let Some(index) = identity.and_then(|key| self.expressions.get(&key)) {
            return *index;
        }
        let op = match expression {
            RawExpr::BaseConstant { value, .. } => WireOp::BaseConstant(*value),
            RawExpr::ExtensionConstant(value) => WireOp::ExtensionConstant(*value),
            RawExpr::BaseInput(input) => WireOp::BaseInput(*input),
            RawExpr::AuxInput(input) => WireOp::AuxInput(*input),
            RawExpr::IsFirstRow => WireOp::IsFirstRow,
            RawExpr::IsLastRow => WireOp::IsLastRow,
            RawExpr::IsTransition => WireOp::IsTransition,
            RawExpr::Node(node) => match &node.op {
                Op::Lift(value) => WireOp::Lift { value: self.expression(value) },
                Op::Mul { x, y } => WireOp::Mul {
                    x: self.expression(x),
                    y: self.expression(y),
                },
                Op::Neg(x) => WireOp::Neg { x: self.expression(x) },
                Op::Sum(values) => WireOp::Sum {
                    values: values.iter().map(|v| self.expression(v)).collect(),
                },
                Op::Product(values) => WireOp::Product {
                    values: values.iter().map(|v| self.expression(v)).collect(),
                },
                Op::LinearCombination { values, coefficients } => WireOp::LinearCombination {
                    values: values.iter().map(|v| self.expression(v)).collect(),
                    coefficients: coefficients.iter().map(|v| self.expression(v)).collect(),
                },
                Op::Exp { x, power } => WireOp::Exp { x: self.expression(x), power: *power },
                Op::ExpPowerOf2 { x, power_log } => WireOp::ExpPowerOf2 {
                    x: self.expression(x),
                    power_log: *power_log,
                },
                Op::ScalePow2 { x, exponent } => WireOp::ScalePow2 {
                    x: self.expression(x),
                    exponent: *exponent,
                },
                Op::BoolCheck(x) => WireOp::BoolCheck { x: self.expression(x) },
            },
        };
        let index = self.nodes.len();
        self.nodes.push(WireNode { domain: expression.domain(), op });
        if let Some(key) = identity {
            self.expressions.insert(key, index);
        }
        index
    }
}
fn decode<F: Field, EF: ExtensionField<F>, D: Domain>(
    wire: WireExpression<F, EF>,
) -> Option<Expr<F, EF, D>> {
    if wire.version != VERSION || wire.nodes.is_empty() || wire.root != wire.nodes.len() - 1 {
        return None;
    }
    let mut built: Vec<RawExpr<F, EF>> = Vec::with_capacity(wire.nodes.len());
    for node in wire.nodes {
        let expression = |index: usize| built.get(index).cloned();
        let list =
            |indices: Vec<usize>| indices.into_iter().map(expression).collect::<Option<Vec<_>>>();
        let domain = node.domain;
        let raw = match node.op {
            WireOp::BaseConstant(value) => RawExpr::BaseConstant { value, domain },
            WireOp::ExtensionConstant(value) => {
                if domain != ExpressionDomain::Extension {
                    return None;
                }
                RawExpr::from_constant(domain, value)
            },
            WireOp::BaseInput(input) => {
                if domain != ExpressionDomain::Base {
                    return None;
                }
                RawExpr::BaseInput(input)
            },
            WireOp::AuxInput(input) => {
                if domain != ExpressionDomain::Extension {
                    return None;
                }
                RawExpr::AuxInput(input)
            },
            WireOp::IsFirstRow => {
                if domain != ExpressionDomain::Base {
                    return None;
                }
                RawExpr::IsFirstRow
            },
            WireOp::IsLastRow => {
                if domain != ExpressionDomain::Base {
                    return None;
                }
                RawExpr::IsLastRow
            },
            WireOp::IsTransition => {
                if domain != ExpressionDomain::Base {
                    return None;
                }
                RawExpr::IsTransition
            },
            WireOp::Lift { value } => RawExpr::node(domain, Op::Lift(expression(value)?)).ok()?,
            WireOp::Mul { x, y } => {
                RawExpr::node(domain, Op::Mul { x: expression(x)?, y: expression(y)? }).ok()?
            },
            WireOp::Neg { x } => RawExpr::node(domain, Op::Neg(expression(x)?)).ok()?,
            WireOp::Sum { values } => {
                RawExpr::node(domain, Op::Sum(list(values)?.into_boxed_slice())).ok()?
            },
            WireOp::Product { values } => {
                RawExpr::node(domain, Op::Product(list(values)?.into_boxed_slice())).ok()?
            },
            WireOp::LinearCombination { values, coefficients } => RawExpr::node(
                domain,
                Op::LinearCombination {
                    values: list(values)?.into_boxed_slice(),
                    coefficients: list(coefficients)?.into_boxed_slice(),
                },
            )
            .ok()?,
            WireOp::Exp { x, power } => {
                RawExpr::node(domain, Op::Exp { x: expression(x)?, power }).ok()?
            },
            WireOp::ExpPowerOf2 { x, power_log } => {
                RawExpr::node(domain, Op::ExpPowerOf2 { x: expression(x)?, power_log }).ok()?
            },
            WireOp::ScalePow2 { x, exponent } => {
                RawExpr::node(domain, Op::ScalePow2 { x: expression(x)?, exponent }).ok()?
            },
            WireOp::BoolCheck { x } => RawExpr::node(domain, Op::BoolCheck(expression(x)?)).ok()?,
        };
        built.push(raw);
    }
    let raw = built.pop()?;
    (raw.domain() == D::DOMAIN).then_some(Expr { raw, marker: PhantomData })
}
impl<F: Field, EF: ExtensionField<F>, D: Domain> Serialize for Expr<F, EF, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoder = Encoder {
            nodes: Vec::new(),
            expressions: BTreeMap::new(),
        };
        let root = encoder.expression(&self.raw);
        WireExpression {
            version: VERSION,
            root,
            nodes: encoder.nodes,
        }
        .serialize(serializer)
    }
}
impl<'de, F: Field, EF: ExtensionField<F>, D: Domain> Deserialize<'de> for Expr<F, EF, D> {
    fn deserialize<S: Deserializer<'de>>(deserializer: S) -> Result<Self, S::Error> {
        decode(WireExpression::<F, EF>::deserialize(deserializer)?)
            .ok_or_else(|| S::Error::custom("invalid version-three symbolic expression graph"))
    }
}
