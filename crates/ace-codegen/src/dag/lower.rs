use std::{collections::HashMap, hash::Hash};

use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, TwoAdicField};
use p3_miden_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};

use super::{
    builder::DagBuilder,
    ir::{AceDag, NodeId, PeriodicColumnData},
};
use crate::{
    AceError, layout::InputKey, quotient::build_quotient_recomposition_dag,
    randomness::RandomnessPlan,
};

/// Lower a symbolic expression into DAG nodes using the provided layout.
pub fn lower_expr<F, EF>(
    expr: &SymbolicExpression<EF>,
    builder: &mut DagBuilder<EF>,
    layout: &crate::layout::InputLayout,
    periodic_nodes: &[NodeId],
) -> Result<NodeId, AceError>
where
    F: PrimeCharacteristicRing,
    EF: PrimeCharacteristicRing + BasedVectorSpace<F> + Copy + Eq + Hash,
{
    match expr {
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Challenge => {
                let plan = RandomnessPlan::from_layout(layout)?;
                plan.lower_challenge(builder, v.index)
            },
            Entry::Aux { offset } | Entry::Permutation { offset } => {
                let index = v.index;
                let mut acc = builder.constant(EF::ZERO);
                for coord in 0..layout.counts.ext_degree {
                    let basis =
                        EF::ith_basis_element(coord).ok_or(AceError::InvalidBasisIndex(coord))?;
                    let coord_node = builder.input(InputKey::AuxCoord { offset, index, coord });
                    let basis_node = builder.constant(basis);
                    let term = builder.mul(basis_node, coord_node);
                    acc = builder.add(acc, term);
                }
                Ok(acc)
            },
            Entry::Periodic => {
                periodic_nodes.get(v.index).copied().ok_or(AceError::InvalidPeriodicColumn {
                    index: v.index,
                    count: periodic_nodes.len(),
                })
            },
            _ => Ok(builder.input(input_key_for_symbolic(v)?)),
        },
        SymbolicExpression::IsFirstRow => {
            let z_pow_n = builder.input(InputKey::ZPowN);
            let one = builder.constant(EF::ONE);
            let numerator = builder.sub(z_pow_n, one);
            let inv = builder.input(InputKey::InvZMinusOne);
            Ok(builder.mul(numerator, inv))
        },
        SymbolicExpression::IsLastRow => {
            let z_pow_n = builder.input(InputKey::ZPowN);
            let one = builder.constant(EF::ONE);
            let numerator = builder.sub(z_pow_n, one);
            let inv = builder.input(InputKey::InvZMinusGInv);
            Ok(builder.mul(numerator, inv))
        },
        SymbolicExpression::IsTransition => {
            let z = builder.input(InputKey::Z);
            let g_inv = builder.input(InputKey::GInv);
            Ok(builder.sub(z, g_inv))
        },
        SymbolicExpression::Constant(c) => Ok(builder.constant(*c)),
        SymbolicExpression::Add { x, y, .. } => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes)?;
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes)?;
            Ok(builder.add(lx, ly))
        },
        SymbolicExpression::Sub { x, y, .. } => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes)?;
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes)?;
            Ok(builder.sub(lx, ly))
        },
        SymbolicExpression::Mul { x, y, .. } => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes)?;
            let ly = lower_expr::<F, EF>(y, builder, layout, periodic_nodes)?;
            Ok(builder.mul(lx, ly))
        },
        SymbolicExpression::Neg { x, .. } => {
            let lx = lower_expr::<F, EF>(x, builder, layout, periodic_nodes)?;
            Ok(builder.neg(lx))
        },
    }
}

/// Build the verifier-equivalent root expression DAG.
///
/// This constructs the folded constraint accumulator, divides by the vanishing
/// polynomial, recomposes the quotient, and subtracts both sides to yield the
/// root expression evaluated by the ACE circuit.
pub fn build_verifier_dag<F, EF>(
    constraints: &[SymbolicExpression<EF>],
    layout: &crate::layout::InputLayout,
    periodic: Option<&PeriodicColumnData<EF>>,
) -> Result<AceDag<EF>, AceError>
where
    F: PrimeCharacteristicRing,
    EF: PrimeCharacteristicRing + BasedVectorSpace<F> + Copy + Eq + Hash,
{
    if layout.counts.ext_degree != EF::DIMENSION {
        return Err(AceError::InvalidExtensionDegree {
            expected: EF::DIMENSION,
            got: layout.counts.ext_degree,
        });
    }

    let mut builder = DagBuilder::<EF>::new();
    let periodic_nodes = match periodic {
        Some(data) => {
            if data.len() != layout.counts.num_periodic {
                return Err(AceError::InvalidPeriodicColumn {
                    index: data.len(),
                    count: layout.counts.num_periodic,
                });
            }
            build_periodic_nodes(&mut builder, layout, data)?
        },
        None => Vec::new(),
    };
    let alpha = builder.input(InputKey::Alpha);
    let inv_vanishing = builder.input(InputKey::InvVanishing);

    let mut acc = builder.constant(EF::ZERO);
    for constraint in constraints {
        let node = lower_expr::<F, EF>(constraint, &mut builder, layout, &periodic_nodes)?;
        let acc_mul = builder.mul(acc, alpha);
        acc = builder.add(acc_mul, node);
    }
    let folded = builder.mul(acc, inv_vanishing);

    let quotient = build_quotient_recomposition_dag::<F, EF>(&mut builder, layout)?;
    let root = builder.sub(folded, quotient);

    Ok(AceDag { nodes: builder.into_nodes(), root })
}

/// Convert periodic columns into evaluation coefficients for DAG building.
///
/// The periodic columns are provided as evaluations; this function applies an
/// inverse DFT so the DAG can evaluate them at `z_k` inside the circuit.
pub fn build_periodic_data<F, EF>(
    periodic_table: Vec<Vec<F>>,
) -> Result<PeriodicColumnData<EF>, AceError>
where
    F: TwoAdicField + Ord,
    EF: PrimeCharacteristicRing + From<F>,
{
    if periodic_table.is_empty() {
        return Ok(PeriodicColumnData { max_len: 0, coeffs: Vec::new() });
    }

    let max_len = periodic_table.iter().map(|col| col.len()).max().unwrap_or(0);
    if max_len == 0 {
        return Ok(PeriodicColumnData {
            max_len,
            coeffs: vec![Vec::new(); periodic_table.len()],
        });
    }
    if !max_len.is_power_of_two() {
        return Err(AceError::InvalidPeriodicColumn { index: 0, count: max_len });
    }

    let dft = Radix2DitParallel::<F>::default();
    let mut coeffs = Vec::with_capacity(periodic_table.len());
    for (idx, col) in periodic_table.into_iter().enumerate() {
        if col.is_empty() {
            coeffs.push(Vec::new());
            continue;
        }
        if !col.len().is_power_of_two() {
            return Err(AceError::InvalidPeriodicColumn { index: idx, count: col.len() });
        }
        let values = dft.idft(col);
        let coeff_row = values.into_iter().map(EF::from).collect();
        coeffs.push(coeff_row);
    }

    Ok(PeriodicColumnData { max_len, coeffs })
}

fn build_periodic_nodes<EF>(
    builder: &mut DagBuilder<EF>,
    layout: &crate::layout::InputLayout,
    periodic: &PeriodicColumnData<EF>,
) -> Result<Vec<NodeId>, AceError>
where
    EF: PrimeCharacteristicRing + Copy + Eq + Hash,
{
    if periodic.coeffs.is_empty() {
        return Ok(Vec::new());
    }

    if layout.index(InputKey::ZK).is_none() {
        return Err(AceError::InvalidPeriodicColumn { index: 0, count: periodic.coeffs.len() });
    }

    let mut cache = HashMap::<usize, NodeId>::new();
    let mut nodes = Vec::with_capacity(periodic.coeffs.len());
    for (idx, coeffs) in periodic.coeffs.iter().enumerate() {
        if coeffs.is_empty() {
            nodes.push(builder.constant(EF::ZERO));
            continue;
        }
        let col_len = coeffs.len();
        let max_len = periodic.max_len;
        if !max_len.is_multiple_of(col_len) || !max_len.is_power_of_two() {
            return Err(AceError::InvalidPeriodicColumn { index: idx, count: col_len });
        }
        let ratio = max_len / col_len;
        if !ratio.is_power_of_two() {
            return Err(AceError::InvalidPeriodicColumn { index: idx, count: col_len });
        }
        let log_pow_col = ratio.ilog2() as usize;
        let z_col = *cache.entry(log_pow_col).or_insert_with(|| {
            let mut z_col = builder.input(InputKey::ZK);
            for _ in 0..log_pow_col {
                z_col = builder.mul(z_col, z_col);
            }
            z_col
        });

        let coeff_nodes: Vec<NodeId> = coeffs.iter().map(|c| builder.constant(*c)).collect();
        let value = horner_eval(builder, z_col, &coeff_nodes);
        nodes.push(value);
    }
    Ok(nodes)
}

fn horner_eval<EF>(builder: &mut DagBuilder<EF>, point: NodeId, coeffs: &[NodeId]) -> NodeId
where
    EF: PrimeCharacteristicRing + Copy + Eq + Hash,
{
    let mut acc = builder.constant(EF::ZERO);
    for coeff in coeffs.iter().rev() {
        let mul = builder.mul(point, acc);
        acc = builder.add(*coeff, mul);
    }
    acc
}

fn input_key_for_symbolic<F>(var: &SymbolicVariable<F>) -> Result<InputKey, AceError> {
    let index = var.index;
    let key = match var.entry {
        Entry::Preprocessed { .. } => {
            return Err(AceError::UnsupportedEntry(var.entry));
        },
        Entry::Main { offset } => InputKey::Main { offset, index },
        Entry::Permutation { .. } | Entry::Aux { .. } => {
            return Err(AceError::UnsupportedEntry(var.entry));
        },
        Entry::Periodic => {
            return Err(AceError::UnsupportedEntry(var.entry));
        },
        Entry::AuxBusBoundary => InputKey::AuxBusBoundary(index),
        Entry::Public => InputKey::Public(index),
        Entry::Challenge => InputKey::Randomness(index),
    };
    Ok(key)
}
