//! Factored ACE emission: a per-proof-order shuffle section composed with an
//! order-invariant common section.
//!
//! The multi-AIR circuit depends on the proof order only through its inputs: which READ
//! slot feeds which canonical wire, and which power of the fold challenge multiplies which
//! per-AIR accumulator. Factored emission lowers the canonical DAG once into a common
//! operation section whose encoding is byte-identical for every proof order, and prefixes
//! it with a short per-order shuffle section that routes proof-order READ slots (and fold
//! coefficients) to the canonical wires the common section consumes.
//!
//! Shuffle-section op positions are fixed across orders (only operand ids vary):
//! 1. one copy gate `Add(input[src], 0)` per shuffled READ slot, in canonical slot order;
//! 2. fold-challenge powers `beta^2 .. beta^(n-1)` by chained `Mul` (order-invariant);
//! 3. one fold-coefficient gate `Add(power(e_j), 0)` per AIR `j` in canonical order;
//! 4. `Add(0, 0)` padding up to an `adv_pipe` block boundary.
//!
//! Because the constants section is also padded to a block boundary, the encoded stream
//! splits into two block-aligned segments: `[constants | shuffle ops]` (per-order) and
//! `[common ops | root padding]` (order-invariant), which the MASM loader hashes
//! separately and the registry binds as `merge(H(prefix_i), H(common))`.

use std::collections::HashMap;

use miden_core::Felt;
use miden_crypto::field::Field;

use crate::{
    AceError, EXT_DEGREE, InputLayout,
    circuit::{AceCircuit, AceNode, AceOp, AceOpNode},
    dag::{AceDag, NodeKind},
    encode::{ADV_PIPE_BLOCK_FELTS, CONST_EF_ALIGN, StreamGeometry},
    layout::InputKey,
};

/// Constants are EF-encoded, so a block boundary is this many EF nodes.
const CONST_EF_BLOCK_ALIGN: usize = ADV_PIPE_BLOCK_FELTS / EXT_DEGREE;

// The factored scheme hashes `[constants | shuffle]` and `[common | padding]` as separate
// adv_pipe-aligned segments. That split only lands on a block boundary if the encoder's
// READ-row rounding (`CONST_EF_ALIGN`) is a no-op on the block-padded constants; otherwise
// `to_ace` would insert extra constant padding and shift the segment boundary mid-block.
const _: () = assert!(
    CONST_EF_BLOCK_ALIGN.is_multiple_of(CONST_EF_ALIGN),
    "constant block alignment must refine the encoder's READ-row alignment, or the two-segment split drifts off a block boundary"
);

/// Index of the seeded zero constant used by copy gates and padding.
const CONST_ZERO: usize = 0;
/// Index of the seeded one constant used for the zero-exponent fold coefficient.
const CONST_ONE: usize = 1;

/// Reusable scratch for `FactoredMultiAirCircuit::encode_shuffle_section_for_order`.
///
/// Holds the per-order sources, exponents, validation marks, operations, and encoded felts across
/// calls so a caller enumerating many orderings does not regrow them each time.
#[derive(Clone, Debug, Default)]
pub struct ShuffleEncodeBuffer {
    srcs: Vec<usize>,
    exponents: Vec<usize>,
    seen_srcs: Vec<bool>,
    seen_exponents: Vec<bool>,
    ops: Vec<AceOpNode>,
    felts: Vec<Felt>,
}

impl ShuffleEncodeBuffer {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the per-order shuffle-source and fold-exponent scratch.
    pub(crate) fn order_scratch(&mut self) -> (&mut Vec<usize>, &mut Vec<usize>) {
        (&mut self.srcs, &mut self.exponents)
    }
}

/// Multi-AIR ACE circuit factored into a per-order shuffle section and a common section.
#[derive(Debug, Clone)]
pub struct FactoredAceCircuit<EF> {
    layout: InputLayout,
    /// Seeded `[0, 1]` followed by the canonical DAG constants, padded to a block boundary.
    constants: Vec<EF>,
    /// Canonical (destination) global input index of each shuffle copy gate.
    shuffle_dsts: Vec<usize>,
    /// Membership map for [`Self::shuffle_dsts`], indexed by global input index.
    shuffle_dst_mask: Vec<bool>,
    /// Number of fold coefficients (one per AIR).
    num_fold_coeffs: usize,
    /// Total shuffle-section ops: copies + power muls + coefficient gates + padding.
    num_shuffle_ops: usize,
    /// Common-section ops; operands reference absolute node positions.
    common_ops: Vec<AceOpNode>,
    /// Node-id bases of the assembled stream; identical for every proof order.
    geometry: StreamGeometry,
}

impl<EF: Field> FactoredAceCircuit<EF> {
    /// Return the input layout shared by every assembled circuit.
    pub fn layout(&self) -> &InputLayout {
        &self.layout
    }

    /// Number of shuffle-section ops (also the section length in stream felts).
    pub fn num_shuffle_ops(&self) -> usize {
        self.num_shuffle_ops
    }

    /// Emit the shuffle-section operations for one proof order, appending to `out`.
    ///
    /// Shared by [`Self::assemble`] and [`Self::encode_shuffle_section`] so the assembled
    /// circuit and the encode-only registry path cannot drift apart.
    ///
    /// `AceNode::Operation` operands are absolute indices into the finished operation list,
    /// so the power-chain base is taken relative to `out`'s current length rather than
    /// assuming this is the first emission into it.
    fn emit_shuffle_ops(
        &self,
        shuffle_srcs: &[usize],
        coeff_exponents: &[usize],
        beta: Option<usize>,
        out: &mut Vec<AceOpNode>,
    ) {
        let start = out.len();
        let zero = AceNode::Constant(CONST_ZERO);
        let beta_node =
            || AceNode::Input(beta.expect("fold challenge is required beyond a single fold slot"));
        let powers_start = start + self.shuffle_dsts.len();
        let power_node = |e: usize| match e {
            0 => AceNode::Constant(CONST_ONE),
            1 => beta_node(),
            _ => AceNode::Operation(powers_start + (e - 2)),
        };

        for &src in shuffle_srcs {
            out.push(AceOpNode {
                op: AceOp::Add,
                lhs: AceNode::Input(src),
                rhs: zero,
            });
        }
        for e in 2..self.num_fold_coeffs {
            out.push(AceOpNode {
                op: AceOp::Mul,
                lhs: power_node(e - 1),
                rhs: beta_node(),
            });
        }
        for &e in coeff_exponents {
            out.push(AceOpNode {
                op: AceOp::Add,
                lhs: power_node(e),
                rhs: zero,
            });
        }
        debug_assert!(
            out.len() - start <= self.num_shuffle_ops,
            "shuffle emission overran its section and would displace the common ops"
        );
        while out.len() - start < self.num_shuffle_ops {
            out.push(AceOpNode { op: AceOp::Add, lhs: zero, rhs: zero });
        }
    }

    /// Encode the shuffle section for the sources and exponents already staged in `buffer`
    /// (see [`ShuffleEncodeBuffer::order_scratch`]), reusing its allocations.
    ///
    /// Equivalent to taking the shuffle slice of `assemble(..).to_ace()`'s instruction
    /// stream, without building the circuit or encoding the order-invariant common section.
    /// Registry construction visits every proof order, so it pays only the per-order bytes.
    ///
    /// Rejects the same layouts [`AceCircuit::to_ace`] does. This path never builds an
    /// `AceCircuit`, so without that check it would return felts for a stream that the
    /// encoder — and therefore the chiplet — would refuse, and a registry built over it
    /// would commit to circuits that can never be evaluated.
    pub(crate) fn encode_shuffle_section<'a>(
        &self,
        buffer: &'a mut ShuffleEncodeBuffer,
    ) -> Result<&'a [Felt], AceError> {
        self.geometry.validate()?;

        let beta = self.validate_assembly_with_scratch(
            &buffer.srcs,
            &buffer.exponents,
            &mut buffer.seen_srcs,
            &mut buffer.seen_exponents,
        )?;

        let mut ops = core::mem::take(&mut buffer.ops);
        ops.clear();
        self.emit_shuffle_ops(&buffer.srcs, &buffer.exponents, beta, &mut ops);
        buffer.ops = ops;

        buffer.felts.clear();
        buffer.felts.reserve(buffer.ops.len());
        for op in &buffer.ops {
            buffer.felts.push(self.geometry.encode_operation(op)?);
        }
        Ok(&buffer.felts)
    }

    /// Shared precondition check for both the assembly and encode-only paths.
    ///
    /// Checks that `shuffle_srcs` is a permutation of the destination slots and that
    /// `coeff_exponents` is a permutation of `0..num_fold_coeffs`; a repeated exponent
    /// would silently produce a degenerate fold rather than an error.
    ///
    /// Returns the fold-challenge input slot, which is absent only for a single-slot fold.
    fn validate_assembly(
        &self,
        shuffle_srcs: &[usize],
        coeff_exponents: &[usize],
    ) -> Result<Option<usize>, AceError> {
        let mut seen_srcs = Vec::new();
        let mut seen_exponents = Vec::new();
        self.validate_assembly_with_scratch(
            shuffle_srcs,
            coeff_exponents,
            &mut seen_srcs,
            &mut seen_exponents,
        )
    }

    fn validate_assembly_with_scratch(
        &self,
        shuffle_srcs: &[usize],
        coeff_exponents: &[usize],
        seen_srcs: &mut Vec<bool>,
        seen_exponents: &mut Vec<bool>,
    ) -> Result<Option<usize>, AceError> {
        if shuffle_srcs.len() != self.shuffle_dsts.len() {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "shuffle source count ({}) does not match destination count ({})",
                    shuffle_srcs.len(),
                    self.shuffle_dsts.len()
                ),
            });
        }
        if !is_exact_permutation(
            shuffle_srcs,
            self.shuffle_dsts.len(),
            &self.shuffle_dst_mask,
            seen_srcs,
        ) {
            return Err(AceError::InvalidInputLayout {
                message: "shuffle sources must be a permutation of the shuffled slots".into(),
            });
        }
        if coeff_exponents.len() != self.num_fold_coeffs {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "fold coefficient count ({}) does not match AIR count ({})",
                    coeff_exponents.len(),
                    self.num_fold_coeffs
                ),
            });
        }
        // The fold assigns each slot a distinct challenge power, so the exponents must be a
        // permutation. A repeated exponent still encodes into a well-formed circuit, so this is
        // the only place it can be caught.
        seen_exponents.resize(self.num_fold_coeffs, false);
        seen_exponents.fill(false);
        for &exponent in coeff_exponents {
            let seen =
                seen_exponents.get_mut(exponent).ok_or_else(|| AceError::InvalidInputLayout {
                    message: format!("fold coefficient exponent {exponent} out of range"),
                })?;
            if *seen {
                return Err(AceError::InvalidInputLayout {
                    message: format!("fold coefficient exponent {exponent} is used twice"),
                });
            }
            *seen = true;
        }

        // A single-slot fold only ever uses the exponent 0, so the challenge itself is not
        // referenced and need not be present in the layout.
        let beta = match self.layout.index(InputKey::MultiAirFoldBeta) {
            Some(beta) => Some(beta),
            None if self.num_fold_coeffs == 1 => None,
            None => {
                return Err(AceError::InvalidInputLayout {
                    message: "factored circuit requires a MultiAirFoldBeta input slot".into(),
                });
            },
        };
        Ok(beta)
    }

    /// Assemble the full circuit for one proof order.
    ///
    /// `shuffle_srcs[i]` is the proof-order (source) global input index feeding the `i`-th
    /// shuffle copy gate; it must be a permutation of the destination slots.
    /// `coeff_exponents[j]` is the fold-challenge exponent assigned to canonical AIR `j`.
    pub fn assemble(
        &self,
        shuffle_srcs: &[usize],
        coeff_exponents: &[usize],
    ) -> Result<AceCircuit<EF>, AceError> {
        let beta = self.validate_assembly(shuffle_srcs, coeff_exponents)?;

        let mut operations = Vec::with_capacity(self.num_shuffle_ops + self.common_ops.len());
        self.emit_shuffle_ops(shuffle_srcs, coeff_exponents, beta, &mut operations);
        operations.extend_from_slice(&self.common_ops);

        let root = AceNode::Operation(operations.len() - 1);
        Ok(AceCircuit {
            layout: self.layout.clone(),
            constants: self.constants.clone(),
            operations,
            root,
        })
    }
}

/// Return whether `values` has `expected_len` distinct entries admitted by `membership`.
fn is_exact_permutation(
    values: &[usize],
    expected_len: usize,
    membership: &[bool],
    seen: &mut Vec<bool>,
) -> bool {
    if values.len() != expected_len {
        return false;
    }
    seen.resize(membership.len(), false);
    seen.fill(false);
    values.iter().all(|&value| {
        let Some(true) = membership.get(value).copied() else {
            return false;
        };
        !core::mem::replace(&mut seen[value], true)
    })
}

/// Lower a canonical multi-AIR DAG into a factored circuit.
///
/// `shuffle_dsts` enumerates the canonical global input indices of every shuffled READ
/// slot (the order fixes the copy-gate order shared by all proof orders). The DAG may
/// reference shuffled slots only through those destinations, and fold coefficients only
/// through [`InputKey::MultiAirFoldCoeff`] with index below `num_fold_coeffs`.
pub fn emit_factored_circuit<EF>(
    dag: &AceDag<EF>,
    layout: InputLayout,
    shuffle_dsts: Vec<usize>,
    num_fold_coeffs: usize,
) -> Result<FactoredAceCircuit<EF>, AceError>
where
    EF: Field,
{
    layout.validate();
    if num_fold_coeffs == 0 {
        return Err(AceError::InvalidInputLayout {
            message: "factored circuit requires at least one fold coefficient".into(),
        });
    }

    let mut copy_by_dst = HashMap::with_capacity(shuffle_dsts.len());
    let mut shuffle_dst_mask = vec![false; layout.total_inputs];
    for (copy_idx, &dst) in shuffle_dsts.iter().enumerate() {
        if dst >= layout.total_inputs {
            return Err(AceError::InvalidInputLayout {
                message: format!("shuffle destination {dst} is outside the READ layout"),
            });
        }
        if copy_by_dst.insert(dst, copy_idx).is_some() {
            return Err(AceError::InvalidInputLayout {
                message: format!("duplicate shuffle destination {dst}"),
            });
        }
        shuffle_dst_mask[dst] = true;
    }

    let num_copies = shuffle_dsts.len();
    let num_power_ops = num_fold_coeffs.saturating_sub(2);
    let unpadded = num_copies + num_power_ops + num_fold_coeffs;
    let num_shuffle_ops = unpadded.next_multiple_of(ADV_PIPE_BLOCK_FELTS);
    let coeffs_start = num_copies + num_power_ops;

    let mut constants = vec![EF::ZERO, EF::ONE];
    let mut constant_map = HashMap::<EF, usize>::new();
    constant_map.insert(EF::ZERO, CONST_ZERO);
    constant_map.insert(EF::ONE, CONST_ONE);

    let mut common_ops: Vec<AceOpNode> = Vec::new();
    let mut node_map: Vec<Option<AceNode>> = vec![None; dag.nodes().len()];

    let lookup = |map: &[Option<AceNode>], id: crate::dag::NodeId| -> AceNode {
        map[id.index()].expect("ACE DAG nodes must be topologically ordered")
    };

    for (idx, node) in dag.nodes().iter().enumerate() {
        let ace_node = match node {
            NodeKind::Input(InputKey::MultiAirFoldCoeff(air)) => {
                if *air >= num_fold_coeffs {
                    return Err(AceError::InvalidInputLayout {
                        message: format!("fold coefficient index {air} out of range"),
                    });
                }
                AceNode::Operation(coeffs_start + air)
            },
            NodeKind::Input(key) => {
                let input_idx = layout.index(*key).ok_or_else(|| AceError::InvalidInputLayout {
                    message: format!("missing input key in layout: {key:?}"),
                })?;
                match copy_by_dst.get(&input_idx) {
                    Some(&copy_idx) => AceNode::Operation(copy_idx),
                    // Reading a slot directly is only correct for keys whose position does not
                    // depend on the proof order. This match is exhaustive on purpose: a new
                    // per-AIR input kind must fail to compile here rather than silently wire a
                    // proof-order slot into the canonical section.
                    None => match *key {
                        InputKey::Public(_)
                        | InputKey::AuxRandAlpha
                        | InputKey::AuxRandBeta
                        | InputKey::MultiAirFoldBeta
                        | InputKey::Reserved
                        | InputKey::Alpha
                        | InputKey::ZPowN
                        | InputKey::ZK
                        | InputKey::IsFirst
                        | InputKey::IsLast
                        | InputKey::IsTransition
                        | InputKey::IsFirstAir(_)
                        | InputKey::IsLastAir(_)
                        | InputKey::IsTransitionAir(_)
                        | InputKey::Weight0
                        | InputKey::F
                        | InputKey::S0
                        | InputKey::QuotientChunkCoord { .. } => AceNode::Input(input_idx),
                        // Per-AIR regions are laid out in proof order, so they must be reached
                        // through the shuffle. Preprocessed traces are committed per AIR in the
                        // same height-sorted order as main traces (see lifted-stark's
                        // `preprocessed_air_for_trace_index`), so they shuffle identically.
                        InputKey::Preprocessed { .. }
                        | InputKey::Main { .. }
                        | InputKey::AuxCoord { .. }
                        | InputKey::AuxBusBoundary(_) => {
                            return Err(AceError::InvalidInputLayout {
                                message: format!(
                                    "shuffled input key {key:?} has no shuffle destination"
                                ),
                            });
                        },
                        // Resolved above, before the layout lookup.
                        InputKey::MultiAirFoldCoeff(_) => unreachable!(),
                    },
                }
            },
            NodeKind::Constant(value) => {
                let const_idx = *constant_map.entry(*value).or_insert_with(|| {
                    constants.push(*value);
                    constants.len() - 1
                });
                AceNode::Constant(const_idx)
            },
            NodeKind::Add(a, b) => {
                let (lhs, rhs) = (lookup(&node_map, *a), lookup(&node_map, *b));
                common_ops.push(AceOpNode { op: AceOp::Add, lhs, rhs });
                AceNode::Operation(num_shuffle_ops + common_ops.len() - 1)
            },
            NodeKind::Sub(a, b) => {
                let (lhs, rhs) = (lookup(&node_map, *a), lookup(&node_map, *b));
                common_ops.push(AceOpNode { op: AceOp::Sub, lhs, rhs });
                AceNode::Operation(num_shuffle_ops + common_ops.len() - 1)
            },
            NodeKind::Mul(a, b) => {
                let (lhs, rhs) = (lookup(&node_map, *a), lookup(&node_map, *b));
                common_ops.push(AceOpNode { op: AceOp::Mul, lhs, rhs });
                AceNode::Operation(num_shuffle_ops + common_ops.len() - 1)
            },
            NodeKind::Neg(a) => {
                let rhs = lookup(&node_map, *a);
                common_ops.push(AceOpNode {
                    op: AceOp::Sub,
                    lhs: AceNode::Constant(CONST_ZERO),
                    rhs,
                });
                AceNode::Operation(num_shuffle_ops + common_ops.len() - 1)
            },
        };
        node_map[idx] = Some(ace_node);
    }

    match lookup(&node_map, dag.root()) {
        AceNode::Operation(idx) if idx == num_shuffle_ops + common_ops.len() - 1 => {},
        other => {
            return Err(AceError::InvalidInputLayout {
                message: format!("factored DAG root must be the last common op, got {other:?}"),
            });
        },
    }

    // Block-align the constants so both encoded segments start on adv_pipe boundaries.
    let padded_len = constants.len().next_multiple_of(CONST_EF_BLOCK_ALIGN);
    constants.resize(padded_len, EF::ZERO);

    // The assembled stream has the same node counts for every proof order, so its node-id
    // bases can be fixed here. `from_counts` applies the encoder's padding rules, so this
    // geometry is the one `to_ace` derives for every circuit assembled from this factoring.
    let num_ops = num_shuffle_ops + common_ops.len();
    let geometry = StreamGeometry::from_counts(layout.total_inputs, constants.len(), num_ops);

    Ok(FactoredAceCircuit {
        layout,
        constants,
        shuffle_dsts,
        shuffle_dst_mask,
        num_fold_coeffs,
        num_shuffle_ops,
        common_ops,
        geometry,
    })
}

#[cfg(test)]
mod tests {
    use super::is_exact_permutation;

    #[test]
    fn exact_permutation_rejects_missing_duplicate_and_foreign_values() {
        let membership = [false, true, false, true, true];
        let mut seen = Vec::new();

        assert!(is_exact_permutation(&[4, 1, 3], 3, &membership, &mut seen));
        assert!(!is_exact_permutation(&[1, 3], 3, &membership, &mut seen));
        assert!(!is_exact_permutation(&[1, 1, 4], 3, &membership, &mut seen));
        assert!(!is_exact_permutation(&[1, 2, 4], 3, &membership, &mut seen));
        assert!(!is_exact_permutation(&[1, 3, 5], 3, &membership, &mut seen));
    }
}
