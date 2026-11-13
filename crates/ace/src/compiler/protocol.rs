//! Captured AIRs and the geometry shared by relation artifact generators.

use miden_constraint_compiler::ir::{CapturedConstraints, Graph, Leaf, Node, OpKind, capture};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{ConstraintCounts, ConstraintDegrees, LiftedAir};

use crate::{
    EXT_DEGREE, InputCounts, MAX_ORDER_AIRS,
    compiler::{AceCircuit, LayoutKind},
};

/// An AIR captured once for both native evaluator and ACE generation.
#[derive(Debug)]
pub struct CapturedAir {
    pub(crate) graph: Graph,
    pub(crate) constraints: CapturedConstraints,
    /// Raw AIR widths; the quotient chunk count is derived from this AIR's degree.
    pub(crate) counts: InputCounts,
    pub(crate) degrees: ConstraintDegrees,
    pub(crate) periodic_columns: Vec<Vec<Felt>>,
    /// Minimum trace height imposed by periodic columns, or zero when absent.
    pub(crate) max_periodic_length: usize,
}

impl CapturedAir {
    /// Captures a code-owned AIR. Panics if its randomness or periodic-column declarations
    /// violate the compiler's conventions.
    pub fn new<A: LiftedAir<Felt, QuadFelt>>(air: &A) -> Self {
        assert_eq!(air.num_randomness(), 2, "AIR must declare alpha and beta challenges");
        let periodic_columns = air.periodic_columns().into_owned();
        assert!(
            periodic_columns.iter().all(|column| column.len().is_power_of_two()),
            "periodic column lengths must be positive powers of two"
        );
        let max_periodic_length = periodic_columns.iter().map(Vec::len).max().unwrap_or(0);
        assert_eq!(
            max_periodic_length,
            air.max_periodic_length(),
            "AIR periodic length hint disagrees with its periodic columns"
        );
        let (graph, constraints) = capture(air);
        let degrees = constraint_degrees(&graph, &constraints);
        let counts = InputCounts {
            preprocessed_width: air.preprocessed_width(),
            width: air.width(),
            aux_width: air.aux_width(),
            num_aux_boundary: air.num_aux_values(),
            num_public: air.num_public_values(),
            num_quotient_chunks: quotient_chunks(degrees.max()),
        };
        Self {
            graph,
            constraints,
            counts,
            degrees,
            periodic_columns,
            max_periodic_length,
        }
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    pub fn constraints(&self) -> &CapturedConstraints {
        &self.constraints
    }

    pub fn degrees(&self) -> ConstraintDegrees {
        self.degrees
    }

    pub(crate) fn constraint_counts(&self) -> ConstraintCounts {
        ConstraintCounts {
            base: self.constraints.base_roots.len(),
            ext: self.constraints.ext_roots.len(),
        }
    }
}

// Match SymbolicExpression::degree_multiple without evaluating the AIR a second time.
fn constraint_degrees(graph: &Graph, constraints: &CapturedConstraints) -> ConstraintDegrees {
    let mut degrees: Vec<usize> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let degree = match node {
            Node::Leaf(
                Leaf::Preprocessed { .. }
                | Leaf::Main { .. }
                | Leaf::Periodic(_)
                | Leaf::IsFirst
                | Leaf::IsLast
                | Leaf::Aux { .. },
            ) => 1,
            Node::Leaf(Leaf::ExtBase(inner)) => degrees[inner.index()],
            Node::Leaf(_) => 0,
            Node::Op { op, x, y, .. } => {
                let x = degrees[x.index()];
                match op {
                    OpKind::Neg => x,
                    OpKind::Add | OpKind::Sub => x.max(degrees[y.unwrap().index()]),
                    OpKind::Mul => x + degrees[y.unwrap().index()],
                }
            },
        };
        degrees.push(degree);
    }
    ConstraintDegrees {
        base: constraints.base_roots.iter().map(|id| degrees[id.index()]).max().unwrap_or(0),
        ext: constraints.ext_roots.iter().map(|id| degrees[id.index()]).max().unwrap_or(0),
    }
}

fn quotient_chunks(degree: usize) -> usize {
    // Constant and linear constraints still require one quotient chunk.
    (degree.max(2) - 1).next_power_of_two()
}

/// A segment of a concatenated committed row, measured in base-field coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowSegment {
    pub offset: usize,
    pub width: usize,
    pub raw_width: usize,
}

/// Physical row segments and constraint metadata for one canonical AIR position.
#[derive(Clone, Debug)]
pub struct AirGeometry {
    /// Public values are concatenated in canonical AIR order without padding.
    pub public_offset: usize,
    pub num_public: usize,
    pub preprocessed: RowSegment,
    pub main: RowSegment,
    pub aux: RowSegment,
    /// Boundary offsets count extension-field values rather than base coordinates.
    pub aux_boundary_offset: usize,
    pub num_aux_boundary: usize,
    pub constraint_counts: ConstraintCounts,
    pub degrees: ConstraintDegrees,
    pub period: usize,
}

/// Geometry derived from the captured AIRs, shared by every generated artifact.
#[derive(Clone, Debug)]
pub struct RelationGeometry {
    pub airs: Vec<AirGeometry>,
    pub preprocessed_width: usize,
    pub main_width: usize,
    /// Committed auxiliary base-field coordinates, including alignment padding.
    pub aux_width: usize,
    pub num_aux_boundary: usize,
    pub num_public: usize,
    pub num_constraints: usize,
    pub max_constraint_degree: usize,
    pub num_quotient_chunks: usize,
    /// Committed quotient base-field coordinates, including alignment padding.
    pub quotient_width: usize,
    pub shared_period: usize,
    pub trace_alignment: usize,
}

impl RelationGeometry {
    fn derive(airs: &[&CapturedAir], alignment: usize, chunks: Option<usize>) -> Self {
        assert!(!airs.is_empty(), "relation must contain at least one AIR");
        let mut result = Self {
            airs: Vec::with_capacity(airs.len()),
            preprocessed_width: 0,
            main_width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 0,
            num_constraints: 0,
            max_constraint_degree: 0,
            num_quotient_chunks: 0,
            quotient_width: 0,
            shared_period: 1,
            trace_alignment: alignment,
        };
        for air in airs {
            let counts = air.counts;
            let preprocessed =
                allocate(&mut result.preprocessed_width, counts.preprocessed_width, alignment);
            let main = allocate(&mut result.main_width, counts.width, alignment);
            let aux = allocate(&mut result.aux_width, counts.aux_width * EXT_DEGREE, alignment);
            assert!(
                aux.width.is_multiple_of(EXT_DEGREE),
                "aligned auxiliary width must be divisible by the extension degree"
            );
            let constraint_counts = air.constraint_counts();
            result.airs.push(AirGeometry {
                public_offset: result.num_public,
                num_public: counts.num_public,
                preprocessed,
                main,
                aux,
                aux_boundary_offset: result.num_aux_boundary,
                num_aux_boundary: counts.num_aux_boundary,
                constraint_counts,
                degrees: air.degrees,
                period: air.max_periodic_length.max(1),
            });
            result.num_public += counts.num_public;
            result.num_aux_boundary += counts.num_aux_boundary;
            result.num_constraints += constraint_counts.total();
            result.max_constraint_degree = result.max_constraint_degree.max(air.degrees.max());
            result.shared_period = result.shared_period.max(air.max_periodic_length);
        }
        result.num_quotient_chunks =
            chunks.unwrap_or(quotient_chunks(result.max_constraint_degree));
        assert!(result.num_quotient_chunks > 0, "num_quotient_chunks must be > 0");
        result.quotient_width =
            (result.num_quotient_chunks * EXT_DEGREE).next_multiple_of(alignment);
        result
    }

    /// Raw committed row widths, in base coordinates and canonical AIR order.
    pub fn raw_widths(&self) -> Vec<(usize, usize, usize)> {
        self.airs
            .iter()
            .map(|air| (air.preprocessed.raw_width, air.main.raw_width, air.aux.raw_width))
            .collect()
    }

    pub fn committed_width(&self) -> usize {
        self.preprocessed_width + self.main_width + self.aux_width + self.quotient_width
    }

    /// Checks the relation shape supported by the MASM LogUp, OOD and DEEP stages.
    ///
    /// Each AIR contributes one normalized boundary value, committed groups use eight-felt
    /// alignment, and every commitment group is nonempty. Relation adapters check these
    /// requirements before generating their MASM artifacts.
    pub fn assert_masm_compatible(&self) {
        let n = self.airs.len();
        assert!(
            (2..=MAX_ORDER_AIRS).contains(&n) && self.trace_alignment == 8,
            "MASM staging requires 2..={MAX_ORDER_AIRS} AIRs and eight-felt trace alignment"
        );
        assert!(
            self.airs.iter().all(|air| air.num_aux_boundary == 1),
            "MASM LogUp staging requires one boundary value per AIR"
        );
        assert!(
            self.preprocessed_width > 0 && self.main_width > 0 && self.aux_width > 0,
            "MASM commitment groups must be nonempty"
        );
    }

    pub(crate) fn input_counts(&self) -> InputCounts {
        InputCounts {
            preprocessed_width: self.preprocessed_width,
            width: self.main_width,
            aux_width: self.aux_width / EXT_DEGREE,
            num_aux_boundary: self.num_aux_boundary,
            num_public: self.num_public,
            num_quotient_chunks: self.num_quotient_chunks,
        }
    }
}

fn allocate(total: &mut usize, raw_width: usize, alignment: usize) -> RowSegment {
    let width = raw_width.next_multiple_of(alignment);
    let segment = RowSegment { offset: *total, width, raw_width };
    *total += width;
    segment
}

/// A relation borrowing captured AIRs in canonical order.
#[derive(Debug)]
pub struct CompiledRelation<'a> {
    pub(crate) airs: Vec<&'a CapturedAir>,
    pub(crate) geometry: RelationGeometry,
}

impl<'a> CompiledRelation<'a> {
    /// Derives a relation from nonempty, code-owned AIRs and a nonzero trace alignment.
    pub fn from_captured(airs: &[&'a CapturedAir], trace_alignment: usize) -> Self {
        Self::with_quotient_chunks(airs, trace_alignment, None)
    }

    pub(crate) fn with_quotient_chunks(
        airs: &[&'a CapturedAir],
        trace_alignment: usize,
        chunks: Option<usize>,
    ) -> Self {
        Self {
            geometry: RelationGeometry::derive(airs, trace_alignment, chunks),
            airs: airs.to_vec(),
        }
    }

    #[cfg(test)]
    pub(crate) fn airs(&self) -> &[&'a CapturedAir] {
        &self.airs
    }

    pub fn geometry(&self) -> &RelationGeometry {
        &self.geometry
    }

    pub fn build_circuit(&self, layout: LayoutKind) -> AceCircuit<QuadFelt> {
        crate::compiler::pipeline::build_circuit_for_relation(self, layout)
    }
}
