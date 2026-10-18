use alloc::string::ToString;
use core::borrow::BorrowMut;

use miden_ace::EvaluationTrace;
use miden_air_source::vm::{
    AceCols, QuadFeltExpr,
    trace::{RowIndex, chiplets::ace::ACE_CHIPLET_NUM_COLS},
};
use miden_core::{
    Felt, Word,
    field::{BasedVectorSpace, QuadFelt},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

use crate::{ContextId, errors::AceError};

/// VM context/clock and AIR-column adapter around pure ACE sequential evaluation records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct CircuitEvaluation {
    ctx: ContextId,
    clk: RowIndex,
    evaluation: EvaluationTrace,
}

impl CircuitEvaluation {
    pub fn new(ctx: ContextId, clk: RowIndex, num_read_rows: u32, num_eval_rows: u32) -> Self {
        Self {
            ctx,
            clk,
            evaluation: EvaluationTrace::new(num_read_rows, num_eval_rows),
        }
    }

    pub fn num_rows(&self) -> usize {
        self.evaluation.num_rows()
    }
    pub fn clk(&self) -> u32 {
        self.clk.into()
    }
    pub fn ctx(&self) -> u32 {
        self.ctx.into()
    }
    pub fn num_read_rows(&self) -> u32 {
        self.evaluation.num_read_rows()
    }
    pub fn num_eval_rows(&self) -> u32 {
        self.evaluation.num_eval_rows()
    }

    pub fn do_read(&mut self, ptr: Felt, word: Word) {
        self.evaluation.do_read(ptr, word);
    }

    pub fn do_eval(&mut self, ptr: Felt, instruction: Felt) -> Result<(), AceError> {
        self.evaluation
            .do_eval(ptr, instruction)
            .map_err(|error| AceError(error.to_string()))
    }

    /// Writes this circuit evaluation's rows into the row-major buffer `out`
    /// (`ACE_CHIPLET_NUM_COLS` contiguous cells per row), starting at row `offset`. `out`
    /// is assumed zero-initialized, so columns that are zero on a row are left untouched.
    pub fn fill(&self, offset: usize, out: &mut [Felt]) {
        const W: usize = ACE_CHIPLET_NUM_COLS;
        let (out_rows, _) = out.as_chunks_mut::<W>();
        let num_read_rows = self.evaluation.read_nodes().len();
        let num_eval_rows = self.evaluation.eval_nodes().len();

        let ctx_felt: Felt = self.ctx.into();
        let clk_felt: Felt = self.clk.into();
        let eval_section_first_idx = Felt::from_u32(num_eval_rows as u32 - 1);
        let mut multiplicities_iter = self.evaluation.multiplicities().map(Felt::from_u32);

        // READ rows.
        for (i, node) in self.evaluation.read_nodes().iter().enumerate() {
            let cols: &mut AceCols<Felt> = out_rows[offset + i].as_mut_slice().borrow_mut();
            cols.s_start = if i == 0 { Felt::ONE } else { Felt::ZERO };
            cols.s_block = Felt::ZERO;
            cols.ctx = ctx_felt;
            cols.clk = clk_felt;
            cols.ptr = node.ptr;
            cols.id_0 = node.id_0;
            cols.v_0 = quad_to_expr(node.v_0);
            cols.id_1 = node.id_1;
            cols.v_1 = quad_to_expr(node.v_1);

            let m_0 = multiplicities_iter
                .next()
                .expect("the m0 multiplicities were not constructed properly");
            let m_1 = multiplicities_iter
                .next()
                .expect("the m1 multiplicities were not constructed properly");

            let read = cols.read_mut();
            read.num_eval = eval_section_first_idx;
            read.m_0 = m_0;
            read.m_1 = m_1;
        }

        // EVAL rows.
        for (i, node) in self.evaluation.eval_nodes().iter().enumerate() {
            let cols: &mut AceCols<Felt> =
                out_rows[offset + num_read_rows + i].as_mut_slice().borrow_mut();
            cols.s_start = Felt::ZERO;
            cols.s_block = Felt::ONE;
            cols.ctx = ctx_felt;
            cols.clk = clk_felt;
            cols.ptr = node.ptr;
            cols.eval_op = node.eval_op;
            cols.id_0 = node.id_0;
            cols.v_0 = quad_to_expr(node.v_0);
            cols.id_1 = node.id_1;
            cols.v_1 = quad_to_expr(node.v_1);

            let m_0 = multiplicities_iter
                .next()
                .expect("the m0 multiplicities were not constructed properly");

            let eval = cols.eval_mut();
            eval.id_2 = node.id_2;
            eval.v_2 = quad_to_expr(node.v_2);
            eval.m_0 = m_0;
        }

        let next = multiplicities_iter.next();
        debug_assert!(next.is_none());
    }

    pub fn output_value(&self) -> Option<QuadFelt> {
        self.evaluation.output_value()
    }
}

/// Lifts a `QuadFelt` value into the [`QuadFeltExpr<Felt>`] basis-coefficient pair expected by the
/// chiplet column structs.
fn quad_to_expr(v: QuadFelt) -> QuadFeltExpr<Felt> {
    let c = v.as_basis_coefficients_slice();
    QuadFeltExpr(c[0], c[1])
}

// Preserve the existing witness encoding: context, clock, bus, READ records, EVAL records.
impl Serializable for CircuitEvaluation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.ctx.write_into(target);
        self.clk.write_into(target);
        self.evaluation.write_into(target);
    }
}

impl Deserializable for CircuitEvaluation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            ctx: ContextId::read_from(source)?,
            clk: RowIndex::read_from(source)?,
            evaluation: EvaluationTrace::read_from(source)?,
        })
    }

    fn min_serialized_size() -> usize {
        ContextId::min_serialized_size()
            + RowIndex::min_serialized_size()
            + EvaluationTrace::min_serialized_size()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary {
    use proptest::prelude::*;

    use super::{CircuitEvaluation, ContextId, EvaluationTrace, RowIndex};

    impl Arbitrary for CircuitEvaluation {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (any::<ContextId>(), any::<RowIndex>(), any::<EvaluationTrace>())
                .prop_map(|(ctx, clk, evaluation)| Self { ctx, clk, evaluation })
                .boxed()
        }
    }
}

#[cfg(test)]
mod legacy_encoding_tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn processor_ace_witness_retains_legacy_field_order_and_bytes() {
        let mut evaluation = CircuitEvaluation::new(ContextId::from(7), RowIndex::from(11), 1, 1);
        evaluation.do_read(
            Felt::from_u32(20),
            Word::new([Felt::from_u32(3), Felt::ZERO, Felt::from_u32(5), Felt::ZERO]),
        );
        evaluation
            .do_eval(Felt::from_u32(24), Felt::new_unchecked(2 + (1 << 30)))
            .unwrap();

        // Frozen pre-extraction encoding: ctx:u32, clk:u32, bus(id_next:Felt, wires:Vec<(EF,u32)>,
        // count:u32), read_nodes:Vec<(ptr,id0,v0,id1,v1)>,
        // eval_nodes:Vec<(ptr,op,id0,v0,id1,v1,id2,v2)>. Build these bytes directly,
        // without invoking the extracted record serializers.
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&11u32.to_le_bytes());
        let p = 0xffff_ffff_0000_0001u64;
        fn felts(bytes: &mut Vec<u8>, values: &[u64]) {
            for value in values {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        felts(&mut expected, &[p - 1]);
        expected.push(7); // vint64 length 3
        for (value, multiplicity) in [(3, 1u32), (5, 1), (p - 2, 0)] {
            felts(&mut expected, &[value, 0]);
            expected.extend_from_slice(&multiplicity.to_le_bytes());
        }
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.push(3); // vint64 READ length 1
        felts(&mut expected, &[20, 2, 3, 0, 1, 5, 0]);
        expected.push(3); // vint64 EVAL length 1
        felts(&mut expected, &[24, p - 1, 0, p - 2, 0, 2, 3, 0, 1, 5, 0]);
        assert_eq!(evaluation.to_bytes(), expected);
        assert_eq!(CircuitEvaluation::read_from_bytes(&expected).unwrap(), evaluation);
    }
}
