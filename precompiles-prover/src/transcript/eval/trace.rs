//! Trace generation for the Keccak-MVP transcript eval chiplet.

use std::collections::{BTreeMap, BTreeSet};

use miden_core::{Felt, field::QuadFelt};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    logup::build_logup_aux_trace,
    relations::ProvideMult,
    transcript::{
        eval::{
            COL_ACT, COL_H_BEGIN, COL_IS_AND, COL_IS_ZERO, COL_LHS_BEGIN, COL_OUT_MULT,
            COL_PERM_SEQ_ID, COL_RHS_BEGIN, NUM_HASH, NUM_MAIN_COLS, TranscriptEvalAir,
        },
        poseidon2::{
            P2Cap, P2Digest,
            trace::{PermSeqId, Poseidon2Requires},
        },
    },
};

#[derive(Debug)]
pub struct Truthy {
    id: u32,
    hash: P2Digest,
}

impl Truthy {
    pub fn hash(&self) -> P2Digest {
        self.hash
    }
}

#[derive(Debug)]
struct EvalNode {
    id: u32,
    absorbed: Option<Absorbed>,
    kind: NodeKind,
}

#[derive(Debug, Clone, Copy)]
struct Absorbed {
    hash: P2Digest,
    perm_seq_id: PermSeqId,
}

#[derive(Debug)]
enum NodeKind {
    Zero,
    And { lhs: P2Digest, rhs: P2Digest },
}

#[derive(Debug, Default)]
pub struct TranscriptEvalRequires {
    next_id: u32,
    live: BTreeSet<u32>,
    node_consumers: BTreeMap<u32, ProvideMult>,
    nodes: Vec<EvalNode>,
}

impl TranscriptEvalRequires {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&mut self, hash: P2Digest) -> Truthy {
        self.fresh(hash)
    }

    pub fn zero(&mut self) -> Truthy {
        let t = self.fresh(P2Digest::default());
        self.nodes.push(EvalNode {
            id: t.id,
            absorbed: None,
            kind: NodeKind::Zero,
        });
        t
    }

    pub fn record_and(&mut self, a: Truthy, b: Truthy, p2: &mut Poseidon2Requires) -> Truthy {
        let (lhs, rhs) = (a.hash, b.hash);
        self.consume(a);
        self.consume(b);
        let absorption = p2.require_one_shot(P2Cap::and(), lhs.as_array(), rhs.as_array());
        let _ = p2.require_digest(absorption.digest);
        let hash = absorption.digest;
        let out = self.fresh(hash);
        self.nodes.push(EvalNode {
            id: out.id,
            absorbed: Some(Absorbed { hash, perm_seq_id: absorption.head() }),
            kind: NodeKind::And { lhs, rhs },
        });
        out
    }

    fn fresh(&mut self, hash: P2Digest) -> Truthy {
        let id = self.next_id;
        self.next_id += 1;
        self.live.insert(id);
        self.node_consumers.entry(id).or_insert(0);
        Truthy { id, hash }
    }

    fn consume(&mut self, t: Truthy) {
        assert!(self.live.remove(&t.id), "truthy handle consumed twice or by foreign eval");
        *self.node_consumers.entry(t.id).or_insert(0) += 1;
    }
}

pub fn generate_trace(mut requires: TranscriptEvalRequires, root: Truthy) -> RowMajorMatrix<Felt> {
    let root_id = root.id;
    assert!(
        requires.live.remove(&root_id),
        "root handle was already consumed or does not belong to this eval"
    );
    assert!(requires.live.is_empty(), "issued truthy handles left unconsumed");

    let root_pos = requires
        .nodes
        .iter()
        .position(|n| n.id == root_id)
        .expect("root must be a recorded eval node");
    let root_node = requires.nodes.remove(root_pos);

    let active_rows = 1 + requires.nodes.len();
    let height = active_rows.next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    push_node_row(&mut trace, root_node, 0, &requires.node_consumers);
    for node in requires.nodes {
        let out_mult = requires.node_consumers[&node.id];
        push_node_row(&mut trace, node, out_mult, &requires.node_consumers);
    }

    trace.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

fn push_node_row(
    trace: &mut Vec<Felt>,
    node: EvalNode,
    out_mult: ProvideMult,
    consumers: &BTreeMap<u32, ProvideMult>,
) {
    let mut row = [Felt::ZERO; NUM_MAIN_COLS];
    row[COL_ACT] = Felt::ONE;
    row[COL_OUT_MULT] = Felt::from(out_mult);

    match node.kind {
        NodeKind::Zero => {
            assert_eq!(node.absorbed.map(|a| a.hash), None);
            row[COL_IS_ZERO] = Felt::ONE;
        },
        NodeKind::And { lhs, rhs } => {
            let absorbed = node.absorbed.expect("AND nodes drive Poseidon2");
            row[COL_IS_AND] = Felt::ONE;
            row[COL_PERM_SEQ_ID] = Felt::from(absorbed.perm_seq_id.seq());
            row[COL_LHS_BEGIN..COL_LHS_BEGIN + NUM_HASH].copy_from_slice(&lhs.as_array());
            row[COL_RHS_BEGIN..COL_RHS_BEGIN + NUM_HASH].copy_from_slice(&rhs.as_array());
            row[COL_H_BEGIN..COL_H_BEGIN + NUM_HASH].copy_from_slice(&absorbed.hash.as_array());
        },
    }

    if consumers[&node.id] == 0 {
        row[COL_OUT_MULT] = Felt::ZERO;
    }
    trace.extend(row);
}

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&TranscriptEvalAir, main, challenges)
}
