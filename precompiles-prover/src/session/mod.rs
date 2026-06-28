//! Keccak-only session facade for the precompile prover MVP.

use miden_core::Felt;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    hash::{
        chunk::trace::{ChunkRequires, generate_trace as chunk_trace},
        keccak::{
            digest::KeccakDigest,
            node::trace::{KeccakNodeRequires, generate_trace as keccak_node_trace},
            round::{RoundRequires, generate_trace as round_trace},
            sponge::trace::{SpongeRequires, generate_trace as sponge_trace},
        },
    },
    primitives::{
        bitwise64::{Bitwise64Requires, generate_trace as bw64_trace},
        byte_pair_lut::{BytePairLutRequires, generate_trace as bpl_trace},
    },
    transcript::{
        eval::trace::{TranscriptEvalRequires, Truthy, generate_trace as eval_trace},
        poseidon2::{
            P2Digest,
            trace::{Poseidon2Requires, generate_trace as p2_trace},
        },
    },
};

mod prove;
pub use prove::{ChipletAir, ChipletMultiAir, SessionProof, VerifyError};

pub const NUM_CHIPLETS: usize = 8;

#[derive(Debug)]
pub struct Session {
    p2: Poseidon2Requires,
    chunk: ChunkRequires,
    round: RoundRequires,
    bw64: Bitwise64Requires,
    bpl: BytePairLutRequires,
    sponge: SpongeRequires,
    node: KeccakNodeRequires,
    eval: TranscriptEvalRequires,
}

impl Session {
    pub fn new() -> Self {
        Self {
            p2: Poseidon2Requires::new(),
            chunk: ChunkRequires::new(),
            round: RoundRequires::new(),
            bw64: Bitwise64Requires::new(),
            bpl: BytePairLutRequires::new(),
            sponge: SpongeRequires::new(),
            node: KeccakNodeRequires::new(),
            eval: TranscriptEvalRequires::new(),
        }
    }

    pub fn keccak(&mut self, input: &[u8]) -> (KeccakDigest, Truthy) {
        let out = self.node.require(
            input,
            &mut self.sponge,
            &mut self.chunk,
            &mut self.round,
            &mut self.bw64,
            &mut self.bpl,
            &mut self.p2,
        );
        let handle = self.eval.issue(out.h_keccak);
        (out.keccak_digest, handle)
    }

    pub fn assert_and(&mut self, a: Truthy, b: Truthy) -> Truthy {
        self.eval.record_and(a, b, &mut self.p2)
    }

    pub fn assert_and_fold(&mut self, handles: impl IntoIterator<Item = Truthy>) -> Truthy {
        let mut acc = self.zero();
        for h in handles {
            acc = self.assert_and(acc, h);
        }
        acc
    }

    pub fn zero(&mut self) -> Truthy {
        self.eval.zero()
    }

    pub fn finish(mut self, root: Truthy) -> SessionTraces {
        let public_root = root.hash();
        let eval = eval_trace(self.eval, root);
        let chunk = chunk_trace(self.chunk);
        let p2 = p2_trace(self.p2);
        let sponge = sponge_trace(self.sponge);
        let node = keccak_node_trace(self.node);
        let round = round_trace(self.round, &mut self.bw64, &mut self.bpl);
        let bw64_active_rows = self.bw64.active_rows();
        let bw64 = bw64_trace(self.bw64);
        let bpl = bpl_trace(self.bpl);

        SessionTraces {
            chunk,
            p2,
            round,
            bw64,
            bpl,
            sponge,
            node,
            eval,
            public_root,
            bw64_active_rows,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SessionTraces {
    chunk: RowMajorMatrix<Felt>,
    p2: RowMajorMatrix<Felt>,
    round: RowMajorMatrix<Felt>,
    bw64: RowMajorMatrix<Felt>,
    bpl: RowMajorMatrix<Felt>,
    sponge: RowMajorMatrix<Felt>,
    node: RowMajorMatrix<Felt>,
    eval: RowMajorMatrix<Felt>,
    public_root: P2Digest,
    bw64_active_rows: usize,
}

impl SessionTraces {
    pub fn mains(&self) -> [&RowMajorMatrix<Felt>; NUM_CHIPLETS] {
        [
            &self.chunk,
            &self.p2,
            &self.round,
            &self.bw64,
            &self.bpl,
            &self.sponge,
            &self.node,
            &self.eval,
        ]
    }

    pub fn air_inputs(&self) -> Vec<Felt> {
        self.public_root.as_array().to_vec()
    }

    pub fn public_root(&self) -> P2Digest {
        self.public_root
    }

    pub fn bw64_active_rows(&self) -> usize {
        self.bw64_active_rows
    }
}
