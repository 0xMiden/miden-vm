//! Session facade for the precompile prover MVP.

use miden_core::Felt;
use miden_precompiles::UintDomain;
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
    math::{U256, from_limbs32, to_limbs32},
    primitives::{
        bitwise64::{Bitwise64Requires, generate_trace as bw64_trace},
        byte_pair_lut::{BytePairLutRequires, generate_trace as bpl_trace},
    },
    transcript::{
        eval::trace::{
            PinnedUint, TranscriptEvalRequires, TranscriptRoot, Truthy, UintNode,
            generate_trace as eval_trace,
        },
        nodes::UintOpId,
        poseidon2::{
            P2Digest,
            trace::{Poseidon2Requires, generate_trace as p2_trace},
        },
    },
    uint::{
        UintStores,
        add::trace::generate_trace as uint_add_trace,
        mul::trace::generate_trace as uint_mul_trace,
        trace::{UintPtr, generate_trace as uint_trace},
    },
};

mod prove;
pub use prove::{ChipletAir, ChipletMultiAir, SessionProof, VerifyError};

pub const NUM_CHIPLETS: usize = 11;

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
    uint: UintStores,
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
            uint: UintStores::new(),
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

    pub fn pin_modulus(&mut self, addr: u32, bound: U256) -> UintPtr {
        self.uint.store.pin_modulus(addr, bound)
    }

    pub fn pin_domain(&mut self, addr: u32, domain: UintDomain) -> UintPtr {
        let modulus = domain.encoded_modulus();
        assert!(
            modulus != [0; 8],
            "the current uint store does not support the U256 wrapping-domain sentinel",
        );
        self.pin_modulus(addr, from_limbs32(&domain.minus_one()))
    }

    pub fn pin_uint(&mut self, addr: u32, value: U256, bound_ptr: UintPtr) -> PinnedUint {
        let ptr = self.uint.store.intern_pinned(addr, value, bound_ptr);
        self.eval
            .pin_uint(ptr, bound_ptr, to_limbs32(value), &mut self.uint.store, &mut self.p2)
    }

    pub fn uint_leaf(&mut self, value: U256, bound_ptr: UintPtr) -> UintNode {
        let ptr = self.uint.store.intern(value, bound_ptr);
        self.eval
            .uint_leaf(ptr, bound_ptr, to_limbs32(value), &mut self.uint.store, &mut self.p2)
    }

    pub fn uint_add(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.eval.uint_op(UintOpId::Add, a, Some(b), self.uint.require(), &mut self.p2)
    }

    pub fn uint_sub(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.eval.uint_op(UintOpId::Sub, a, Some(b), self.uint.require(), &mut self.p2)
    }

    pub fn uint_mul(&mut self, a: &UintNode, b: &UintNode) -> UintNode {
        self.eval.uint_op(UintOpId::Mul, a, Some(b), self.uint.require(), &mut self.p2)
    }

    pub fn uint_neg(&mut self, a: &UintNode) -> UintNode {
        let _ = a;
        panic!("uint neg has no canonical deferred node in this segment")
    }

    pub fn uint_is(&mut self, a: &UintNode, b: &UintNode) -> Truthy {
        self.eval.record_is(a, b, &mut self.p2)
    }

    pub fn finish(mut self, root: impl Into<TranscriptRoot>) -> SessionTraces {
        let root = root.into();
        let public_root = root.hash();
        self.eval.assert_no_stray_values();
        let eval = eval_trace(self.eval, root);
        let uint_add = uint_add_trace(self.uint.add, &mut self.uint.store);
        let uint_mul = uint_mul_trace(self.uint.mul, &mut self.uint.store, &mut self.bpl);
        let uint_store = uint_trace(self.uint.store, &mut self.bpl);
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
            uint_store,
            uint_add,
            uint_mul,
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
    uint_store: RowMajorMatrix<Felt>,
    uint_add: RowMajorMatrix<Felt>,
    uint_mul: RowMajorMatrix<Felt>,
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
            &self.uint_store,
            &self.uint_add,
            &self.uint_mul,
        ]
    }

    pub fn air_inputs(&self) -> Vec<Felt> {
        self.public_root.as_array().to_vec()
    }

    pub fn public_root(&self) -> P2Digest {
        self.public_root
    }

    #[cfg(test)]
    pub(crate) fn eval_main(&self) -> &RowMajorMatrix<Felt> {
        &self.eval
    }

    pub fn bw64_active_rows(&self) -> usize {
        self.bw64_active_rows
    }
}
