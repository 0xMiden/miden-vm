//! Batch STARK AIR wrappers, lookup implementations, and prove/verify runner.

use miden_lifted_stark::{
    air::{BaseAir, log2_strict_u8},
    testing::airs::poseidon2::NUM_POSEIDON2_COLS,
};
use p3_air::{Air, AirBuilder, AirLayout, BaseLeaf, SymbolicExpression, WindowAccess};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_blake3_air::{Blake3Air, NUM_BLAKE3_COLS};
use p3_commit::ExtensionMmcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS};
use p3_lookup::{
    LookupAir,
    lookup_traits::{Direction, Kind, Lookup},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_uni_stark::SymbolicAirBuilder;
use tracing::info_span;

use crate::{
    BatchPoseidon2Air, Felt, GlRoundConstants, QuadFelt, RunResult,
    cli::{AirType, Cli, TraceSpec},
};

// ═══════════════════════════════════════════════════════════════════════════════
// Keccak wrapper with a single local lookup
// ═══════════════════════════════════════════════════════════════════════════════

/// Wraps [`KeccakAir`] and adds a single local LogUp lookup producing one
/// extension-field permutation column. Matches the lifted prover's unconditional
/// 1-column EF aux trace.
#[derive(Clone)]
struct KeccakWithLookup {
    num_lookups: usize,
}

impl<F> BaseAir<F> for KeccakWithLookup {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for KeccakWithLookup {
    fn eval(&self, builder: &mut AB) {
        Air::eval(&KeccakAir {}, builder);
    }
}

impl<F: Field> LookupAir<F> for KeccakWithLookup {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;
        let col0 = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let one = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let lookup_inputs = vec![
            (vec![col0.clone()], one.clone(), Direction::Send),
            (vec![col0], one, Direction::Receive),
        ];
        vec![LookupAir::register_lookup(self, Kind::Local, &lookup_inputs)]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Miden wrapper with N local lookups
// ═══════════════════════════════════════════════════════════════════════════════

/// Wraps the Miden degree-9 constraint and adds `num_lookups_target` local LogUp
/// lookups, each producing one EF permutation column.
#[derive(Clone)]
struct MidenWithLookups {
    width: usize,
    num_lookups_target: usize,
    num_lookups: usize,
}

impl<F> BaseAir<F> for MidenWithLookups {
    fn width(&self) -> usize {
        self.width
    }
}

impl<AB: AirBuilder> Air<AB> for MidenWithLookups {
    fn eval(&self, builder: &mut AB) {
        // Same degree-9 constraint as DummyMidenAir.
        let main = builder.main();
        let local = main.current_slice();
        let product = (0..9).fold(AB::Expr::ONE, |acc, j| acc * local[j].into());
        builder.assert_zero(product);
    }
}

impl<F: Field> LookupAir<F> for MidenWithLookups {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let idx = self.num_lookups;
        self.num_lookups += 1;
        vec![idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        self.num_lookups = 0;
        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: self.width,
            ..AirLayout::default()
        });
        let main = symbolic.main();
        let local = main.current_slice();
        let col0: SymbolicExpression<F> = local[0].into();
        let one = SymbolicExpression::Leaf(BaseLeaf::Constant(F::ONE));
        let lookup_inputs = vec![
            (vec![col0.clone()], one.clone(), Direction::Send),
            (vec![col0], one, Direction::Receive),
        ];
        (0..self.num_lookups_target)
            .map(|_| LookupAir::register_lookup(self, Kind::Local, &lookup_inputs))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Batch AIR enum
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
enum BatchBenchAir {
    Keccak(KeccakWithLookup),
    Poseidon2(Box<BatchPoseidon2Air>),
    Blake3,
    Miden(MidenWithLookups),
}

impl<F> BaseAir<F> for BatchBenchAir {
    fn width(&self) -> usize {
        match self {
            Self::Keccak(a) => BaseAir::<F>::width(a),
            Self::Poseidon2(_) => NUM_POSEIDON2_COLS,
            Self::Blake3 => NUM_BLAKE3_COLS,
            Self::Miden(a) => BaseAir::<F>::width(a),
        }
    }
}

impl<AB: AirBuilder<F = Felt>> Air<AB> for BatchBenchAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Keccak(a) => Air::eval(a, builder),
            Self::Poseidon2(a) => Air::eval(a.as_ref(), builder),
            Self::Blake3 => Air::eval(&Blake3Air {}, builder),
            Self::Miden(a) => Air::eval(a, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for BatchBenchAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Keccak(a) => <KeccakWithLookup as LookupAir<F>>::add_lookup_columns(a),
            Self::Miden(a) => <MidenWithLookups as LookupAir<F>>::add_lookup_columns(a),
            Self::Poseidon2(_) | Self::Blake3 => vec![],
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Keccak(a) => <KeccakWithLookup as LookupAir<F>>::get_lookups(a),
            Self::Miden(a) => <MidenWithLookups as LookupAir<F>>::get_lookups(a),
            Self::Poseidon2(_) | Self::Blake3 => vec![],
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Batch config macro
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a `p3_uni_stark::StarkConfig` for batch-STARK from MMCS components.
///
/// Parameterized over packed field/digest types and digest size, since these
/// differ per hash function and cannot be inferred from the constructor.
macro_rules! batch_config {
    (
        $P:ty,
        $PD:ty,
        $DIGEST:expr,
        $leaf:expr,
        $compress:expr,
        $challenger:expr,
        $log_blowup:expr,
        $cli:expr
    ) => {{
        type Dft = p3_dft::Radix2DitParallel<Felt>;
        let mmcs: MerkleTreeMmcs<$P, $PD, _, _, 2, $DIGEST> =
            MerkleTreeMmcs::new($leaf, $compress, 0);
        let challenge_mmcs = ExtensionMmcs::<Felt, QuadFelt, _>::new(mmcs.clone());
        let fri_params = FriParameters {
            log_blowup: $log_blowup as usize,
            log_final_poly_len: $cli.log_final_degree as usize,
            max_log_arity: $cli.log_folding_arity as usize,
            num_queries: $cli.num_queries,
            commit_proof_of_work_bits: $cli.folding_pow_bits,
            query_proof_of_work_bits: $cli.query_pow_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = TwoAdicFriPcs::new(Dft::default(), mmcs, fri_params);
        p3_uni_stark::StarkConfig::new(pcs, $challenger)
    }};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runner
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) fn run_batch<SC>(
    config: &SC,
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    cli: &Cli,
) -> RunResult
where
    SC: p3_uni_stark::StarkGenericConfig<Challenge = QuadFelt>,
    <SC::Pcs as p3_commit::Pcs<QuadFelt, SC::Challenger>>::Domain:
        p3_commit::PolynomialSpace<Val = Felt>,
{
    let mut airs: Vec<BatchBenchAir> = specs
        .iter()
        .map(|spec| match spec.air_type {
            AirType::Keccak => BatchBenchAir::Keccak(KeccakWithLookup { num_lookups: 0 }),
            AirType::Poseidon2 => {
                let c = constants.as_ref().expect("poseidon2 constants required");
                BatchBenchAir::Poseidon2(Box::new(BatchPoseidon2Air::new(c.clone())))
            },
            AirType::Blake3 => BatchBenchAir::Blake3,
            AirType::Miden => BatchBenchAir::Miden(MidenWithLookups {
                width: spec.width,
                num_lookups_target: spec.num_aux_cols,
                num_lookups: 0,
            }),
        })
        .collect();

    let degree_bits: Vec<usize> =
        traces.iter().map(|t| log2_strict_u8(t.height()) as usize).collect();
    let prover_data = ProverData::from_airs_and_degrees(config, &mut airs, &degree_bits);
    let common = &prover_data.common;

    let trace_refs: Vec<&RowMajorMatrix<Felt>> = traces.iter().collect();
    let pvs: Vec<Vec<Felt>> = specs.iter().map(|_| vec![]).collect();

    let instances = StarkInstance::new_multiple(&airs, &trace_refs, &pvs, common);

    let proof = info_span!("prove").in_scope(|| prove_batch(config, &instances, &prover_data));

    let result = RunResult {
        proof_size_bytes: postcard::to_allocvec(&proof).expect("serialization failed").len(),
        field_elems: 0,
        commitments: 0,
    };

    if !cli.no_verify {
        info_span!("verify").in_scope(|| {
            verify_batch(config, &airs, &proof, &pvs, common)
                .expect("batch-stark verification failed");
        });
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Batch config constructors (called from main)
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) fn run_batch_poseidon2(
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    log_blowup: u8,
    cli: &Cli,
) -> RunResult {
    use miden_lifted_stark::testing::configs::goldilocks_poseidon2 as gl;
    use p3_symmetric::PaddingFreeSponge;

    let (perm, _, compress) = gl::test_components();
    let leaf = PaddingFreeSponge::<_, { gl::WIDTH }, { gl::RATE }, { gl::DIGEST }>::new(perm);
    let config = batch_config!(
        gl::PackedFelt,
        gl::PackedFelt,
        { gl::DIGEST },
        leaf,
        compress,
        gl::test_challenger(),
        log_blowup,
        cli
    );
    run_batch(&config, specs, traces, constants, cli)
}

pub(crate) fn run_batch_keccak(
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    log_blowup: u8,
    cli: &Cli,
) -> RunResult {
    use miden_lifted_stark::testing::configs::goldilocks_keccak as keccak;
    use p3_keccak::KeccakF;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    let u64_hash = U64Hash::new(KeccakF);
    let leaf = SerializingHasher::new(u64_hash);
    let compress = CompressionFunctionFromHasher::<U64Hash, 2, 4>::new(u64_hash);
    let config = batch_config!(
        [Felt; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        4,
        leaf,
        compress,
        keccak::test_challenger(),
        log_blowup,
        cli
    );
    run_batch(&config, specs, traces, constants, cli)
}

pub(crate) fn run_batch_blake3(
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    log_blowup: u8,
    cli: &Cli,
) -> RunResult {
    use miden_lifted_stark::testing::configs::goldilocks_blake3 as blake3;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    let leaf = SerializingHasher::new(p3_blake3::Blake3);
    let compress = CompressionFunctionFromHasher::<p3_blake3::Blake3, 2, { blake3::DIGEST }>::new(
        p3_blake3::Blake3,
    );
    let config = batch_config!(
        Felt,
        u8,
        { blake3::DIGEST },
        leaf,
        compress,
        blake3::test_challenger(),
        log_blowup,
        cli
    );
    run_batch(&config, specs, traces, constants, cli)
}

pub(crate) fn run_batch_blake3_192(
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    log_blowup: u8,
    cli: &Cli,
) -> RunResult {
    use miden_lifted_stark::testing::configs::goldilocks_blake3_192 as blake3_192;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    let h = blake3_192::Blake3_192::new(p3_blake3::Blake3);
    let leaf = SerializingHasher::new(h);
    let compress =
        CompressionFunctionFromHasher::<blake3_192::Blake3_192, 2, { blake3_192::DIGEST }>::new(h);
    let config = batch_config!(
        Felt,
        u8,
        { blake3_192::DIGEST },
        leaf,
        compress,
        blake3_192::test_challenger(),
        log_blowup,
        cli
    );
    run_batch(&config, specs, traces, constants, cli)
}
