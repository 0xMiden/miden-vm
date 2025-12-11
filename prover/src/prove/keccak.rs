// Keccak-specific prover implementation

use std::{vec, vec::Vec};

use miden_air::{Felt, ProcessorAir};
use miden_processor::ExecutionTrace;
use p3_challenger::{HashChallenger, SerializingChallenger64, *};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{
    PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset, extension::BinomialExtensionField,
};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::{
    Matrix, bitrev::BitReversalPerm, dense::DenseMatrix, row_index_mapped::RowIndexMappedView,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use tracing::info_span;

use super::{
    types::{Commitments, OpenedValues, Proof},
    utils::{quotient_values, to_row_major, to_row_major_aux},
};

type Val = Felt;
type Challenge = BinomialExtensionField<Val, 2>;

pub type ByteHash = Keccak256Hash; // Standard Keccak for byte hashing
pub type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>; // Keccak optimized for field elements
pub type FieldHash = SerializingHasher<U64Hash>; // Wrapper for field element hashing
pub type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
pub type ValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    4,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
pub type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type StarkConfigKeccak = StarkConfig<FriPcs, Challenge, Challenger>;

pub fn prove_keccak(trace: ExecutionTrace) -> Vec<u8> {
    let air = ProcessorAir {};
    let public_values: Vec<Felt> = vec![];
    let trace_row_major = to_row_major(&trace);
    let degree = trace_row_major.height();
    let log_degree = log2_strict_usize(degree);

    let constraint_degree = 8;
    let constraint_count = 2;

    /*
    let symbolic_constraints =
        get_symbolic_constraints::<Felt, ProcessorAir>(&air, 0, public_values.len());


    let constraint_count = symbolic_constraints.len();
    let constraint_degree = symbolic_constraints
        .iter()
        .map(SymbolicExpression::degree_multiple)
        .max()
        .unwrap_or(0);*/
    let log_quotient_degree = log2_ceil_usize(constraint_degree - 1);
    let quotient_degree = 1 << log_quotient_degree;

    let config = generate_keccak_config();
    let mut challenger = config.initialise_challenger();
    let pcs = config.pcs();
    let trace_domain: TwoAdicMultiplicativeCoset<Felt> =
        <FriPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(pcs, degree);

    let (trace_commit, trace_data) = info_span!("commit to main trace data").in_scope(|| {
        <FriPcs as Pcs<Challenge, Challenger>>::commit(pcs, vec![(trace_domain, trace_row_major)])
    });

    challenger.observe(Felt::from_u8(log_degree as u8));

    challenger.observe(trace_commit);
    challenger.observe_slice(&public_values);

    let alphas: [Challenge; 16] =
        core::array::from_fn(|_| challenger.sample_algebra_element::<Challenge>());

    let aux_trace = info_span!("build aux trace").in_scope(|| trace.build_aux_trace(&alphas));

    let aux_row_major = to_row_major_aux(&aux_trace.unwrap());

    let aux_row_major =
        info_span!("flatten auxiliary trace").in_scope(|| aux_row_major.flatten_to_base());
    let (aux_trace_commit, aux_trace_data) =
        info_span!("commit to auxiliary trace data").in_scope(|| {
            <FriPcs as Pcs<Challenge, Challenger>>::commit(pcs, vec![(trace_domain, aux_row_major)])
        });

    challenger.observe(aux_trace_commit);

    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));

    let trace_on_quotient_domain =
        <FriPcs as Pcs<Challenge, Challenger>>::get_evaluations_on_domain(
            pcs,
            &trace_data,
            0,
            quotient_domain,
        );

    let _aux_on_quotient_domain = <FriPcs as Pcs<Challenge, Challenger>>::get_evaluations_on_domain(
        pcs,
        &aux_trace_data,
        0,
        quotient_domain,
    );
    let alpha: Challenge = challenger.sample_algebra_element();

    let quotient_values = quotient_values::<
        StarkConfigKeccak,
        ProcessorAir,
        RowIndexMappedView<BitReversalPerm, DenseMatrix<Felt, &[Felt]>>,
    >(
        &air,
        &public_values,
        trace_domain,
        quotient_domain,
        trace_on_quotient_domain,
        alpha,
        constraint_count,
    );

    let quotient_flat = info_span!("flatten quotient data")
        .in_scope(|| p3_matrix::dense::RowMajorMatrix::new_col(quotient_values).flatten_to_base());
    let quotient_chunks = quotient_domain.split_evals(quotient_degree, quotient_flat);
    let qc_domains = quotient_domain.split_domains(quotient_degree);

    let (quotient_commit, quotient_data) =
        info_span!("commit to quotient poly chunks").in_scope(|| {
            <FriPcs as Pcs<Challenge, Challenger>>::commit(
                pcs,
                qc_domains.into_iter().zip(quotient_chunks),
            )
        });
    challenger.observe(quotient_commit);

    let commitments = Commitments {
        trace: trace_commit,
        aux_trace: aux_trace_commit,
        quotient_chunks: quotient_commit,
    };

    let zeta: Challenge = challenger.sample();
    let zeta_next = trace_domain.next_point(zeta).unwrap();

    let (opened_values, opening_proof) = info_span!("open").in_scope(|| {
        pcs.open(
            vec![
                (&trace_data, vec![vec![zeta, zeta_next]]),
                (&aux_trace_data, vec![vec![zeta, zeta_next]]),
                (&quotient_data, (0..quotient_degree).map(|_| vec![zeta]).collect()),
            ],
            &mut challenger,
        )
    });

    let trace_local = opened_values[0][0][0].clone();
    let trace_next = opened_values[0][0][1].clone();
    let aux_trace_local = opened_values[1][0][0].clone();
    let aux_trace_next = opened_values[1][0][1].clone();
    let quotient_chunks = opened_values[2].iter().map(|v| v[0].clone()).collect();
    let opened_values = OpenedValues {
        trace_local,
        trace_next,
        aux_trace_local,
        aux_trace_next,
        quotient_chunks,
    };
    let proof: Proof<StarkConfigKeccak> = Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits: log_degree,
    };

    bincode::serialize(&proof).unwrap()
}

pub fn generate_keccak_config() -> StarkConfigKeccak {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let compress = MyCompress::new(u64_hash);

    let field_hash = FieldHash::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let fri_config = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 7,
        num_queries: 27,
        proof_of_work_bits: 16,
        log_folding_factor: 1,
        mmcs: challenge_mmcs,
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);

    let challenger = Challenger::from_hasher(vec![], byte_hash);

    StarkConfigKeccak::new(pcs, challenger)
}
