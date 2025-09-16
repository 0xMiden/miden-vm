// Blake-specific prover implementation

use super::utils::{quotient_values, to_row_major, to_row_major_aux};
use air::{Commitments, Felt, OpenedValues, Proof};
use air::ProcessorAir;
use miden_crypto::BinomialExtensionField;
use p3_blake3::Blake3;
use p3_challenger::HashChallenger;
use p3_challenger::SerializingChallenger64;
use p3_challenger::*;
use p3_commit::PolynomialSpace;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversalPerm;
use p3_matrix::dense::DenseMatrix;
use p3_matrix::row_index_mapped::RowIndexMappedView;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkGenericConfig;
use p3_uni_stark::StarkConfig;
use p3_util::{log2_ceil_usize, log2_strict_usize};
use processor::ExecutionTrace;
use std::{println, vec};
use std::vec::Vec;
use tracing::info_span;

type Challenge = BinomialExtensionField<Felt, 2>;
type H = Blake3;

 type FieldHash = SerializingHasher<H>; 
type Compress<H> = CompressionFunctionFromHasher<H, 2, 32>;
type ValMmcs<H> = MerkleTreeMmcs<Felt, u8, FieldHash, Compress<H>, 32>;
type ChallengeMmcs<H> = ExtensionMmcs<Felt, Challenge, ValMmcs<H>>;
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs<H>, ChallengeMmcs<H>>;
type Dft = Radix2DitParallel<Felt>;
type Challenger<H> = SerializingChallenger64<Felt, HashChallenger<u8, H, 32>>;
type StarkConfigBlake = StarkConfig<FriPcs, Challenge, Challenger<H>>;

pub fn prove_blake(trace: ExecutionTrace) -> Vec<u8> {
    let air = ProcessorAir {};
    let public_values: Vec<Felt> = vec![];
    let trace_row_major = to_row_major(&trace);
    let degree = trace_row_major.height();
    let log_degree = log2_strict_usize(degree);
/*
    let symbolic_constraints =
        get_symbolic_constraints::<Felt, ProcessorAir>(&air, 0, public_values.len());

    let constraint_count = symbolic_constraints.len();
    let constraint_degree = symbolic_constraints
        .iter()
        .map(SymbolicExpression::degree_multiple)
        .max()
        .unwrap_or(0);
 */

 let constraint_degree = 8;
 let constraint_count = 2;

    let log_quotient_degree = log2_ceil_usize(constraint_degree - 1);
    let quotient_degree = 1 << log_quotient_degree;
println!("constraints degree {:?}", constraint_degree);
println!("constraints count {:?}", constraint_count);

    let config = generate_blake_config();
    let mut challenger = config.initialise_challenger();
    let pcs = config.pcs();
    let trace_domain: TwoAdicMultiplicativeCoset<Felt> =
        <FriPcs as Pcs<Challenge, Challenger<H>>>::natural_domain_for_degree(&pcs, degree);

    let (trace_commit, trace_data) = info_span!("commit to main trace data").in_scope(|| {
        <FriPcs as Pcs<Challenge, Challenger<H>>>::commit(
            &pcs,
            vec![(trace_domain, trace_row_major)],
        )
    });

    challenger.observe(Felt::from_u8(log_degree as u8));

    challenger.observe(trace_commit.clone());
    challenger.observe_slice(&public_values);

    let alphas: [Challenge; 16] =
        core::array::from_fn(|_| challenger.sample_algebra_element::<Challenge>());

    let aux_trace = info_span!("build aux trace").in_scope(|| trace.build_aux_trace(&alphas));

    let aux_row_major = to_row_major_aux(&aux_trace.unwrap());

    let aux_row_major =
        info_span!("flatten auxiliary trace").in_scope(|| aux_row_major.flatten_to_base());
    let (aux_trace_commit, aux_trace_data) =
        info_span!("commit to auxiliary trace data").in_scope(|| {
            <FriPcs as Pcs<Challenge, Challenger<H>>>::commit(
                &pcs,
                vec![(trace_domain, aux_row_major)],
            )
        });

    challenger.observe(aux_trace_commit.clone());

    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));

    let trace_on_quotient_domain =
        <FriPcs as Pcs<Challenge, Challenger<H>>>::get_evaluations_on_domain(
            pcs,
            &trace_data,
            0,
            quotient_domain,
        );

    let _aux_on_quotient_domain =
        <FriPcs as Pcs<Challenge, Challenger<H>>>::get_evaluations_on_domain(
            pcs,
            &aux_trace_data,
            0,
            quotient_domain,
        );
    let alpha: Challenge = challenger.sample_algebra_element();

    let quotient_values = quotient_values::<
        StarkConfigBlake,
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
            <FriPcs as Pcs<Challenge, Challenger<H>>>::commit(
                pcs,
                qc_domains.into_iter().zip(quotient_chunks.into_iter()),
            )
        });
    challenger.observe(quotient_commit.clone());

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
    let proof: Proof<StarkConfigBlake> = Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits: log_degree,
    };

    bincode::serialize(&proof).unwrap()
}

pub fn generate_blake_config() -> StarkConfigBlake {
    let field_hash = FieldHash::new(H {});
    let compress = Compress::new(H {});

    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    let fri_config = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 7,
        num_queries: 27,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);

    let challenger = Challenger::from_hasher(vec![], H {});

    StarkConfigBlake::new(pcs, challenger)
}
