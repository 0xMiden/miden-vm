#![no_std]

#[cfg_attr(all(feature = "metal", target_arch = "aarch64", target_os = "macos"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::marker::PhantomData;
use p3_blake3::Blake3;
use prove::{prove_blake, prove_rpo};
use std::{println, vec, vec::Vec};
use tracing::instrument;

use air::{ProcessorAir, PublicInputs, trace::TRACE_WIDTH};
use miden_crypto::hash::rpo::RpoPermutation256;
#[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
use miden_gpu::HashFn;
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64};
use p3_commit::{ExtensionMmcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{Field, extension::BinomialExtensionField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher64, TruncatedPermutation,
};
use p3_uni_stark::{Proof, StarkConfig, StarkGenericConfig, prove as prove_uni_stark};
use processor::{ExecutionTrace, Program, ZERO, math::Felt};

#[cfg(feature = "std")]
use std::time::Instant;
mod gpu;

mod prove;

// EXPORTS
// ================================================================================================

pub use air::{DeserializationError, ExecutionProof, FieldExtension, HashFunction, ProvingOptions};
pub use processor::{
    AdviceInputs, Digest, ExecutionError, Host, InputError, MemAdviceProvider, StackInputs,
    StackOutputs, Word, crypto, math, utils,
};

// PROVER
// ================================================================================================

struct ExecutionProver<SC> {
    config: SC,
    public_inputs: PublicInputs,
    _sc: PhantomData<SC>,
}

impl<SC> ExecutionProver<SC>
where
    SC: StarkGenericConfig,
{
    pub fn new(config: SC, public_inputs: PublicInputs) -> Self {
        Self { config, public_inputs, _sc: PhantomData }
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates the stack inputs against the provided execution trace and returns true if valid.
    fn are_inputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_inputs()
            .iter()
            .zip(trace.init_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    /// Validates the stack outputs against the provided execution trace and returns true if valid.
    fn are_outputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_outputs()
            .iter()
            .zip(trace.last_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    fn prove(&self, trace: ExecutionTrace) -> Proof<SC> where {
        let processor_air = ProcessorAir {};

        //let mut public_inputs = self.public_inputs.stack_inputs().to_vec();
        //public_inputs.extend_from_slice(&self.public_inputs.stack_outputs().to_vec() );
        //public_inputs.extend_from_slice(&self.public_inputs.program_info().to_elements() );

        //let public_inputs = vec![];
        let trace_row_major = to_row_major(&trace);
        //prove_uni_stark(&self.config, &processor_air, trace_row_major, &public_inputs)
        todo!()
    }
}

#[instrument("program proving", skip_all)]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError>
where
{
    // execute the program to create an execution trace
    #[cfg(feature = "std")]
    let now = Instant::now();
    let trace =
        processor::execute(program, stack_inputs.clone(), host, *options.execution_options())?;
    #[cfg(feature = "std")]
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps ({}% padded) in {} ms",
        trace.trace_len_summary().main_trace_len(),
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().padding_percentage(),
        now.elapsed().as_millis()
    );

    let stack_outputs = trace.stack_outputs().clone();
    let hash_fn = options.hash_fn();
    let program_info = trace.program_info();
    let public_inputs = PublicInputs::new(program_info.clone(), stack_inputs, stack_outputs);

    type Val = Felt;
    type Challenge = BinomialExtensionField<Val, 2>;

    // generate STARK proof
    let proof = match hash_fn {
        HashFunction::Rpo256 => {
            println!("rpo proving");

            type Perm = RpoPermutation256;

            type MyHash = PaddingFreeSponge<Perm, 12, 8, 4>;
            let hash = MyHash::new(Perm {});

            type MyCompress = TruncatedPermutation<Perm, 2, 4, 12>;
            let compress = MyCompress::new(Perm {});

            type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
            let challenger = Challenger::new(Perm {});

            type ValMmcs = MerkleTreeMmcs<
                <Val as Field>::Packing,
                <Val as Field>::Packing,
                MyHash,
                MyCompress,
                4,
            >;
            let val_mmcs = ValMmcs::new(hash, compress);

            type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            type Dft = Radix2DitParallel<Val>;
            let dft = Dft::default();

            let fri_config = FriConfig {
                log_blowup: 3,
                log_final_poly_len: 7,
                num_queries: 27,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
            let pcs = Pcs::new(dft, val_mmcs, fri_config);
            type Config = StarkConfig<Pcs, Challenge, Challenger>;
            let config = Config::new(pcs, challenger);

            //let prover = ExecutionProver::<Config>::new(config.clone(), public_inputs);
            //prover.are_inputs_valid(&trace);
            //prover.are_outputs_valid(&trace);

            let proof = prove_rpo(config, trace);
            //let proof = bincode::serialize(&proof).unwrap();
            ExecutionProof::new(proof, hash_fn)
        },
        HashFunction::Blake3_256 | HashFunction::Blake3_192 => {
            println!("blake proving");
            type H = Blake3;
            type FieldHash<H> = SerializingHasher64<H>;
            type Compress<H> = CompressionFunctionFromHasher<H, 2, 32>;
            type ValMmcs<H> = MerkleTreeMmcs<Val, u8, FieldHash<H>, Compress<H>, 32>;
            type ChallengeMmcs<H> = ExtensionMmcs<Val, Challenge, ValMmcs<H>>;
            type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs<H>, ChallengeMmcs<H>>;
            type Dft = Radix2DitParallel<Val>;

            type Challenger<H> = SerializingChallenger64<Val, HashChallenger<u8, H, 32>>;
            type Config = StarkConfig<Pcs, Challenge, Challenger<H>>;

            let field_hash = FieldHash::new(H {});
            let compress = Compress::new(H {});

            let val_mmcs = ValMmcs::new(field_hash, compress);
            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft::default();

            let fri_config = FriConfig {
                log_blowup: 3,
                log_final_poly_len: 7,
                num_queries: 27,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };

            let pcs = Pcs::new(dft, val_mmcs, fri_config);

            let challenger = Challenger::from_hasher(vec![], H {});

            let config = Config::new(pcs, challenger);

            //let prover = ExecutionProver::<Config>::new(config, public_inputs);

            let proof = prove_blake(config, trace);
            //let proof = bincode::serialize(&proof).unwrap();
            ExecutionProof::new(proof, hash_fn)
        },

        HashFunction::Rpx256 => {
            unimplemented!()
        },
    };
    Ok((stack_outputs, proof))
}

// HELPERS
// ================================================================================================

#[instrument("naive transposition", skip_all)]
fn to_row_major(trace: &ExecutionTrace) -> RowMajorMatrix<Felt> {
    let mut result: RowMajorMatrix<Felt> =
        RowMajorMatrix::new(vec![ZERO; TRACE_WIDTH * trace.get_trace_len()], TRACE_WIDTH);
    result.par_rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..TRACE_WIDTH {
            row[col_idx] = trace.main_trace.get(col_idx, row_idx)
        }
    });

    result
}
