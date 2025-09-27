// Prover-related proof data types (Proof, Commitments, OpenedValues)

use serde::{Deserialize, Serialize};
use p3_commit::Pcs;
use p3_uni_stark::StarkGenericConfig;
use std::vec::Vec;

type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<SC: StarkGenericConfig> {
    pub(crate) commitments: Commitments<Com<SC>>,
    pub(crate) opened_values: OpenedValues<SC::Challenge>,
    pub(crate) opening_proof: PcsProof<SC>,
    pub(crate) degree_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Commitments<Com> {
    pub(crate) trace: Com,
    pub(crate) aux_trace: Com,
    pub(crate) quotient_chunks: Com,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenedValues<Challenge> {
    pub(crate) trace_local: Vec<Challenge>,
    pub(crate) trace_next: Vec<Challenge>,
    pub(crate) aux_trace_local: Vec<Challenge>,
    pub(crate) aux_trace_next: Vec<Challenge>,
    pub(crate) quotient_chunks: Vec<Vec<Challenge>>,
}