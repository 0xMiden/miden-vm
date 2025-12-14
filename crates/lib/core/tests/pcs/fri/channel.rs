use miden_core::Word;
use miden_utils_testing::{
    Felt, FieldElement, MerkleTreeVC,
    crypto::{BatchMerkleProof, ElementHasher, Hasher as HasherTrait, PartialMerkleTree},
    serde::DeserializationError,
};
use winter_fri::{FriProof, VerifierError};

pub trait UnBatch<E: FieldElement, H: ElementHasher> {
    fn unbatch<const N: usize, const W: usize>(
        &mut self,
        positions: &[usize],
        domain_size: usize,
        layer_commitments: Vec<<H as HasherTrait>::Digest>,
    ) -> (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>);
}

pub struct MidenFriVerifierChannel<
    E: FieldElement<BaseField = Felt>,
    H: ElementHasher<BaseField = E::BaseField> + ElementHasher,
> {
    layer_commitments: Vec<H::Digest>,
    layer_proofs: Vec<BatchMerkleProof<H>>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
}

impl<E, H> MidenFriVerifierChannel<E, H>
where
    E: FieldElement<BaseField = Felt>,
    H: ElementHasher<BaseField = E::BaseField> + ElementHasher,
{
    /// Builds a new verifier channel from the specified [FriProof].
    ///
    /// # Errors
    /// Returns an error if the specified `proof` could not be parsed correctly.
    pub fn new(
        proof: FriProof,
        layer_commitments: Vec<H::Digest>,
        domain_size: usize,
        folding_factor: usize,
    ) -> Result<Self, DeserializationError> {
        let remainder = proof.parse_remainder()?;
        let (layer_queries, layer_proofs) =
            proof.parse_layers::<E, H, MerkleTreeVC<H>>(domain_size, folding_factor)?;

        Ok(MidenFriVerifierChannel {
            layer_commitments,
            layer_proofs,
            layer_queries,
            remainder,
        })
    }

    pub fn take_fri_remainder(&mut self) -> Vec<E> {
        self.remainder.clone()
    }

    pub fn layer_proofs(&mut self) -> Vec<BatchMerkleProof<H>> {
        self.layer_proofs.drain(..).collect()
    }

    pub fn layer_queries(&mut self) -> Vec<Vec<E>> {
        self.layer_queries.clone()
    }

    pub fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.layer_commitments.drain(..).collect()
    }

    pub fn read_remainder(
        &mut self,
        expected_commitment: &<H as HasherTrait>::Digest,
    ) -> Result<Vec<E>, VerifierError> {
        let poly = self.take_fri_remainder();
        let commitment = H::hash_elements(&poly);
        assert_eq!(&commitment, expected_commitment);

        Ok(poly)
    }
}
