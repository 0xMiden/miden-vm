//! Transcript data container for external transport.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Raw transcript data captured by a prover and replayed by a verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, C: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, C: Deserialize<'de>"))]
pub struct TranscriptData<F, C> {
    fields: Vec<F>,
    commitments: Vec<C>,
}

impl<F, C> TranscriptData<F, C> {
    /// Create transcript data from field and commitment streams.
    pub fn new(fields: Vec<F>, commitments: Vec<C>) -> Self {
        Self { fields, commitments }
    }

    /// Returns the recorded field elements.
    pub fn fields(&self) -> &[F] {
        &self.fields
    }

    /// Returns the recorded commitments.
    pub fn commitments(&self) -> &[C] {
        &self.commitments
    }

    /// Returns field and commitment slices for verifier construction.
    pub fn as_slices(&self) -> (&[F], &[C]) {
        (&self.fields, &self.commitments)
    }

    /// Consume and return the underlying vectors.
    pub fn into_parts(self) -> (Vec<F>, Vec<C>) {
        (self.fields, self.commitments)
    }

    /// Returns the total byte size of the recorded transcript data.
    pub fn size_in_bytes(&self) -> usize {
        size_of_val(self.fields.as_slice()) + size_of_val(self.commitments.as_slice())
    }
}
