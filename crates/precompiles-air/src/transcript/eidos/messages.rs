//! LogUp interface messages for the native Eidos compression chiplet.
//!
//! Callers provide each eight-Felt block and the initial chaining value separately. The physical
//! compression-cycle ID ties both inputs to the native trace. The output relation carries a
//! chain's terminal chaining value.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// LogUp message for one Eidos message block.
#[derive(Debug, Clone)]
pub struct EidosBlockMsg<E> {
    pub compression_id: E,
    pub block: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for EidosBlockMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = self.block.clone();
        challenges.encode(
            BusId::EidosBlock as usize,
            [self.compression_id.clone(), b0, b1, b2, b3, b4, b5, b6, b7],
        )
    }
}

/// LogUp message for the initial chaining value of an Eidos chain.
#[derive(Debug, Clone)]
pub struct EidosInitMsg<E> {
    pub compression_id: E,
    pub initial_cv: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for EidosInitMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [cv0, cv1, cv2, cv3] = self.initial_cv.clone();
        challenges
            .encode(BusId::EidosInit as usize, [self.compression_id.clone(), cv0, cv1, cv2, cv3])
    }
}

/// LogUp message for the `EidosOut` relation: a 6-tuple
/// `(chain_head_id, compression_id, d0, d1, d2, d3)` carrying a chain's terminal 4-felt
/// chaining value.
///
/// The two IDs bind the output to the physical span that starts at `chain_head_id` and ends at
/// `compression_id`. The digest is the terminal four-felt packed Eidos chaining word.
///
/// Encoded as `bus_prefix[EidosOut] + β⁰·chain_head_id + β¹·compression_id + β²·d0 +
/// β³·d1 + β⁴·d2 + β⁵·d3`.
#[derive(Debug, Clone)]
pub struct EidosOutMsg<E> {
    pub chain_head_id: E,
    pub compression_id: E,
    pub digest: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for EidosOutMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [d0, d1, d2, d3] = self.digest.clone();
        challenges.encode(
            BusId::EidosOut as usize,
            [self.chain_head_id.clone(), self.compression_id.clone(), d0, d1, d2, d3],
        )
    }
}
