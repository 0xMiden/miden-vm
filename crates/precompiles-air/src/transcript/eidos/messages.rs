//! LogUp interface messages for the native Eidos compression chiplet.
//!
//! The input relation carries one complete logical chaining step atomically: its identifier, head
//! flag, domain, eight packed message fields, and four-field chain framing context. Keeping these
//! fields in one tuple prevents independently valid message halves or framing contexts from being
//! recombined across steps. The output relation carries the terminal chaining value.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// Domain value for a generic tagged-node chain on [`BusId::EidosIn`].
pub const EIDOS_DOMAIN_NODE: u8 = 2;
/// Domain value for the framework AND chain on [`BusId::EidosIn`].
pub const EIDOS_DOMAIN_AND: u8 = 3;
/// Domain value for the framework CHUNKS chain on [`BusId::EidosIn`].
pub const EIDOS_DOMAIN_CHUNKS: u8 = 4;

/// Atomic LogUp message for one logical Eidos chaining step.
///
/// - `chain_step_id` uniquely identifies the logical message-block step.
/// - `is_head` marks the first step and prevents an unrequested block from being prepended.
/// - `domain` separates generic-node, AND, and CHUNKS chains.
/// - `message` is the complete eight-field packed Eidos compression message block.
/// - `chain_context` is the four-field framing value shared by every step in the chain.
///
/// The 15-field payload remains below the PVM relation domain's width of 18.
#[derive(Debug, Clone)]
pub struct EidosChainInputMsg<E> {
    pub chain_step_id: E,
    pub is_head: E,
    pub domain: E,
    pub message: [E; 8],
    pub chain_context: [E; 4],
}

impl<E> EidosChainInputMsg<E>
where
    E: PrimeCharacteristicRing,
{
    pub fn node(chain_step_id: E, is_head: E, message: [E; 8], chain_context: [E; 4]) -> Self {
        Self {
            chain_step_id,
            is_head,
            domain: E::from_u8(EIDOS_DOMAIN_NODE),
            message,
            chain_context,
        }
    }

    pub fn and(chain_step_id: E, is_head: E, message: [E; 8], chain_context: [E; 4]) -> Self {
        Self {
            chain_step_id,
            is_head,
            domain: E::from_u8(EIDOS_DOMAIN_AND),
            message,
            chain_context,
        }
    }

    pub fn chunks(chain_step_id: E, is_head: E, message: [E; 8], chain_context: [E; 4]) -> Self {
        Self {
            chain_step_id,
            is_head,
            domain: E::from_u8(EIDOS_DOMAIN_CHUNKS),
            message,
            chain_context,
        }
    }
}

impl<E, EF> LookupMessage<E, EF> for EidosChainInputMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [m0, m1, m2, m3, m4, m5, m6, m7] = self.message.clone();
        let [c0, c1, c2, c3] = self.chain_context.clone();
        challenges.encode(
            BusId::EidosIn as usize,
            [
                self.chain_step_id.clone(),
                self.is_head.clone(),
                self.domain.clone(),
                m0,
                m1,
                m2,
                m3,
                m4,
                m5,
                m6,
                m7,
                c0,
                c1,
                c2,
                c3,
            ],
        )
    }
}

/// LogUp message for the `EidosOut` relation: a 5-tuple
/// `(chain_step_id, d0, d1, d2, d3)` carrying the terminal 4-felt chaining value.
///
/// The digest is the terminal four-felt packed Eidos chaining word.
///
/// Encoded as `bus_prefix[EidosOut] + β⁰·chain_step_id + β¹·d0 + β²·d1 +
/// β³·d2 + β⁴·d3`.
#[derive(Debug, Clone)]
pub struct EidosOutMsg<E> {
    pub chain_step_id: E,
    pub digest: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for EidosOutMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [d0, d1, d2, d3] = self.digest.clone();
        challenges.encode(BusId::EidosOut as usize, [self.chain_step_id.clone(), d0, d1, d2, d3])
    }
}
