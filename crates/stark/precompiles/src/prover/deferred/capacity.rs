//! Conservative capacity reservations for preparation and Session recording.
//!
//! These estimates cover hydrated graphs, scratch, and recording expansion before allocating
//! them. They deliberately retain reservations until import finishes, even when scratch is freed.
//! Like the trace-memory model, this is not an allocator quota or a bound on process RSS (including
//! caller-owned inputs, allocator overhead, and other concurrent requests).

use miden_air_definitions::precompiles::primitives::byte_pair_lut::eidos;
use miden_core::deferred::{DataChunk, PrecompileWitness, PrecompileWitnessEntry, PreparedNode};
use miden_precompiles::{CurveOp, Keccak256Precompile, Sha256Precompile, Sha512Precompile};

use crate::prover::{
    PrecompileProvingError, primitives::byte_pair_lut::NUM_BYTE_PAIRS, relations::ProvideMult,
};

// Per-entry allowance for wire/prepared headers, the commitment index, canonical DFS scratch,
// and collection slack. Payloads are charged separately, including PairList hydration from
// indices to digests, its intermediate copies, and DFS edges.
const PREPARATION_BYTES_PER_NODE: u64 = 1024;
const PREPARATION_BYTES_PER_CHUNK: u64 = 8 * size_of::<DataChunk>() as u64;

// The eagerly allocated byte-pair multiplicities plus fixed uint/group records and metadata.
pub(crate) const SESSION_BYTES: u64 =
    NUM_BYTE_PAIRS as u64 * (eidos::NUM_RELATIONS as u64 + 1) * size_of::<ProvideMult>() as u64
        + (64 << 10);

// Allow for eval/commitment caches and the uint/EC records of a fixed-size operation, including
// collection slack. Variable hash and MSM recording demand is charged in addition to this.
pub(crate) const IMPORT_BYTES_PER_NODE: u64 = 64 << 10;
// Keccak retains 24 200-byte round states per 136 input bytes (about 35 bytes per input byte),
// plus sponge/chunk/Eidos records and byte buffers. Growing the round-state vector can briefly
// hold the old and new buffers. SHA-256 and SHA-512 retain less per input byte.
const IMPORT_BYTES_PER_HASH_BYTE: u64 = 192;
// A 256-bit scalar can have 257 wNAF digits. Allow 16 KiB per digit for the ladder's EC/uint
// records and tables, plus 1 KiB per digit and balanced-reduction level for copied term rows.
// An extra level covers GLV's two virtual bases. This also covers the term-preserving fallback;
// neither zero scalars nor repeated bases discount the reservation.
const MSM_DIGITS: u64 = 257;
const MSM_LADDER_BYTES_PER_DIGIT: u64 = 16 << 10;
const MSM_REDUCTION_BYTES_PER_DIGIT: u64 = 1 << 10;

pub(super) struct MemoryBudget {
    reserved_bytes: u64,
    budget_bytes: u64,
}

impl MemoryBudget {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self { reserved_bytes: 0, budget_bytes }
    }

    /// Reserves `bytes` cumulatively. `None` denotes an estimate that overflowed `u64`.
    pub(super) fn reserve(&mut self, bytes: Option<u64>) -> Result<(), PrecompileProvingError> {
        let estimated_bytes = bytes
            .and_then(|bytes| self.reserved_bytes.checked_add(bytes))
            .ok_or(PrecompileProvingError::MemoryEstimateOverflow)?;
        if estimated_bytes > self.budget_bytes {
            return Err(PrecompileProvingError::MemoryBudgetExceeded {
                estimated_bytes,
                budget_bytes: self.budget_bytes,
            });
        }
        self.reserved_bytes = estimated_bytes;
        Ok(())
    }
}

pub(crate) fn preparation_bytes(witness: &PrecompileWitness) -> Option<u64> {
    witness
        .entries()
        .iter()
        .try_fold(size_of::<PrecompileWitness>() as u64, |bytes, entry| {
            let chunks = match entry {
                PrecompileWitnessEntry::Data { chunks, .. } => chunks.len(),
                PrecompileWitnessEntry::Join { .. } => 1,
                PrecompileWitnessEntry::PairList { pairs, .. } => pairs.len(),
            };
            bytes
                .checked_add(PREPARATION_BYTES_PER_NODE)?
                .checked_add(u64::try_from(chunks).ok()?.checked_mul(PREPARATION_BYTES_PER_CHUNK)?)
        })
}

pub(super) fn import_bytes(prepared: &PreparedNode) -> Option<u64> {
    let frame = prepared.node().frame().expect("prepared nodes are not TRUE");
    let hash_bytes = Keccak256Precompile::decode_assert_frame(frame)
        .expect("preparation validates hash frames")
        .or_else(|| {
            Sha512Precompile::decode_assert_frame(frame).expect("preparation validates hash frames")
        })
        .or_else(|| {
            Sha256Precompile::decode_assert_frame(frame).expect("preparation validates hash frames")
        });
    if let Some(bytes) = hash_bytes {
        return IMPORT_BYTES_PER_NODE
            .checked_add(u64::from(bytes).checked_mul(IMPORT_BYTES_PER_HASH_BYTE)?);
    }
    if let Some(CurveOp::Msm(terms)) =
        CurveOp::decode_frame(frame).expect("preparation validates curve frames")
    {
        let terms = u64::from(terms);
        let levels = u64::from(terms.checked_next_power_of_two()?.ilog2()) + 1;
        let per_digit = MSM_LADDER_BYTES_PER_DIGIT
            .checked_add(levels.checked_mul(MSM_REDUCTION_BYTES_PER_DIGIT)?)?;
        return IMPORT_BYTES_PER_NODE
            .checked_add(terms.checked_mul(MSM_DIGITS)?.checked_mul(per_digit)?);
    }
    Some(IMPORT_BYTES_PER_NODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_checked_and_allow_the_exact_budget() {
        let mut budget = MemoryBudget::new(10);
        budget.reserve(Some(4)).unwrap();
        budget.reserve(Some(6)).unwrap();
        assert!(matches!(
            budget.reserve(Some(1)),
            Err(PrecompileProvingError::MemoryBudgetExceeded {
                estimated_bytes: 11,
                budget_bytes: 10,
            })
        ));
        budget.reserve(Some(0)).unwrap();

        let mut budget = MemoryBudget::new(u64::MAX);
        budget.reserve(Some(u64::MAX)).unwrap();
        for bytes in [Some(1), None] {
            assert!(matches!(
                budget.reserve(bytes),
                Err(PrecompileProvingError::MemoryEstimateOverflow)
            ));
        }
    }
}
