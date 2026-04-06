//! Unified bus challenge encoding with per-bus domain separation.
//!
//! Provides [`Challenges`], a single struct for encoding multiset/LogUp bus messages
//! as `bus_prefix.prefix_for_bus(bus) + <beta, message>`. Each bus interaction type gets a unique
//! prefix to ensure domain separation.
//!
//! This type is used by:
//!
//! - **AIR constraints** (symbolic expressions): `Challenges<AB::ExprEF>`
//! - **Processor aux trace builders** (concrete field elements): `Challenges<E>`
//! - **Verifier** (`reduced_aux_values`): `Challenges<EF>`
//!
//! See [`super::bus_message`] for the standard coefficient index layout.
//! See [`super::bus_types`] for the bus interaction type constants.

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

use super::{
    MAX_MESSAGE_WIDTH,
    bus_types::{
        ACE_WIRING_BUS, BLOCK_HASH_TABLE, BLOCK_STACK_TABLE, CHIPLETS_BUS,
        LOG_PRECOMPILE_TRANSCRIPT, NUM_BUS_TYPES, OP_GROUP_TABLE, RANGE_CHECK_BUS, SIBLING_TABLE,
        STACK_OVERFLOW_TABLE,
    },
};

/// Per-bus domain separation constants: each field is `alpha + (bus_const + 1) * gamma`
/// where `gamma = beta^MAX_MESSAGE_WIDTH` (see [`Challenges::new`]).
///
/// Field order matches [`super::bus_types`].
#[derive(Clone, Debug)]
pub struct BusPrefix<EF> {
    pub chiplets_bus: EF,
    pub block_stack_table: EF,
    pub block_hash_table: EF,
    pub op_group_table: EF,
    pub stack_overflow_table: EF,
    pub sibling_table: EF,
    pub log_precompile_transcript: EF,
    pub range_check_bus: EF,
    pub ace_wiring_bus: EF,
}

impl<EF> BusPrefix<EF> {
    /// Prefix for the bus index used by [`Challenges::encode`] / [`Challenges::encode_sparse`].
    #[inline(always)]
    pub(crate) fn prefix_for_bus(&self, bus: usize) -> &EF {
        match bus {
            CHIPLETS_BUS => &self.chiplets_bus,
            BLOCK_STACK_TABLE => &self.block_stack_table,
            BLOCK_HASH_TABLE => &self.block_hash_table,
            OP_GROUP_TABLE => &self.op_group_table,
            STACK_OVERFLOW_TABLE => &self.stack_overflow_table,
            SIBLING_TABLE => &self.sibling_table,
            LOG_PRECOMPILE_TRANSCRIPT => &self.log_precompile_transcript,
            RANGE_CHECK_BUS => &self.range_check_bus,
            ACE_WIRING_BUS => &self.ace_wiring_bus,
            _ => unreachable!("bus index {bus} is not a valid bus type (< {NUM_BUS_TYPES})"),
        }
    }
}

/// Encodes multiset/LogUp contributions as **per-bus prefix + \<beta, message\>**.
///
/// - `alpha`: randomness base (kept public for direct access by range checker etc.)
/// - `beta_powers`: precomputed powers `[beta^0, beta^1, ..., beta^(MAX_MESSAGE_WIDTH-1)]`
/// - `bus_prefix`: per-bus domain separation (see [`BusPrefix`])
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// Precomputed once and passed by reference to all bus components.
pub struct Challenges<EF: PrimeCharacteristicRing> {
    pub alpha: EF,
    pub beta_powers: [EF; MAX_MESSAGE_WIDTH],
    pub bus_prefix: BusPrefix<EF>,
}

impl<EF: PrimeCharacteristicRing> Challenges<EF> {
    /// Builds `alpha`, precomputed `beta` powers, and per-bus prefixes.
    pub fn new(alpha: EF, beta: EF) -> Self {
        let mut beta_powers = core::array::from_fn(|_| EF::ONE);
        for i in 1..MAX_MESSAGE_WIDTH {
            beta_powers[i] = beta_powers[i - 1].clone() * beta.clone();
        }
        // gamma = beta^MAX_MESSAGE_WIDTH (one power beyond the message range)
        let gamma = beta_powers[MAX_MESSAGE_WIDTH - 1].clone() * beta;
        let term = |k: u32| alpha.clone() + gamma.clone() * EF::from_u32(k);
        let bus_prefix = BusPrefix {
            chiplets_bus: term(1),
            block_stack_table: term(2),
            block_hash_table: term(3),
            op_group_table: term(4),
            stack_overflow_table: term(5),
            sibling_table: term(6),
            log_precompile_transcript: term(7),
            range_check_bus: term(8),
            ace_wiring_bus: term(9),
        };
        Self { alpha, beta_powers, bus_prefix }
    }

    /// Encodes as **prefix_for_bus(bus) + sum(beta_powers\[i\] * elem\[i\])** with K consecutive
    /// elements.
    ///
    /// The `bus` parameter selects the bus interaction type for domain separation.
    #[inline(always)]
    pub fn encode<BF, const K: usize>(&self, bus: usize, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        const { assert!(K <= MAX_MESSAGE_WIDTH, "Message length exceeds beta_powers capacity") };
        debug_assert!(
            bus < NUM_BUS_TYPES,
            "Bus index {bus} exceeds NUM_BUS_TYPES ({NUM_BUS_TYPES})"
        );
        let mut acc = self.bus_prefix.prefix_for_bus(bus).clone();
        for (i, elem) in elems.into_iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem;
        }
        acc
    }

    /// Encodes as **prefix_for_bus(bus) + sum(beta_powers\[layout\[i\]\] * values\[i\])** using
    /// sparse positions.
    ///
    /// The `bus` parameter selects the bus interaction type for domain separation.
    #[inline(always)]
    pub fn encode_sparse<BF, const K: usize>(
        &self,
        bus: usize,
        layout: [usize; K],
        values: [BF; K],
    ) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        debug_assert!(
            bus < NUM_BUS_TYPES,
            "Bus index {bus} exceeds NUM_BUS_TYPES ({NUM_BUS_TYPES})"
        );
        let mut acc = self.bus_prefix.prefix_for_bus(bus).clone();
        for (idx, value) in layout.into_iter().zip(values) {
            debug_assert!(
                idx < self.beta_powers.len(),
                "encode_sparse index {} exceeds beta_powers length ({})",
                idx,
                self.beta_powers.len()
            );
            acc += self.beta_powers[idx].clone() * value;
        }
        acc
    }
}
