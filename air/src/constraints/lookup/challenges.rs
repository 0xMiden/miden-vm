//! Compatibility alias for the lookup module's verifier challenges.
//!
//! Re-exports [`crate::trace::Challenges`] under the legacy `LookupChallenges` name so
//! existing references inside the lookup module continue to resolve. The 2856 unified
//! `Challenges` struct has the same `bus_prefix[i]` / `beta_powers[k]` access pattern but
//! uses fixed-size arrays (`[EF; NUM_BUS_TYPES]` / `[EF; MAX_MESSAGE_WIDTH]`) instead of
//! `Box<[EF]>`, so callers no longer pass `max_message_width` / `num_bus_ids` to the
//! constructor. The two-arg `Challenges::new(alpha, beta)` is the only constructor.

pub type LookupChallenges<EF> = crate::trace::Challenges<EF>;
