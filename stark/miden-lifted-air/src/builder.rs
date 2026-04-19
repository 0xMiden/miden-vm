//! The `LiftedAirBuilder` super-trait for constraint evaluation builders.

use crate::{AirBuilder, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder};

/// Super-trait bundling all builder capabilities needed by the lifted STARK system.
///
/// Every type that already satisfies the four upstream builder traits automatically
/// implements this trait via the blanket impl below. No additional methods or
/// associated types are required .
pub trait LiftedAirBuilder:
    AirBuilder + ExtensionBuilder + PermutationAirBuilder + PeriodicAirBuilder
{
}

impl<T> LiftedAirBuilder for T where
    T: AirBuilder + ExtensionBuilder + PermutationAirBuilder + PeriodicAirBuilder
{
}
