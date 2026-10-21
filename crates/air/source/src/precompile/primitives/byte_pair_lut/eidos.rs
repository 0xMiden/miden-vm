//! PVM bus mapping for the shared Eidos byte-pair rotation relations.

use crate::precompile::relations::BusId;
pub(super) use crate::shared::eidos::rotation_lookup::provider_values;
pub use crate::shared::eidos::rotation_lookup::{
    BytePairRelation as Relation, NUM_RELATIONS, Rotation, contribution, denormalize, normalize,
};

/// Returns the PVM lookup bus for a normalized Eidos rotation relation.
pub const fn bus(relation: Relation) -> BusId {
    match relation {
        Relation::CanonicalXor => BusId::BytePairLut,
        Relation::Rot12Pos1 => BusId::EidosRot12Pos1,
        Relation::Rot7Pos0 => BusId::EidosRot7Pos0,
        Relation::Rot7Pos2 => BusId::EidosRot7Pos2,
        Relation::Rot12Pos3 => BusId::EidosRot12Pos3,
        Relation::Rot7Pos3 => BusId::EidosRot7Pos3,
    }
}
