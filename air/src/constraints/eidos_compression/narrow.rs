//! Shared description of the 36 narrow Eidos lookup slots.

/// Source of the three fields encoded by one narrow lookup slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarrowSlotFields {
    /// A stored `(lhs, rhs, result)` byte tuple at the given physical slot.
    StoredByte(u8),
    /// The rotation tuple reconstructed from the current and next fused rows.
    MissingRotation,
    /// A `(message_index, message_word, compression_cycle_id)` tuple for one G lane.
    MessageWord(u8),
}

/// Bus selected by a narrow slot in one row family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarrowSlotBus {
    /// The fixed And8 byte-pair table.
    And8,
    /// The Eidos rotation bus for the given byte position.
    Rotation(u8),
    /// The 16-bit range-check table.
    RangeCheck,
    /// The internal Eidos message-word relation.
    MessageWord,
}

/// Row-family behavior of one narrow lookup slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NarrowSlotSpec {
    /// Fields encoded by the slot.
    pub fields: NarrowSlotFields,
    /// Bus used on fused rows.
    pub fused_bus: NarrowSlotBus,
    /// Bus used on footer rows, or `None` when the slot is inactive there.
    pub footer_bus: Option<NarrowSlotBus>,
}

const fn stored(
    slot: u8,
    fused_bus: NarrowSlotBus,
    footer_bus: Option<NarrowSlotBus>,
) -> NarrowSlotSpec {
    NarrowSlotSpec {
        fields: NarrowSlotFields::StoredByte(slot),
        fused_bus,
        footer_bus,
    }
}

const fn missing_rotation(byte: u8) -> NarrowSlotSpec {
    NarrowSlotSpec {
        fields: NarrowSlotFields::MissingRotation,
        fused_bus: NarrowSlotBus::Rotation(byte),
        footer_bus: None,
    }
}

const fn message_word(g: u8) -> NarrowSlotSpec {
    NarrowSlotSpec {
        fields: NarrowSlotFields::MessageWord(g),
        fused_bus: NarrowSlotBus::MessageWord,
        footer_bus: Some(NarrowSlotBus::MessageWord),
    }
}

use NarrowSlotBus::{And8, RangeCheck, Rotation};

/// Complete narrow-slot layout shared by the Miden VM and PVM compression AIRs.
///
/// Slots 0 through 15 are And8 tuples. Slots 16 through 31 are rotation tuples on fused rows and
/// are selectively reused for footer And8 and range checks. Slots 32 through 35 carry message
/// words.
pub const NARROW_SLOTS: [NarrowSlotSpec; 36] = [
    stored(0, And8, Some(And8)),
    stored(1, And8, Some(And8)),
    stored(2, And8, Some(And8)),
    stored(3, And8, Some(And8)),
    stored(4, And8, Some(And8)),
    stored(5, And8, Some(And8)),
    stored(6, And8, Some(And8)),
    stored(7, And8, Some(And8)),
    stored(8, And8, Some(And8)),
    stored(9, And8, Some(And8)),
    stored(10, And8, Some(And8)),
    stored(11, And8, Some(And8)),
    stored(12, And8, Some(And8)),
    stored(13, And8, Some(And8)),
    stored(14, And8, Some(And8)),
    stored(15, And8, Some(And8)),
    stored(16, Rotation(0), Some(And8)),
    stored(17, Rotation(1), Some(RangeCheck)),
    stored(18, Rotation(2), None),
    stored(19, Rotation(3), None),
    stored(20, Rotation(0), None),
    stored(21, Rotation(1), None),
    stored(22, Rotation(2), Some(RangeCheck)),
    stored(23, Rotation(3), Some(RangeCheck)),
    stored(24, Rotation(0), Some(RangeCheck)),
    stored(25, Rotation(1), Some(RangeCheck)),
    stored(26, Rotation(2), Some(RangeCheck)),
    stored(27, Rotation(3), None),
    stored(28, Rotation(0), Some(RangeCheck)),
    stored(29, Rotation(1), Some(RangeCheck)),
    stored(30, Rotation(2), None),
    missing_rotation(3),
    message_word(0),
    message_word(1),
    message_word(2),
    message_word(3),
];

const _: () = assert!(NARROW_SLOTS.len().is_multiple_of(2));
