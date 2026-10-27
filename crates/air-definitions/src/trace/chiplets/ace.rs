use crate::trace::chiplets::Felt;

// --- CONSTANTS ----------------------------------------------------------------------------------

/// Total number of columns making up the ACE chiplet.
pub const ACE_CHIPLET_NUM_COLS: usize = 16;

/// Offset of the `ID1` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID1_OFFSET: Felt = Felt::new_unchecked(1 << 30);

/// Offset of the `ID2` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID2_OFFSET: Felt = Felt::new_unchecked(1 << 60);
