//! Tag group base IDs and sizes.

/// Base ID for the system constraint group.
pub const TAG_SYSTEM_BASE: usize = 0;
/// Number of system clock constraints.
pub const TAG_SYSTEM_CLK_COUNT: usize = 2;
/// Number of system context constraints.
pub const TAG_SYSTEM_CTX_COUNT: usize = 3;
/// Number of system function-hash constraints.
pub const TAG_SYSTEM_FN_HASH_COUNT: usize = 8;

/// Base ID for the system clock constraints.
pub const TAG_SYSTEM_CLK_BASE: usize = TAG_SYSTEM_BASE;
/// Base ID for the system context constraints.
pub const TAG_SYSTEM_CTX_BASE: usize = TAG_SYSTEM_CLK_BASE + TAG_SYSTEM_CLK_COUNT;
/// Base ID for the system function-hash constraints.
pub const TAG_SYSTEM_FN_HASH_BASE: usize = TAG_SYSTEM_CTX_BASE + TAG_SYSTEM_CTX_COUNT;

/// Total number of system constraints in this group.
pub const TAG_SYSTEM_COUNT: usize =
    TAG_SYSTEM_CLK_COUNT + TAG_SYSTEM_CTX_COUNT + TAG_SYSTEM_FN_HASH_COUNT;

/// Base ID for the range checker main constraint group.
pub const TAG_RANGE_MAIN_BASE: usize = TAG_SYSTEM_BASE + TAG_SYSTEM_COUNT;
/// Number of range checker main constraints in this group.
pub const TAG_RANGE_MAIN_COUNT: usize = 3;

/// Base ID for the stack general constraint group.
pub const TAG_STACK_GENERAL_BASE: usize = TAG_RANGE_MAIN_BASE + TAG_RANGE_MAIN_COUNT;
/// Number of stack general constraints in this group.
pub const TAG_STACK_GENERAL_COUNT: usize = 16;

/// Base ID for the stack overflow constraint group.
pub const TAG_STACK_OVERFLOW_BASE: usize = TAG_STACK_GENERAL_BASE + TAG_STACK_GENERAL_COUNT;
/// Number of stack overflow constraints in this group.
pub const TAG_STACK_OVERFLOW_COUNT: usize = 8;

/// Base ID for the stack ops constraint group.
pub const TAG_STACK_OPS_BASE: usize = TAG_STACK_OVERFLOW_BASE + TAG_STACK_OVERFLOW_COUNT;
/// Number of stack ops constraints in this group.
pub const TAG_STACK_OPS_COUNT: usize = 88;

/// Base ID for the stack crypto constraint group.
pub const TAG_STACK_CRYPTO_BASE: usize = TAG_STACK_OPS_BASE + TAG_STACK_OPS_COUNT;
/// Number of stack crypto constraints in this group.
pub const TAG_STACK_CRYPTO_COUNT: usize = 46;

/// Base ID for the decoder constraint group.
pub const TAG_DECODER_BASE: usize = TAG_STACK_CRYPTO_BASE + TAG_STACK_CRYPTO_COUNT;
/// Number of decoder constraints in this group.
pub const TAG_DECODER_COUNT: usize = 57;

/// Base ID for the chiplets constraint group.
pub const TAG_CHIPLETS_BASE: usize = TAG_DECODER_BASE + TAG_DECODER_COUNT;
/// Number of chiplets constraints in this group.
pub const TAG_CHIPLETS_COUNT: usize = 72;

/// Base ID for the range bus constraint.
///
/// Bus constraints are emitted after all main-trace constraints, so bus tags come last.
pub const TAG_RANGE_BUS_BASE: usize = TAG_CHIPLETS_BASE + TAG_CHIPLETS_COUNT;
/// Number of range bus constraints in this group.
pub const TAG_RANGE_BUS_COUNT: usize = 1;

/// Base ID for the stack overflow bus constraint group.
pub const TAG_STACK_OVERFLOW_BUS_BASE: usize = TAG_RANGE_BUS_BASE + TAG_RANGE_BUS_COUNT;
/// Number of stack overflow bus constraints in this group.
pub const TAG_STACK_OVERFLOW_BUS_COUNT: usize = 1;

/// Base ID for the decoder bus constraint group.
pub const TAG_DECODER_BUS_BASE: usize = TAG_STACK_OVERFLOW_BUS_BASE + TAG_STACK_OVERFLOW_BUS_COUNT;
/// Number of decoder bus constraints in this group.
#[cfg(all(test, feature = "std"))]
pub const TAG_DECODER_BUS_COUNT: usize = 3;

/// Total number of tagged constraints in the current group set.
#[cfg(all(test, feature = "std"))]
pub const TAG_TOTAL_COUNT: usize = TAG_DECODER_BUS_BASE + TAG_DECODER_BUS_COUNT;
