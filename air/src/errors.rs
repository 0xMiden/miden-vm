// EXECUTION OPTIONS ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExecutionOptionsError {
    #[error(
        "expected number of cycles {expected_cycles} must be smaller than the maximum number of cycles {max_cycles}"
    )]
    ExpectedCyclesTooBig { max_cycles: u32, expected_cycles: u32 },
    #[error("maximum number of cycles {max_cycles} must be greater than {min_cycles_limit}")]
    MaxCycleNumTooSmall { max_cycles: u32, min_cycles_limit: usize },
    #[error("maximum number of cycles {max_cycles} must be less than {max_cycles_limit}")]
    MaxCycleNumTooBig { max_cycles: u32, max_cycles_limit: u32 },
}
