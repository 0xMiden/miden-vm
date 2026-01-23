mod test_consistency_host;

pub use test_consistency_host::{ProcessStateSnapshot, TestConsistencyHost, TraceCollector};

/// Type alias for compatibility - `TestHost` is the same as `TestConsistencyHost`.
pub type TestHost = TestConsistencyHost;
