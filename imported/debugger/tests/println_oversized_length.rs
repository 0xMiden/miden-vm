mod common;

use std::sync::Arc;

use log::Level;
use miden_assembly::DefaultSourceManager;
use miden_debug::{DebugQuery, event::PRINTLN_EVENT};

#[test]
fn trace_println_oversized_length_logs_warning_and_continues_execution() {
    common::init_test_debug_logger();
    let source = format!(
        r#"
begin
    # Ask TRACE_PRINT_LN to read more than the maximum allowed byte length.
    push.524289
    push.1114112
    emit.event("{PRINTLN_EVENT}")
    drop
    drop

    # Store 42 at element 278529 to prove execution continued.
    push.42
    push.278529
    mem_store
end
"#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let trace = common::execute_trace(&source, source_manager);

    assert_eq!(
        trace.read_memory_element(278529).map(|f| f.as_canonical_u64()),
        Some(42),
        "expected execution to continue and write 42 to memory",
    );

    assert_logged!(entry => entry.level == Level::Warn && entry.message.contains("exceeds maximum"));
}
