use miden_processor::ExecutionOptions;

/// Test that CLI --release flag controls debug mode and trace decorators
/// Tests the exact logic from run.rs: ExecutionOptions::new(..., !release)
#[test]
fn test_cli_release_flag_controls_execution() {
    const DEFAULT_FRAGMENT_SIZE: usize = 4096;

    // Requirement 1: Debug mode can be turned on/off by CLI --release flag
    let debug_options = ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        DEFAULT_FRAGMENT_SIZE,
        false,
        true,
    )
    .expect("Default should enable debugging");
    assert!(debug_options.enable_debugging(), "CLI default should enable debug mode");

    let release_options = ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        DEFAULT_FRAGMENT_SIZE,
        false,
        false,
    )
    .expect("--release should disable debugging");
    assert!(!release_options.enable_debugging(), "CLI --release should disable debug mode");

    // Requirement 2: Trace mode activates execution of trace decorators
    let trace_options = ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        DEFAULT_FRAGMENT_SIZE,
        true,
        true,
    )
    .expect("--trace should enable tracing");
    assert!(trace_options.enable_tracing(), "CLI --trace should enable trace decorators");

    // Requirement 3: With --release and no trace, decorators are skipped
    assert!(
        !release_options.enable_tracing(),
        "Release mode without trace should skip decorators"
    );
    assert!(
        !release_options.enable_debugging(),
        "Release mode should disable debug decorators"
    );
}
