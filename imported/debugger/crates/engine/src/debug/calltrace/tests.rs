use alloc::{vec, vec::Vec};

use super::CallTraceRecorder;

fn stack(depth: usize, top: &[u64]) -> Vec<u64> {
    let mut stack = top.to_vec();
    stack.resize(depth, 0);
    stack
}

/// An argument one stack element wide, as a `Felt` parameter is.
fn observe_felt_arg(recorder: &mut CallTraceRecorder, index: u32, name: &str, value: u64) {
    recorder.observe_arg(index, name, Some(1), Some(vec![value]));
}

/// ```text
/// fn function_1() -> (Felt, Felt) { (function_2(), function_3()) }
///
/// function_2 -> 42
/// function_3 -> 7
/// ```
///
/// Both go under `function_1`, in the order they were called.
#[test]
fn frames_follow_entry_and_exit_order() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(2), None);
    // function_1 returns (Felt, Felt)
    recorder.enter(20, Vec::new());
    recorder.observe_callee("function_2", Some(1), None);
    // function_2 returns Felt
    recorder.exit(30, &stack(17, &[42]));
    recorder.enter(40, Vec::new());
    recorder.observe_callee("function_3", Some(1), None);
    // function_3 returns Felt
    recorder.exit(50, &stack(18, &[7, 42]));
    recorder.exit(60, &stack(18, &[7, 42]));

    let trace = recorder.finish();

    assert_eq!(trace.roots.len(), 1);
    let function_1 = &trace.roots[0];
    assert_eq!(function_1.callee.as_deref(), Some("function_1"));
    assert_eq!((function_1.enter_clk, function_1.exit_clk), (10, Some(60)));
    assert_eq!(function_1.results.as_deref(), Some([7, 42].as_slice()));

    let names: Vec<_> = function_1.children.iter().map(|frame| frame.callee.as_deref()).collect();
    assert_eq!(names, [Some("function_2"), Some("function_3")]);
    assert_eq!(function_1.children[0].results.as_deref(), Some([42].as_slice()));
    assert_eq!(function_1.children[1].results.as_deref(), Some([7].as_slice()));
}

/// ```text
/// fn consume_u64(n: u64)   // stack 16 -> 16
/// ```
///
/// Padding at the minimum stack depth is not reported as results.
#[test]
fn min_depth_padding_is_not_counted_as_result() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("consume_u64", Some(0), None);
    recorder.observe_arg(0, "n", Some(2), Some(vec![0, 0]));

    recorder.exit(20, &stack(16, &[]));

    let consume = &recorder.finish().roots[0];
    assert_eq!(consume.results.as_deref(), Some([].as_slice()));
}

/// ```text
/// fn function_2(x: Felt) -> Felt { load_sw(x) }   // load_sw is MASM, it has no markers
///
/// function_2                 the callee runs   -> names the call
/// intrinsics::mem::load_sw   it calls this     -> skipped
/// ```
///
/// `load_sw` gets no call of its own, and must not rename this one.
#[test]
fn an_unmarked_call_does_not_rename_the_frame_it_runs_in() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_2", None, None);
    recorder.observe_callee("intrinsics::mem::load_sw", None, None);
    recorder.exit(20, &stack(17, &[42]));

    let trace = recorder.finish();

    assert_eq!(trace.roots[0].callee.as_deref(), Some("function_2"));
}

/// ```text
/// fn fib(n: Felt) -> Felt { fib(n - 1) + fib(n - 2) }   // dynexec to itself
/// ```
///
/// Recursive records can share a selected callee without sharing their children.
#[test]
fn recursive_records_keep_their_selected_callee() {
    fn fib_value(n: u64) -> u64 {
        if n < 2 {
            n
        } else {
            fib_value(n - 1) + fib_value(n - 2)
        }
    }

    // The collector supplies the selected identity for each recursive invocation.
    fn drive(recorder: &mut CallTraceRecorder, n: u64, clk: &mut usize) {
        *clk += 10;
        recorder.enter(*clk, Vec::new());
        recorder.observe_callee("fib", Some(1), None);

        if n >= 2 {
            drive(recorder, n - 1, clk);
            drive(recorder, n - 2, clk);
        }
        *clk += 10;
        recorder.exit(*clk, &stack(16, &[fib_value(n)]));
    }

    let mut recorder = CallTraceRecorder::default();
    drive(&mut recorder, 4, &mut 0);
    let root = recorder.finish().roots.remove(0);

    assert_eq!(root.callee.as_deref(), Some("fib"));
    assert_eq!(root.results.as_deref(), Some([3].as_slice())); // fib(4) = 3
    assert_eq!(root.children.len(), 2);

    let fib3 = &root.children[0];
    let fib2 = &root.children[1];
    assert_eq!(fib3.callee.as_deref(), Some("fib"));
    assert_eq!(fib3.results.as_deref(), Some([2].as_slice())); // fib(3) = 2
    assert_eq!(fib2.callee.as_deref(), Some("fib"));
    assert_eq!(fib2.results.as_deref(), Some([1].as_slice())); // fib(2) = 1

    let deep = &fib3.children[0];
    assert_eq!(deep.callee.as_deref(), Some("fib")); // fib(2)
    assert_eq!(deep.children[0].results.as_deref(), Some([1].as_slice())); // fib(1) = 1
    assert_eq!(deep.children[1].results.as_deref(), Some([0].as_slice())); // fib(0) = 0
}

/// ```text
/// fn function_1() { function_2(); panic!() }
///
/// function_2   returns   -> has an exit cycle
/// function_1   fails     -> has none
/// ```
///
/// The trace still shows the call that failed.
#[test]
fn a_frame_left_open_has_no_exit() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", None, None);
    recorder.enter(20, Vec::new());
    recorder.observe_callee("function_2", None, None);
    recorder.exit(30, &stack(17, &[42]));

    let trace = recorder.finish();

    let function_1 = &trace.roots[0];
    assert_eq!(function_1.exit_clk, None);
    assert_eq!(function_1.cycles(), None);
    assert_eq!(function_1.children[0].exit_clk, Some(30));
}

/// ```text
/// fn function_1(a: Felt) { function_2(7, 9) }
/// fn function_2(b: Felt, c: Felt) { .. }
///
/// a = 5   function_1's own parameter          -> kept
/// c = 9   still reported after function_2 ran -> skipped
/// ```
///
/// `function_1` keeps only `a` - see `args_sealed`.
#[test]
fn arguments_are_not_collected_after_the_frame_makes_a_call() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", None, None);
    observe_felt_arg(&mut recorder, 1, "a", 5);
    recorder.enter(20, Vec::new());
    recorder.observe_callee("function_2", None, None);
    observe_felt_arg(&mut recorder, 1, "b", 7);
    observe_felt_arg(&mut recorder, 2, "c", 9);
    recorder.exit(30, &stack(17, &[0]));
    observe_felt_arg(&mut recorder, 2, "c", 9);
    recorder.exit(40, &stack(17, &[0]));

    let trace = recorder.finish();

    let function_1 = &trace.roots[0];
    let names: Vec<_> = function_1.args.iter().map(|arg| arg.name.as_str()).collect();
    assert_eq!(names, ["a"]);
    let function_2 = &function_1.children[0];
    let names: Vec<_> = function_2.args.iter().map(|arg| arg.name.as_str()).collect();
    assert_eq!(names, ["b", "c"]);
}

/// `has_arg` answers for the innermost open frame only, so the caller can skip a read it
/// would throw away.
#[test]
fn an_argument_already_recorded_is_reported_as_held() {
    let mut recorder = CallTraceRecorder::default();
    assert!(!recorder.has_arg(1), "no frame is open");

    recorder.enter(10, Vec::new());
    assert!(!recorder.has_arg(1));
    observe_felt_arg(&mut recorder, 1, "a", 3);
    assert!(recorder.has_arg(1));
    assert!(!recorder.has_arg(2));

    // The inner frame holds none of the outer frame's arguments.
    recorder.enter(20, Vec::new());
    assert!(!recorder.has_arg(1));
}

/// ```text
/// fn function_1(mut op: Felt, amount: Felt) -> Felt { op = 99; .. }   // function_1(3, 5)
///
/// amount = 5   comes first, but is the second parameter
/// op = 3       the call was made with this   -> kept
/// op = 99      the body wrote this later     -> skipped
/// ```
///
/// The trace shows `op = 3, amount = 5`.
#[test]
fn arguments_are_ordered_and_the_first_observation_is_kept() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", None, None);
    observe_felt_arg(&mut recorder, 2, "amount", 5);
    observe_felt_arg(&mut recorder, 1, "op", 3);
    observe_felt_arg(&mut recorder, 1, "op", 99);
    recorder.exit(20, &stack(17, &[8]));

    let trace = recorder.finish();

    let args: Vec<_> = trace.roots[0]
        .args
        .iter()
        .map(|arg| (arg.index, arg.name.as_str(), arg.values.as_deref()))
        .collect();
    assert_eq!(args, [(1, "op", Some([3].as_slice())), (2, "amount", Some([5].as_slice()))]);
}

/// ```text
/// fn function_1(op: Felt, amount: Felt) -> Felt { op + amount }   // returns one felt
/// ```
///
/// The signature says one result, so the top felt of the stack is reported.
#[test]
fn a_felt_result_is_the_top_of_the_stack() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(1), None);

    observe_felt_arg(&mut recorder, 1, "a", 3);
    observe_felt_arg(&mut recorder, 2, "b", 5);
    recorder.exit(20, &stack(17, &[8]));

    let trace = recorder.finish();

    assert_eq!(trace.roots[0].results.as_deref(), Some([8].as_slice()));
}

/// Argument width no longer drives the results: an argument of unknown width still leaves the
/// results known, because the count comes from the callee's signature.
#[test]
fn an_argument_of_unknown_width_does_not_affect_the_results() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(1), None);

    observe_felt_arg(&mut recorder, 1, "a", 3);
    recorder.observe_arg(2, "b", None, None);
    recorder.exit(20, &stack(17, &[8]));

    let trace = recorder.finish();

    let function_1 = &trace.roots[0];
    assert_eq!(function_1.results.as_deref(), Some([8].as_slice()));
    assert_eq!(function_1.args[1].felt_count, None);
    assert_eq!(function_1.args[1].values, None);
}

/// ```text
/// fn function_1(x: u64) -> u64 { .. }   // returns a u64
/// ```
///
/// A `u64` result is two felts, so the top two of the stack are reported.
#[test]
fn a_u64_result_is_two_felts() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(2), None);

    recorder.observe_arg(1, "x", Some(2), Some(vec![0, 1]));
    recorder.exit(20, &stack(18, &[9, 8]));

    let trace = recorder.finish();

    let function_1 = &trace.roots[0];
    assert_eq!(function_1.results.as_deref(), Some([9, 8].as_slice()));
    assert_eq!(function_1.args[0].values.as_deref(), Some([0, 1].as_slice()));
}

/// ```text
/// fn function_1(w: Word, n: Felt) { .. }   // returns nothing
/// ```
///
/// The signature says no results, so none are reported and the 99 left on top of the stack is
/// ignored.
#[test]
fn a_call_that_returns_nothing_reports_no_results() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(0), None);

    recorder.observe_arg(1, "w", Some(4), Some(vec![1, 2, 3, 4]));
    observe_felt_arg(&mut recorder, 2, "n", 5);
    recorder.exit(20, &stack(16, &[99]));

    let trace = recorder.finish();

    assert_eq!(trace.roots[0].results.as_deref(), Some([].as_slice()));
}

/// ```text
/// fn function_1(a: Felt) { .. }   // returns nothing
/// ```
///
/// The 99 left on top belongs to the caller, and the signature says no results, so none are
/// reported.
#[test]
fn a_call_without_results_reports_empty() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", Some(0), None);

    observe_felt_arg(&mut recorder, 1, "a", 3);
    recorder.exit(20, &stack(16, &[99]));

    let trace = recorder.finish();

    assert_eq!(trace.roots[0].results.as_deref(), Some([].as_slice()));
}

/// A call whose callee has no signature has no output width, so its results are unknown rather
/// than guessed from the stack.
#[test]
fn results_are_unknown_without_a_signature() {
    let mut recorder = CallTraceRecorder::default();
    recorder.enter(10, Vec::new());
    recorder.observe_callee("function_1", None, None);
    recorder.exit(20, &stack(16, &[8]));

    let trace = recorder.finish();

    assert_eq!(trace.roots[0].results, None);
}
