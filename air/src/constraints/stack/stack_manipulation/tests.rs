use miden_core::{Felt, ONE, Operation, ZERO};
use proptest::prelude::*;

use super::{super::STACK_TRACE_OFFSET, EvaluationFrame, NUM_CONSTRAINTS, enforce_constraints};
use crate::stack::op_flags::{OpFlags, generate_evaluation_frame};

// RANDOMIZED TESTS
// ================================================================================================

proptest! {

    // --------------- dupn operation -------------------------------------------------------------

    #[test]
    fn test_dupn_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let nidex = [0,1,2,3,4,5,6,7,9,11,13,15];
        for n in nidex.iter() {
            let frame = get_dup_test_frame(a, *n);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }
    }

    // --------------- swap operation -------------------------------------------------------------

    #[test]
    fn test_swap_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_swap_test_frame(a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // --------------- swapwx operation -------------------------------------------------------------

    #[test]
    fn test_swapwx_operation(
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        d in any::<u64>(),
        e in any::<u64>(),
        f in any::<u64>(),
        g in any::<u64>(),
        h in any::<u64>())
    {
        // -----------  swapw operation ---------------------------------------

        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_swapw_test_frame(a, b, c, d, e, f, g, h);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

        // -----------  swapw2 operation ---------------------------------------

        let frame = get_swapw2_test_frame(a, b, c, d, e, f, g, h);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

        // -----------  swapw3 operation ---------------------------------------

        let frame = get_swapw3_test_frame(a, b, c, d, e, f, g, h);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // --------------- swapdw operation -------------------------------------------------------------

    #[test]
    fn test_swapdw_operation(
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        d in any::<u64>(),
        e in any::<u64>(),
        f in any::<u64>(),
        g in any::<u64>(),
        h in any::<u64>(),
        i in any::<u64>(),
        j in any::<u64>(),
        k in any::<u64>(),
        l in any::<u64>(),
        m in any::<u64>(),
        n in any::<u64>(),
        o in any::<u64>(),
        p in any::<u64>(),
    ) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let frame = get_swapdw_test_frame(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);
    }

    // --------------- movupn operation -------------------------------------------------------------

    #[test]
    fn test_movupn_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let nidex = [2, 3, 4, 5, 6, 7, 8];
        for n in nidex.iter() {
            let frame = get_movup_test_frame(a, *n);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }
    }

    // --------------- movupn operation -------------------------------------------------------------

    #[test]
    fn test_movdnn_operation(a in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];
        let nidex = [2, 3, 4, 5, 6, 7, 8];
        for n in nidex.iter() {
            let frame = get_movdn_test_frame(a, *n);
            let result = get_constraint_evaluation(frame);
            assert_eq!(expected, result);
        }
    }

    // --------------- cswap operation -------------------------------------------------------------

    #[test]
    fn test_cswap_operation(a in any::<u64>(), b in any::<u64>()) {
        let expected = [ZERO; NUM_CONSTRAINTS];

        // -------------- when the first element is 0 ---------------------

        let c = 0;
        let frame = get_cswap_test_frame(c, a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

        // -------------- when the first element is 1 ---------------------

        let c = 1;
        let frame = get_cswap_test_frame(c, a, b);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

    }

    // --------------- cswap operation -------------------------------------------------------------

    #[test]
    fn test_cswapw_operation(
        a in any::<u64>(),
        b in any::<u64>(),
        c in any::<u64>(),
        d in any::<u64>(),
        e in any::<u64>(),
        f in any::<u64>(),
        g in any::<u64>(),
        h in any::<u64>()
    ) {
        let expected = [ZERO; NUM_CONSTRAINTS];

        // -------------- when the first element is 0 ---------------------

        let x = 0;
        let frame = get_cswapw_test_frame(x, a, b, c, d, e, f, g, h);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

        // -------------- when the first element is 1 ---------------------

        let x = 1;
        let frame = get_cswapw_test_frame(x, a, b, c, d, e, f, g, h);
        let result = get_constraint_evaluation(frame);
        assert_eq!(expected, result);

    }

}

// UNIT TESTS
// ================================================================================================

// --------------- pad operation -------------------------------------------------------------

#[test]
fn test_pad_operation() {
    let expected = [ZERO; NUM_CONSTRAINTS];
    let frame = get_pad_test_frame();
    let result = get_constraint_evaluation(frame);
    assert_eq!(expected, result);
}

// TEST HELPERS
// ================================================================================================

/// Returns the result of stack operation constraint evaluations on the provided frame.
fn get_constraint_evaluation(frame: EvaluationFrame<Felt>) -> [Felt; NUM_CONSTRAINTS] {
    let mut result = [ZERO; NUM_CONSTRAINTS];

    let op_flag = &OpFlags::new(&frame);

    enforce_constraints(&frame, &mut result, op_flag);

    result
}

/// Generates the correct current and next rows for the PAD operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_pad_test_frame() -> EvaluationFrame<Felt> {
    // frame initialised with a pad operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Pad.op_code().into());

    // Set the output. The top element in the next frame should be 0.
    frame.next_mut()[STACK_TRACE_OFFSET] = ZERO;

    frame
}

/// Generates the correct current and next rows for the DUPn operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_dup_test_frame(a: u64, n: usize) -> EvaluationFrame<Felt> {
    let op = match n {
        0 => Operation::Dup0.op_code() as usize,
        1 => Operation::Dup1.op_code() as usize,
        2 => Operation::Dup2.op_code() as usize,
        3 => Operation::Dup3.op_code() as usize,
        4 => Operation::Dup4.op_code() as usize,
        5 => Operation::Dup5.op_code() as usize,
        6 => Operation::Dup6.op_code() as usize,
        7 => Operation::Dup7.op_code() as usize,
        9 => Operation::Dup9.op_code() as usize,
        11 => Operation::Dup11.op_code() as usize,
        13 => Operation::Dup13.op_code() as usize,
        15 => Operation::Dup15.op_code() as usize,
        _ => panic!("Invalid index"),
    };

    // frame initialised with a dupn operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(op);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET + n] = Felt::new(a);
    for i in 0..15 {
        frame.next_mut()[STACK_TRACE_OFFSET + i + 1] = frame.current()[STACK_TRACE_OFFSET + i]
    }
    frame.next_mut()[STACK_TRACE_OFFSET] = frame.current()[STACK_TRACE_OFFSET + n];

    frame
}

/// Generates the correct current and next rows for the SWAP operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_swap_test_frame(a: u64, b: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a swap operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::Swap.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);

    frame
}

/// Generates the correct current and next rows for the SWAPW operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_swapw_test_frame(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
) -> EvaluationFrame<Felt> {
    // frame initialised with a swapw operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::SwapW.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c);
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(d);
    frame.current_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(e);
    frame.current_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(f);
    frame.current_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(g);
    frame.current_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(h);

    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(e);
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(f);
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(g);
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(h);
    frame.next_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(c);
    frame.next_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(d);

    frame
}

/// Generates the correct current and next rows for the SWAPW2 operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_swapw2_test_frame(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
) -> EvaluationFrame<Felt> {
    // frame initialised with a swapw2 operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::SwapW2.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c);
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(d);
    frame.current_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(e);
    frame.current_mut()[STACK_TRACE_OFFSET + 9] = Felt::new(f);
    frame.current_mut()[STACK_TRACE_OFFSET + 10] = Felt::new(g);
    frame.current_mut()[STACK_TRACE_OFFSET + 11] = Felt::new(h);

    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(e);
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(f);
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(g);
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(h);
    frame.next_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET + 9] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET + 10] = Felt::new(c);
    frame.next_mut()[STACK_TRACE_OFFSET + 11] = Felt::new(d);

    frame
}

/// Generates the correct current and next rows for the SWAPW3 operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_swapw3_test_frame(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
) -> EvaluationFrame<Felt> {
    // frame initialised with a swapw3 operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::SwapW3.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c);
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(d);
    frame.current_mut()[STACK_TRACE_OFFSET + 12] = Felt::new(e);
    frame.current_mut()[STACK_TRACE_OFFSET + 13] = Felt::new(f);
    frame.current_mut()[STACK_TRACE_OFFSET + 14] = Felt::new(g);
    frame.current_mut()[STACK_TRACE_OFFSET + 15] = Felt::new(h);

    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(e);
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(f);
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(g);
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(h);
    frame.next_mut()[STACK_TRACE_OFFSET + 12] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET + 13] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET + 14] = Felt::new(c);
    frame.next_mut()[STACK_TRACE_OFFSET + 15] = Felt::new(d);

    frame
}

/// Generates the correct current and next rows for the SWAPW operation and inputs and
/// returns an EvaluationFrame for testing.
#[expect(clippy::too_many_arguments)]
pub fn get_swapdw_test_frame(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    i: u64,
    j: u64,
    k: u64,
    l: u64,
    m: u64,
    n: u64,
    o: u64,
    p: u64,
) -> EvaluationFrame<Felt> {
    // frame initialised with a swapdw operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::SwapDW.op_code() as usize);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
    frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c);
    frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(d);
    frame.current_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(e);
    frame.current_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(f);
    frame.current_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(g);
    frame.current_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(h);
    frame.current_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(i);
    frame.current_mut()[STACK_TRACE_OFFSET + 9] = Felt::new(j);
    frame.current_mut()[STACK_TRACE_OFFSET + 10] = Felt::new(k);
    frame.current_mut()[STACK_TRACE_OFFSET + 11] = Felt::new(l);
    frame.current_mut()[STACK_TRACE_OFFSET + 12] = Felt::new(m);
    frame.current_mut()[STACK_TRACE_OFFSET + 13] = Felt::new(n);
    frame.current_mut()[STACK_TRACE_OFFSET + 14] = Felt::new(o);
    frame.current_mut()[STACK_TRACE_OFFSET + 15] = Felt::new(p);

    frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(i);
    frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(j);
    frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(k);
    frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(l);
    frame.next_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(m);
    frame.next_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(n);
    frame.next_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(o);
    frame.next_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(p);
    frame.next_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(a);
    frame.next_mut()[STACK_TRACE_OFFSET + 9] = Felt::new(b);
    frame.next_mut()[STACK_TRACE_OFFSET + 10] = Felt::new(c);
    frame.next_mut()[STACK_TRACE_OFFSET + 11] = Felt::new(d);
    frame.next_mut()[STACK_TRACE_OFFSET + 12] = Felt::new(e);
    frame.next_mut()[STACK_TRACE_OFFSET + 13] = Felt::new(f);
    frame.next_mut()[STACK_TRACE_OFFSET + 14] = Felt::new(g);
    frame.next_mut()[STACK_TRACE_OFFSET + 15] = Felt::new(h);

    frame
}

/// Generates the correct current and next rows for the MOVUPn operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_movup_test_frame(a: u64, n: usize) -> EvaluationFrame<Felt> {
    let op = match n {
        2 => Operation::MovUp2.op_code() as usize,
        3 => Operation::MovUp3.op_code() as usize,
        4 => Operation::MovUp4.op_code() as usize,
        5 => Operation::MovUp5.op_code() as usize,
        6 => Operation::MovUp6.op_code() as usize,
        7 => Operation::MovUp7.op_code() as usize,
        8 => Operation::MovUp8.op_code() as usize,
        _ => panic!("Invalid index"),
    };

    // frame initialised with a movupn operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(op);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET + n] = Felt::new(a);
    for i in 0..n {
        frame.next_mut()[STACK_TRACE_OFFSET + i + 1] = frame.current()[STACK_TRACE_OFFSET + i]
    }
    frame.next_mut()[STACK_TRACE_OFFSET] = frame.current()[STACK_TRACE_OFFSET + n];

    frame
}

/// Generates the correct current and next rows for the MOVDNn operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_movdn_test_frame(a: u64, n: usize) -> EvaluationFrame<Felt> {
    let op = match n {
        2 => Operation::MovDn2.op_code() as usize,
        3 => Operation::MovDn3.op_code() as usize,
        4 => Operation::MovDn4.op_code() as usize,
        5 => Operation::MovDn5.op_code() as usize,
        6 => Operation::MovDn6.op_code() as usize,
        7 => Operation::MovDn7.op_code() as usize,
        8 => Operation::MovDn8.op_code() as usize,
        _ => panic!("Invalid index"),
    };

    // frame initialised with a movdnn operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(op);

    // Set the output.
    frame.current_mut()[STACK_TRACE_OFFSET + n] = Felt::new(a);
    for i in 1..=n {
        frame.next_mut()[STACK_TRACE_OFFSET + i - 1] = frame.current()[STACK_TRACE_OFFSET + i]
    }
    frame.next_mut()[STACK_TRACE_OFFSET] = frame.current()[STACK_TRACE_OFFSET + n];

    frame
}

/// Generates the correct current and next rows for the CSWAP operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_cswap_test_frame(c: u64, a: u64, b: u64) -> EvaluationFrame<Felt> {
    // frame initialised with a cswap operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::CSwap.op_code() as usize);

    // Set the output.
    if c == 0 {
        frame.current_mut()[STACK_TRACE_OFFSET] = ZERO;
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(b);
        frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
        frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
    } else if c == 1 {
        frame.current_mut()[STACK_TRACE_OFFSET] = ONE;
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(b);
        frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(b);
        frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);
    } else {
        panic!("Invalid bit value")
    }

    frame
}

/// Generates the correct current and next rows for the CSWAPW operation and inputs and
/// returns an EvaluationFrame for testing.
pub fn get_cswapw_test_frame(
    x: u64,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
) -> EvaluationFrame<Felt> {
    // frame initialised with a cswapw operation using it's unique opcode.
    let mut frame = generate_evaluation_frame(Operation::CSwapW.op_code() as usize);

    // Set the output.
    if x == 0 {
        frame.current_mut()[STACK_TRACE_OFFSET] = ZERO;
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(b);
        frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(c);
        frame.current_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(d);
        frame.current_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(e);
        frame.current_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(f);
        frame.current_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(g);
        frame.current_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(h);

        frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(a);
        frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(b);
        frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(c);
        frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(d);
        frame.next_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(e);
        frame.next_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(f);
        frame.next_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(g);
        frame.next_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(h);
    } else if x == 1 {
        frame.current_mut()[STACK_TRACE_OFFSET] = ONE;
        frame.current_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(a);
        frame.current_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(b);
        frame.current_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(c);
        frame.current_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(d);
        frame.current_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(e);
        frame.current_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(f);
        frame.current_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(g);
        frame.current_mut()[STACK_TRACE_OFFSET + 8] = Felt::new(h);

        frame.next_mut()[STACK_TRACE_OFFSET] = Felt::new(e);
        frame.next_mut()[STACK_TRACE_OFFSET + 1] = Felt::new(f);
        frame.next_mut()[STACK_TRACE_OFFSET + 2] = Felt::new(g);
        frame.next_mut()[STACK_TRACE_OFFSET + 3] = Felt::new(h);
        frame.next_mut()[STACK_TRACE_OFFSET + 4] = Felt::new(a);
        frame.next_mut()[STACK_TRACE_OFFSET + 5] = Felt::new(b);
        frame.next_mut()[STACK_TRACE_OFFSET + 6] = Felt::new(c);
        frame.next_mut()[STACK_TRACE_OFFSET + 7] = Felt::new(d);
    } else {
        panic!("Invalid bit value")
    }

    frame
}
