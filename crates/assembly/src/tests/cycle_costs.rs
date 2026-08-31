// INSTRUCTION CYCLE COSTS
// ================================================================================================

use super::*;

/// Pins the cycle cost of every instruction documented in
/// `docs/src/user_docs/assembly/field_operations.md` to the number of operations the assembler
/// actually emits, so the two cannot drift apart.
///
/// Cost is measured by differencing programs containing the instruction once, twice and three
/// times: this cancels the entrypoint prologue exactly, and requiring the two deltas to agree
/// rules out any fusion between adjacent copies.
#[test]
fn field_operation_cycle_costs_match_docs() {
    // (source, documented cycles)
    let cases: &[(&str, usize)] = &[
        // Assertions and tests
        ("assert", 1),
        ("assertz", 2),
        ("assert_eq", 2),
        ("assert_eqw", 11),
        // Arithmetic and Boolean operations
        ("add", 1),
        ("add.2", 2),
        ("sub", 2),
        ("sub.2", 2),
        ("mul", 1),
        ("mul.2", 2),
        ("div", 2),
        ("div.2", 2),
        ("neg", 1),
        ("inv", 1),
        ("pow2", 16),
        ("exp", 72),
        ("exp.u8", 17),
        ("exp.u16", 25),
        ("exp.u32", 41),
        ("exp.u63", 72),
        // exp.b: small-power table for b <= 7, then 11 + floor(log2(b))
        ("exp.0", 3),
        ("exp.1", 1),
        ("exp.2", 2),
        ("exp.3", 4),
        ("exp.4", 6),
        ("exp.5", 8),
        ("exp.6", 10),
        ("exp.7", 12),
        ("exp.8", 14),
        ("exp.16", 15),
        ("exp.256", 19),
        ("ilog2", 70),
        ("not", 1),
        ("and", 1),
        ("or", 1),
        ("xor", 7),
        // Comparison operations
        ("eq", 1),
        ("eq.2", 2),
        ("neq", 2),
        ("neq.2", 3),
        ("lt", 17),
        ("lt.2", 18),
        ("lte", 18),
        ("lte.2", 19),
        ("gt", 16),
        ("gt.2", 17),
        ("gte", 17),
        ("gte.2", 18),
        ("is_odd", 6),
        ("eqw", 15),
        // Extension field operations
        ("ext2add", 5),
        ("ext2sub", 7),
        ("ext2mul", 3),
        ("ext2neg", 4),
        ("ext2inv", 11),
        ("ext2div", 14),
    ];

    let ops_for = |instruction: &str, copies: usize| -> usize {
        let context = TestContext::default();
        let body = core::iter::repeat_n(instruction, copies).collect::<Vec<_>>().join("\n    ");
        let source = source_file!(&context, format!("begin\n    {body}\nend"));
        let program = Assembler::new(context.source_manager())
            .assemble_program("program", source)
            .expect("assembly failed")
            .unwrap_program();

        program
            .mast_forest()
            .nodes()
            .iter()
            .filter_map(|node| node.get_basic_block())
            .map(|block| block.raw_operations().count())
            .sum()
    };

    let mut mismatches = Vec::new();
    for (instruction, documented) in cases {
        let (one, two, three) =
            (ops_for(instruction, 1), ops_for(instruction, 2), ops_for(instruction, 3));
        let (first, second) = (two - one, three - two);
        assert_eq!(
            first, second,
            "{instruction}: cost is not additive across copies ({first} then {second}); \
             the differencing measurement is not valid for this instruction"
        );
        if first != *documented {
            mismatches.push(format!("  {instruction}: documented {documented}, emits {first}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "field_operations.md is out of date:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn bare_exp_lowers_to_63_expacc_rows() -> Result<(), Report> {
    let context = TestContext::default();
    let program = Assembler::new(context.source_manager())
        .assemble_program("p", "begin push.5 push.3 exp drop end")?
        .unwrap_program();
    let ops: Vec<Operation> = program.mast_forest()[program.entrypoint()]
        .unwrap_basic_block()
        .operations()
        .copied()
        .collect();

    let start = ops.iter().position(|op| matches!(op, Operation::Expacc)).unwrap();
    assert_eq!(ops.iter().filter(|op| matches!(op, Operation::Expacc)).count(), 63);

    let end = start + 63;
    assert_matches!(ops.get(end), Some(Operation::Drop));
    assert_matches!(ops.get(end + 1), Some(Operation::Drop));
    assert_matches!(ops.get(end + 2), Some(Operation::Swap));
    assert_matches!(ops.get(end + 3), Some(Operation::Eqz));
    assert_matches!(ops.get(end + 4), Some(Operation::Assert(_)));

    Ok(())
}

#[test]
fn exp_imm_uses_exact_exponent_bit_length() -> Result<(), Report> {
    let context = TestContext::default();

    for pow in [(1_u64 << 63) - 1, 1_u64 << 63, Felt::ORDER_U64 - 2, Felt::ORDER_U64 - 1] {
        let source = format!("begin push.3 exp.{pow} drop end");
        let program = Assembler::new(context.source_manager())
            .assemble_program("p", source.as_str())?
            .unwrap_program();
        let num_expacc = program.mast_forest()[program.entrypoint()]
            .unwrap_basic_block()
            .operations()
            .filter(|op| matches!(op, Operation::Expacc))
            .count();

        assert_eq!(num_expacc, pow.ilog2() as usize + 1, "unexpected row count for pow = {pow}");
    }

    Ok(())
}
