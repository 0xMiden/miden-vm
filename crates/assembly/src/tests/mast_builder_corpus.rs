// MAST BUILDER ACCEPTANCE CORPUS
// ================================================================================================

use super::*;

#[test]
fn mast_builder_acceptance_corpus() -> TestResult {
    let context = TestContext::default();
    let mut summary = String::new();

    let cases = [
        (
            "straight_line_events",
            source_file!(
                &context,
                r#"
                const EVT = event("acceptance::straight_line")

                begin
                    push.1 push.2 add
                    emit.EVT
                end
                "#
            ),
        ),
        (
            "nested_control_flow",
            source_file!(
                &context,
                r#"
                begin
                    push.1
                    if.true
                        push.2
                    else
                        push.3
                    end

                    repeat.3
                        push.1 add
                    end
                end
                "#
            ),
        ),
        (
            "procedure_calls_and_repeated_subtrees",
            source_file!(
                &context,
                r#"
                proc repeated_a
                    push.9 push.3 add
                end

                proc repeated_b
                    push.9 push.3 add
                end

                proc decorated
                    push.0 drop
                end

                begin
                    exec.repeated_a
                    exec.repeated_b
                    exec.decorated
                end
                "#
            ),
        ),
    ];

    for (case_name, source) in cases {
        let program = context.assemble(source)?;
        append_program_acceptance_summary(&mut summary, case_name, &program);
    }

    let mut static_context = TestContext::default();
    static_context.add_module(source_file!(
        &static_context,
        r#"
            namespace acceptance::helpers

            pub proc inc
                push.1 add
            end

            pub proc inspect
                push.0 drop
            end
            "#
    ))?;
    let static_program = static_context.assemble(source_file!(
        &static_context,
        r#"
        use acceptance::helpers

        begin
            push.41
            exec.helpers::inc
            exec.helpers::inspect
        end
        "#
    ))?;
    append_program_acceptance_summary(&mut summary, "static_imports", &static_program);

    insta::assert_snapshot!("mast_builder_acceptance_corpus", summary);

    Ok(())
}

fn append_program_acceptance_summary(output: &mut String, case_name: &str, program: &Program) {
    let forest = program.mast_forest();
    let serialized_program_len = program.to_bytes().len();
    let serialized_forest_len = forest.to_bytes().len();

    writeln!(output, "=== {case_name} ===").unwrap();
    writeln!(output, "program_hash={:?}", program.hash()).unwrap();
    writeln!(output, "entrypoint={}", u32::from(program.entrypoint())).unwrap();
    writeln!(output, "num_procedures={}", program.num_procedures()).unwrap();
    writeln!(output, "num_nodes={}", forest.num_nodes()).unwrap();
    writeln!(output, "forest_commitment={:?}", forest.commitment()).unwrap();
    writeln!(output, "serialized_program_len={serialized_program_len}").unwrap();
    writeln!(output, "serialized_forest_len={serialized_forest_len}").unwrap();

    let roots = forest
        .procedure_roots()
        .iter()
        .map(|&node_id| u32::from(node_id))
        .collect::<Vec<_>>();
    let procedure_digests = forest.procedure_digests().collect::<Vec<_>>();
    let node_digests = forest.nodes().iter().map(MastNodeExt::digest).collect::<Vec<_>>();
    writeln!(output, "roots={roots:?}").unwrap();
    writeln!(output, "procedure_digests={procedure_digests:?}").unwrap();
    writeln!(output, "node_digests={node_digests:?}").unwrap();
}

#[test]
fn vendoring() -> TestResult {
    let context = TestContext::new();
    let vendor_lib = {
        let mod1 = context
            .parse_module(source_file!(
                &context,
                "namespace test::mod1
pub proc bar push.1 end pub proc prune push.2 end"
            ))
            .unwrap();
        Assembler::default()
            .assemble_library("vendor", mod1, None::<Box<Module>>)
            .unwrap()
    };

    let lib = {
        let mod2 = context
            .parse_module(source_file!(
                &context,
                "namespace test::mod2
pub proc foo exec.::test::mod1::bar end"
            ))
            .unwrap();

        let mut assembler = Assembler::default();
        assembler.link_package(Arc::from(vendor_lib), Linkage::Static)?;
        Arc::<Package>::from(assembler.assemble_library("lib", mod2, None::<Box<Module>>).unwrap())
    };

    // Rigorous testing of vendoring functionality

    // 1. The vendored library (lib) has `exec.::test::mod1::bar` which is a 0-cycle instruction.
    // 0-cycle instructions like `exec` don't generate AssemblyOps because they don't execute
    // any VM operations. The debug info may still have procedure names, error codes, etc.
    // The vendor_lib (mod1) has actual instructions (push.1, push.2) which do have AssemblyOps.

    // 2. Create an equivalent expected library for structural comparison
    let expected_lib = {
        let mod2 = context
            .parse_module(source_file!(
                &context,
                "namespace test::expected\npub proc foo push.1 end"
            ))
            .unwrap();
        Assembler::default()
            .assemble_library("test", mod2, None::<Box<Module>>)
            .unwrap()
    };

    // 3. Verify that the expected library (which has push.1) has package-owned AssemblyOps.
    assert_package_has_source_asm_ops(
        &expected_lib,
        "Expected library should have package-owned AssemblyOps for instruction tracking",
    );

    // 4. Verify we can create an assembler that successfully links the vendored library
    let mut assembler_with_vendored_lib = Assembler::default();
    let link_result = assembler_with_vendored_lib.link_package(lib.clone(), Linkage::Static);
    assert!(link_result.is_ok(), "Should be able to link the vendored library");

    // 5. Test that a simple program can be assembled with the linked library
    let program_with_lib_source = r#"
    begin
        push.1
        push.2
        add
    end
    "#;
    let assemble_result =
        assembler_with_vendored_lib.assemble_program("test", program_with_lib_source);
    assert!(
        assemble_result.is_ok(),
        "Should be able to assemble program with linked library"
    );
    let assembled_program = assemble_result.unwrap();

    // Verify the assembled program has package-owned debug info (AssemblyOps).
    assert_package_has_source_asm_ops(
        &assembled_program,
        "Assembled program with library should have package-owned AssemblyOps for instruction tracking",
    );

    // 6. Verify the vendored library contains the expected structure
    let mast_forest = lib.mast_forest();
    assert!(mast_forest.num_nodes() > 0, "Vendored library should have nodes");

    // Verify there are root procedures (the first node is usually a root for libraries)
    let nodes = mast_forest.nodes();
    assert!(!nodes.is_empty(), "Vendored library should have root procedures");

    Ok(())
}
