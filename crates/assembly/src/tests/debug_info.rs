// DEBUG INFO
// ================================================================================================

use super::*;

fn replace_nops_with_named_inline_call_markers(
    context: &TestContext,
    procedure: &mut Procedure,
    markers: &[Option<&str>],
) -> Result<(), Report> {
    use miden_assembly_syntax::ast::DebugInlineCallInfo;

    let mut markers = markers.iter();
    for op in procedure.body_mut().iter_mut() {
        let Op::Inst(instruction) = op else {
            continue;
        };
        if !matches!(instruction.inner(), Instruction::Nop) {
            continue;
        }
        let Some(marker) = markers.next() else {
            break;
        };

        let span = instruction.span();
        let replacement = match marker {
            Some(name) => {
                let source_location = context
                    .source_manager()
                    .file_line_col(span)
                    .map_err(|error| Report::msg(error.to_string()))?;
                Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                    *name,
                    source_location.clone(),
                    source_location,
                ))
            },
            None => Instruction::DebugInlineCallClear,
        };
        *op = Op::Inst(Span::new(span, replacement));
    }

    assert!(markers.next().is_none(), "test fixture has too few marker placeholders");
    Ok(())
}

fn reachable_source_nodes(
    debug_info: &miden_mast_package::debug_info::PackageDebugInfo,
    root: miden_mast_package::debug_info::DebugSourceNodeId,
) -> BTreeSet<miden_mast_package::debug_info::DebugSourceNodeId> {
    let mut reachable = BTreeSet::new();
    let mut worklist = vec![root];
    while let Some(source_node_id) = worklist.pop() {
        if reachable.insert(source_node_id) {
            worklist.extend(debug_info[source_node_id].children.iter().copied());
        }
    }
    reachable
}

#[test]
fn inline_call_chains_are_recorded_on_call_and_structured_control_occurrences() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
        end

        begin
            nop
            nop
            call.callee
            nop
            nop
            if.true
                add
            else
                mul
            end
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::inlined"), None, Some("source::inlined")],
    )?;

    let package = Assembler::new(context.source_manager()).assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");

    for expected_op in ["call.", "if.true"] {
        let source_node = debug_info
            .nodes()
            .iter()
            .find(|source_node| {
                source_node
                    .asm_ops
                    .iter()
                    .any(|asm_op| debug_info[asm_op.op_name_idx].starts_with(expected_op))
            })
            .unwrap_or_else(|| panic!("missing source occurrence for {expected_op}"));
        let inline_calls = source_node
            .inline_calls
            .iter()
            .filter(|inline_call| inline_call.op_idx == 0)
            .collect::<Vec<_>>();

        assert_eq!(inline_calls.len(), 1, "{expected_op} should retain its inline chain");
        let function = debug_info
            .get_function(inline_calls[0].callee_idx)
            .expect("inline callee should be registered");
        assert_eq!(debug_info[function.name_idx].as_ref(), "source::inlined");
    }

    Ok(())
}

#[test]
fn inline_call_chains_cover_exec_source_occurrences() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
            mul
        end

        begin
            nop
            nop
            exec.callee
            nop
            nop
            exec.callee
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::inlined"), None, Some("source::inlined")],
    )?;

    let package = Assembler::new(context.source_manager()).assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");

    let callee_source = debug_info
        .nodes()
        .iter()
        .find(|source_node| {
            source_node
                .asm_ops
                .iter()
                .any(|asm_op| debug_info[asm_op.context_name_idx].contains("callee"))
                && !source_node.inline_calls.is_empty()
        })
        .expect("exec target should have a decorated source occurrence");
    for asm_op in callee_source
        .asm_ops
        .iter()
        .filter(|asm_op| debug_info[asm_op.context_name_idx].contains("callee"))
    {
        assert_eq!(
            callee_source
                .inline_calls
                .iter()
                .filter(|inline_call| inline_call.op_idx == asm_op.op_idx)
                .count(),
            1,
            "every operation in the exec target should retain the active inline chain",
        );
    }

    Ok(())
}

#[test]
fn exec_occurrences_do_not_reuse_stale_inline_chains() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc callee
            add
            mul
        end

        begin
            nop
            nop
            exec.callee
            nop
            exec.callee
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::decorated"), None],
    )?;

    let package = Assembler::new(context.source_manager()).assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");
    let entrypoint_source = package
        .entrypoint_source_node()
        .expect("executable should identify its entrypoint source occurrence");
    let reachable = reachable_source_nodes(&debug_info, entrypoint_source);
    let mut inline_counts = Vec::new();
    for source_node_id in reachable {
        for asm_op in &debug_info[source_node_id].asm_ops {
            if debug_info[asm_op.context_name_idx].contains("callee") {
                inline_counts.push(
                    debug_info.inline_calls_for_operation(source_node_id, asm_op.op_idx).count(),
                );
            }
        }
    }
    assert_eq!(
        inline_counts,
        [1, 1, 0, 0],
        "the plain exec must not inherit the earlier inline chain",
    );

    Ok(())
}

#[test]
fn nested_exec_inline_chains_are_innermost_first() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
        proc inner
            add
        end

        proc outer_target
            nop
            nop
            exec.inner
        end

        begin
            nop
            nop
            exec.outer_target
        end
        "
    );
    let mut module = context.parse_module(source)?;
    for procedure in module.procedures_mut() {
        if procedure.is_entrypoint() {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::outer")],
            )?;
        } else if procedure.name().as_str() == "outer_target" {
            replace_nops_with_named_inline_call_markers(
                &context,
                procedure,
                &[None, Some("source::inner")],
            )?;
        }
    }

    let package = Assembler::new(context.source_manager()).assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");
    let entrypoint_source = package
        .entrypoint_source_node()
        .expect("executable should identify its entrypoint source occurrence");
    let reachable = reachable_source_nodes(&debug_info, entrypoint_source);
    let inner_source = reachable
        .into_iter()
        .find(|source_node_id| {
            debug_info[*source_node_id].asm_ops.iter().any(|asm_op| {
                debug_info[asm_op.context_name_idx].contains("inner")
                    && debug_info[asm_op.op_name_idx].as_ref() == "add"
            })
        })
        .expect("nested exec target should be reachable from the entrypoint");
    let inner_op = debug_info[inner_source]
        .asm_ops
        .iter()
        .find(|asm_op| debug_info[asm_op.op_name_idx].as_ref() == "add")
        .expect("inner target should contain add");
    let names = debug_info
        .inline_calls_for_operation(inner_source, inner_op.op_idx)
        .map(|inline_call| {
            let function = debug_info
                .get_function(inline_call.callee_idx)
                .expect("inline callee should be registered");
            debug_info[function.name_idx].to_string()
        })
        .collect::<Vec<_>>();

    assert_eq!(names, ["source::inner", "source::outer"]);
    Ok(())
}

#[test]
fn external_exec_records_inline_context_at_the_boundary() -> TestResult {
    let context = TestContext::default();
    let library_module = context.parse_module(
        "
        namespace dep::math

        pub proc callee
            add
        end
        ",
    )?;
    let library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        library_module,
        None::<Box<Module>>,
    )?;
    let assembler = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Dynamic)?;
    let source = source_file!(
        &context,
        "
        use dep::math

        begin
            nop
            nop
            exec.math::callee
        end
        "
    );
    let mut module = context.parse_module(source)?;
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .expect("executable module should contain an entrypoint");
    replace_nops_with_named_inline_call_markers(
        &context,
        entrypoint,
        &[None, Some("source::external")],
    )?;

    let package = assembler.assemble_program("test", module)?;
    let debug_info = package
        .debug_info()
        .into_diagnostic()?
        .expect("assembled package should contain debug info");
    let external_source = debug_info
        .nodes()
        .iter()
        .find(|source_node| {
            package.mast_forest()[source_node.exec_node].is_external()
                && !source_node.inline_calls.is_empty()
        })
        .expect("decorated external exec should carry boundary inline context");

    assert_eq!(external_source.op_start, external_source.op_end);
    assert!(
        external_source
            .inline_calls
            .iter()
            .all(|inline_call| inline_call.op_idx == external_source.op_start)
    );
    Ok(())
}

#[test]
fn source_name_attribute_sets_debug_name_and_linkage_name() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace debug::names

        @source_name("duplicate")
        pub proc first
            push.1
        end

        @source_name("duplicate")
        pub proc second
            push.2
        end

        pub proc normal
            push.3
        end
        "#
    ))?;
    let package = Assembler::new(context.source_manager()).assemble_library(
        "debug-names",
        module,
        None::<Box<Module>>,
    )?;

    let assert_function_names = |package: &Package| {
        let debug_info = package
            .debug_info()
            .expect("package debug info should decode")
            .expect("package should contain debug info");
        let duplicate_functions = debug_info
            .functions()
            .iter()
            .filter(|function| {
                debug_info[function.name_idx].as_ref() == "::debug::names::duplicate"
            })
            .collect::<Vec<_>>();

        assert_eq!(duplicate_functions.len(), 2);
        assert_eq!(duplicate_functions[0].name_idx, duplicate_functions[1].name_idx);
        let linkage_names = duplicate_functions
            .iter()
            .map(|function| {
                let linkage_name_idx = function
                    .linkage_name_idx
                    .into_option()
                    .expect("source-named function should have a linkage name");
                debug_info[linkage_name_idx].to_string()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(linkage_names.len(), 2);
        assert!(linkage_names.iter().any(|name| name.ends_with("::first")));
        assert!(linkage_names.iter().any(|name| name.ends_with("::second")));

        let normal = debug_info
            .functions()
            .iter()
            .find(|function| debug_info[function.name_idx].ends_with("::normal"))
            .expect("normal function should retain its assembler path as its name");
        assert_eq!(normal.linkage_name_idx.into_option(), None);
    };

    assert_function_names(&package);
    let round_tripped = Package::read_from_bytes(&package.to_bytes())
        .expect("package with source-named functions should round trip");
    assert_function_names(&round_tripped);

    Ok(())
}

#[test]
fn malformed_source_name_attributes_are_rejected() -> TestResult {
    let context = TestContext::default();

    for attribute in [
        "@source_name",
        "@source_name(unquoted)",
        "@source_name(\"one\", \"two\")",
        "@source_name(value = \"named\")",
    ] {
        let source = source_file!(
            &context,
            format!(
                r#"
                namespace debug::invalid

                {attribute}
                pub proc test
                    nop
                end
                "#
            )
        );
        let module = context.parse_module(source)?;
        let error = Assembler::new(context.source_manager())
            .assemble_library("invalid-source-name", module, None::<Box<Module>>)
            .expect_err("malformed @source_name should be rejected");
        assert_diagnostic!(&error, "invalid `@source_name` procedure attribute");
        assert_diagnostic!(&error, "expected exactly one quoted string");
    }

    Ok(())
}
