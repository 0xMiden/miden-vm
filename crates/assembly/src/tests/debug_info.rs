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
            .filter(|inline_call| inline_call.contains_operation(0))
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
                .filter(|inline_call| inline_call.contains_operation(asm_op.op_idx))
                .count(),
            2,
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
        [2, 2, 1, 1],
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

    assert_eq!(
        names,
        ["::$exec::inner", "source::inner", "::$exec::outer_target", "source::outer"]
    );
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
fn compact_inline_ranges_survive_padding_and_static_linking() -> TestResult {
    let context = TestContext::default();
    let body = "push.1 drop\n".repeat(200);
    let mut library_module = context.parse_module(source_file!(
        &context,
        format!("namespace dep::math pub proc callee nop {body} nop push.2 drop end")
    ))?;
    let callee = library_module.procedures_mut().next().unwrap();
    replace_nops_with_named_inline_call_markers(&context, callee, &[Some("source::inner"), None])?;
    let library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        library_module,
        None::<Box<Module>>,
    )?;
    let info = library.debug_info().into_diagnostic()?.unwrap();
    assert_eq!(info.nodes().iter().map(|node| node.inline_calls.len()).sum::<usize>(), 1);

    let mut module = context
        .parse_module(source_file!(&context, "use dep::math begin nop exec.math::callee end"))?;
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(&context, entrypoint, &[Some("source::outer")])?;
    let package = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Static)?
        .assemble_program("test", module)?;
    let info = package.debug_info().into_diagnostic()?.unwrap();
    let mut checked = BTreeSet::new();
    for (source_index, node) in info.nodes().iter().enumerate() {
        let source_id = miden_mast_package::debug_info::DebugSourceNodeId::from(
            u32::try_from(source_index).unwrap(),
        );
        for operation in &node.asm_ops {
            let name = info[operation.op_name_idx].as_ref();
            if !matches!(name, "push.1" | "push.2") {
                continue;
            }
            let chain = info
                .inline_calls_for_operation(source_id, operation.op_idx)
                .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
                .collect::<Vec<_>>();
            let expected = if name == "push.1" {
                vec!["source::inner", "source::outer"]
            } else {
                vec!["source::outer"]
            };
            assert_eq!(chain, expected);
            checked.insert(operation.op_idx);
        }
    }
    assert_eq!(checked.len(), 201);
    Ok(())
}

#[test]
fn many_inline_ranges_survive_padding_and_static_linking() -> TestResult {
    let context = TestContext::default();
    let body = "nop nop push.1 drop nop nop push.2 drop\n".repeat(128);
    let mut library_module = context.parse_module(source_file!(
        &context,
        format!("namespace dep::math pub proc callee {body} end")
    ))?;
    let markers = [None, Some("source::first"), None, Some("source::second")].repeat(128);
    let callee = library_module.procedures_mut().next().unwrap();
    replace_nops_with_named_inline_call_markers(&context, callee, &markers)?;
    let library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        library_module,
        None::<Box<Module>>,
    )?;
    let info = library.debug_info().into_diagnostic()?.unwrap();
    assert_eq!(info.nodes().iter().map(|node| node.inline_calls.len()).sum::<usize>(), 256);

    let mut module = context
        .parse_module(source_file!(&context, "use dep::math begin nop exec.math::callee end"))?;
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    replace_nops_with_named_inline_call_markers(&context, entrypoint, &[Some("source::outer")])?;
    let package = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Static)?
        .assemble_program("test", module)?;
    let info = package.debug_info().into_diagnostic()?.unwrap();
    let mut checked = BTreeSet::new();
    for (source_index, node) in info.nodes().iter().enumerate() {
        let source_id = miden_mast_package::debug_info::DebugSourceNodeId::from(
            u32::try_from(source_index).unwrap(),
        );
        for operation in &node.asm_ops {
            let name = info[operation.op_name_idx].as_ref();
            let inner = match name {
                "push.1" => "source::first",
                "push.2" => "source::second",
                _ => continue,
            };
            let chain = info
                .inline_calls_for_operation(source_id, operation.op_idx)
                .map(|row| info[info.get_function(row.callee_idx).unwrap().name_idx].as_ref())
                .collect::<Vec<_>>();
            assert_eq!(chain, vec![inner, "source::outer"]);
            checked.insert(operation.op_idx);
        }
    }
    assert_eq!(checked.len(), 256);
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

#[test]
fn plain_exec_preserves_canonical_definitions() -> TestResult {
    for visibility in ["pub ", ""] {
        let context = TestContext::default();
        let source = format!(
            "namespace debug::repro\n{visibility}proc leaf push.42 end\npub proc wrapper exec.leaf end"
        );
        let package = Assembler::new(context.source_manager()).assemble_library(
            "probe",
            source,
            None::<String>,
        )?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let leaf = debug
            .functions()
            .iter()
            .find(|f| debug[f.name_idx].ends_with("::leaf"))
            .unwrap();
        let wrapper = debug
            .functions()
            .iter()
            .find(|f| debug[f.name_idx].ends_with("::wrapper"))
            .unwrap();
        assert_eq!(leaf.mast_root, wrapper.mast_root);
        assert_ne!(leaf.source_node, wrapper.source_node);
        assert!(debug[leaf.source_node.into_option().unwrap()].inline_calls.is_empty());
    }

    Ok(())
}

#[test]
fn plain_exec_preserves_invocation_identity_through_merging() -> TestResult {
    use miden_assembly_syntax::debuginfo::{SourceLanguage, Uri};
    use miden_core::serde::{Deserializable, Serializable};

    let source = "proc leaf push.42 end\nproc wrapper exec.leaf end\nbegin\n exec.wrapper\n drop\n exec.wrapper\n drop\nend";
    let assemble = |text: &str| {
        let context = TestContext::default();
        let file = context.source_manager().load(
            SourceLanguage::Masm,
            Uri::new("memory://reproducer.masm"),
            text.to_string(),
        );
        Assembler::new(context.source_manager()).assemble_program("program", file)
    };
    let wrapper_package = assemble(source)?;
    let leaf_package =
        assemble(&source.replace("exec.wrapper\n drop\nend", "exec.leaf   \n drop\nend"))?;
    assert_eq!(wrapper_package.mast_forest().to_bytes(), leaf_package.mast_forest().to_bytes());
    // Captured from v0.35.0 before the fix: source changes must not alter execution bytes.
    let baseline = include_bytes!("fixtures/exec-source-identity.mast");
    assert_eq!(wrapper_package.mast_forest().to_bytes(), baseline.as_slice());
    let debug = wrapper_package.debug_info().into_diagnostic()?.unwrap();
    let decoded =
        miden_mast_package::debug_info::PackageDebugInfo::read_from_bytes(&debug.to_bytes())
            .into_diagnostic()?;
    assert_eq!(decoded, debug);
    assert_ne!(
        debug.to_bytes(),
        leaf_package.debug_info().into_diagnostic()?.unwrap().to_bytes()
    );
    let root = wrapper_package.entrypoint_source_node().unwrap();
    let pushes = debug[root]
        .asm_ops
        .iter()
        .filter(|op| debug[op.op_name_idx].as_ref() == "push.42");
    let mut count = 0;
    for op in pushes {
        let calls = debug.inline_calls_for_operation(root, op.op_idx).collect::<Vec<_>>();
        let names = calls
            .iter()
            .map(|row| debug[debug.get_function(row.callee_idx).unwrap().name_idx].to_string())
            .collect::<Vec<_>>();
        assert!(names[0].ends_with("::leaf"));
        assert!(names[1].ends_with("::wrapper"));
        assert_eq!(names.len(), 2);
        let inner_location = debug.get_location(calls[0].loc_idx).unwrap();
        let outer_location = debug.get_location(calls[1].loc_idx).unwrap();
        let inner_start = source.find("exec.leaf").unwrap() as u32;
        let outer_start = source.match_indices("exec.wrapper").nth(count).unwrap().0 as u32;
        assert_eq!(inner_location.start.to_u32(), inner_start);
        assert_eq!(inner_location.end.to_u32(), inner_start + "exec.leaf".len() as u32);
        assert_eq!(outer_location.start.to_u32(), outer_start);
        assert_eq!(outer_location.end.to_u32(), outer_start + "exec.wrapper".len() as u32);
        assert_eq!(outer_location.uri, Uri::new("memory://reproducer.masm"));
        for row in calls {
            let function = debug.get_function(row.callee_idx).unwrap();
            let canonical = function.source_node.into_option().unwrap();
            assert_ne!(canonical, root);
            assert_eq!(
                wrapper_package.mast_forest()[debug[canonical].exec_node].digest(),
                function.mast_root
            );
            assert!(debug.get_location(row.loc_idx).is_some());
        }
        count += 1;
    }
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn plain_exec_preserves_imported_alias_identity() -> TestResult {
    use miden_core::serde::{Deserializable, Serializable};

    let context = TestContext::default();
    let library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        "namespace dep::math\n@source_name(\"same\")\npub proc leaf() -> felt\n push.42\nend\n@source_name(\"same\")\npub proc wrapper() -> felt\n exec.leaf\nend",
        None::<String>,
    )?;
    let library = Arc::new(Package::read_from_bytes(&library.to_bytes()).into_diagnostic()?);
    for (linkage, tail) in
        [(Linkage::Static, ""), (Linkage::Static, "drop"), (Linkage::Dynamic, "drop")]
    {
        let package = Assembler::new(context.source_manager())
            .with_package(Arc::clone(&library), linkage)?
            .assemble_program(
                "test",
                if tail.is_empty() { "use dep::math\nproc caller exec.math::wrapper end\nbegin call.caller end".to_string() }
                else { format!("use dep::math\nbegin exec.math::wrapper {tail} exec.math::wrapper {tail} end") },
            )?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let mut names = Vec::new();
        for source in reachable_source_nodes(&debug, root) {
            for row in &debug[source].inline_calls {
                let function = debug.get_function(row.callee_idx).unwrap();
                let name = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
                names.push(debug[name].to_string());
                assert_ne!(function.mast_root, Word::default());
                assert!(
                    function.type_idx.into_option().is_some(),
                    "exec must reference the typed declaration"
                );
                if linkage == Linkage::Static && tail.is_empty() {
                    let definition = function
                        .source_node
                        .into_option()
                        .expect("linked alias must retain its definition");
                    assert_ne!(definition, root);
                    assert_eq!(
                        package.mast_forest()[debug[definition].exec_node].digest(),
                        function.mast_root
                    );
                } else {
                    assert_eq!(
                        function.source_node.into_option(),
                        None,
                        "a pruned or dynamic definition must not be attributed to the invocation copy"
                    );
                }
            }
        }
        assert!(names.iter().any(|name| name.ends_with("::wrapper")));
        if linkage == Linkage::Static {
            assert!(names.iter().any(|name| name.ends_with("::leaf")));
        }
    }
    Ok(())
}

#[test]
fn plain_exec_preserves_reexported_function_identity() -> TestResult {
    use miden_core::serde::{Deserializable, Serializable};

    let context = TestContext::default();
    let root =
        context.parse_module("namespace root\npub use {foo as bar, other as baz} from dep")?;
    let dep = context.parse_module(
        "namespace dep\n@source_name(\"same\")\npub proc foo() -> felt\n push.42\nend\n@source_name(\"same\")\npub proc other() -> felt\n push.42\nend",
    )?;
    let library = Assembler::new(context.source_manager()).assemble_library("dep", root, [dep])?;
    let library = Arc::new(Package::read_from_bytes(&library.to_bytes()).into_diagnostic()?);
    let library_debug = library.debug_info().into_diagnostic()?.unwrap();
    let expected = ["::dep::foo", "::dep::other"];
    assert_eq!(library_debug.functions()[0].mast_root, library_debug.functions()[1].mast_root);

    for (linkage, tail) in
        [(Linkage::Static, ""), (Linkage::Static, "drop"), (Linkage::Dynamic, "drop")]
    {
        let package = Assembler::new(context.source_manager())
            .with_package(Arc::clone(&library), linkage)?
            .assemble_program(
                "test",
                if tail.is_empty() {
                    "use root\nproc first exec.root::bar end\nproc second exec.root::baz end\nbegin call.first call.second end"
                        .to_string()
                } else {
                    format!("use root\nbegin exec.root::bar {tail} exec.root::baz {tail} end")
                },
            )?;
        let package = Package::read_from_bytes(&package.to_bytes()).into_diagnostic()?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let calls = reachable_source_nodes(&debug, root)
            .iter()
            .flat_map(|source| debug[*source].inline_calls.iter())
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2, "re-exported exec calls must retain invocation rows");
        assert_ne!(calls[0].callee_idx, calls[1].callee_idx);
        let mut names = Vec::new();
        for call in calls {
            let function = debug.get_function(call.callee_idx).unwrap();
            names.push(debug[function.linkage_name_idx.into_option().unwrap()].to_string());
            assert!(function.type_idx.into_option().is_some());
            if linkage == Linkage::Static && tail.is_empty() {
                let definition = function.source_node.into_option().unwrap();
                assert_ne!(definition, root);
                assert_eq!(
                    package.mast_forest()[debug[definition].exec_node].digest(),
                    function.mast_root
                );
            } else {
                assert_eq!(function.source_node.into_option(), None);
            }
            assert!(debug.get_location(call.loc_idx).is_some());
        }
        names.sort();
        assert_eq!(names, expected);
    }
    Ok(())
}

#[test]
fn plain_exec_prefers_named_function_with_shared_provenance() -> TestResult {
    use miden_core::serde::Serializable;
    use miden_mast_package::{SectionId, debug_info::PackageDebugInfoBuilder};

    let context = TestContext::default();
    let mut library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        "namespace dep\npub proc foo push.42 end",
        None::<String>,
    )?;
    let mut debug =
        PackageDebugInfoBuilder::from(Box::new(library.debug_info().into_diagnostic()?.unwrap()));
    let mut alias = debug.debug_info().functions()[0];
    alias.name_idx = debug.add_string("::dep::alias");
    debug.add_function(alias);
    library
        .sections
        .iter_mut()
        .find(|section| section.id == SectionId::DEBUG_INFO)
        .unwrap()
        .data = debug.build().to_bytes().into();
    let library: Arc<Package> = Arc::from(library);

    for linkage in [Linkage::Static, Linkage::Dynamic] {
        let package = Assembler::new(context.source_manager())
            .with_package(Arc::clone(&library), linkage)?
            .assemble_program("test", "use dep\nbegin exec.dep::foo drop end")?;
        let debug = package.debug_info().into_diagnostic()?.unwrap();
        let root = package.entrypoint_source_node().unwrap();
        let calls = reachable_source_nodes(&debug, root)
            .iter()
            .flat_map(|source| debug[*source].inline_calls.iter())
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 1, "named exec must retain its invocation row under {linkage:?}");
        let function = debug.get_function(calls[0].callee_idx).unwrap();
        assert_eq!(debug[function.name_idx].as_ref(), "::dep::foo");
    }
    Ok(())
}

#[test]
fn linking_does_not_invent_definitions_for_source_less_functions() -> TestResult {
    let context = TestContext::default();
    let dependency = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        "namespace dep::math\npub proc leaf push.42 end\npub proc wrapper exec.leaf end",
        None::<String>,
    )?;
    let bridge = Assembler::new(context.source_manager())
        .with_package(Arc::from(dependency), Linkage::Dynamic)?
        .assemble_library(
            "bridge",
            "namespace bridge::math\nuse dep::math\npub proc wrapper exec.math::wrapper end",
            None::<String>,
        )?;
    let package = Assembler::new(context.source_manager())
        .with_package(Arc::from(bridge), Linkage::Static)?
        .assemble_program("test", "use bridge::math\nbegin exec.math::wrapper end")?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let dependency_functions = debug
        .functions()
        .iter()
        .filter(|function| debug[function.name_idx].starts_with("::dep::math::"))
        .collect::<Vec<_>>();
    assert_eq!(dependency_functions.len(), 2);
    for function in dependency_functions {
        assert_eq!(function.source_node.into_option(), None);
    }
    let root = package.entrypoint_source_node().unwrap();
    let names = reachable_source_nodes(&debug, root)
        .iter()
        .flat_map(|source| debug[*source].inline_calls.iter())
        .map(|row| debug[debug.get_function(row.callee_idx).unwrap().name_idx].to_string())
        .collect::<Vec<_>>();
    assert_eq!(names, ["::dep::math::wrapper", "::bridge::math::wrapper"]);
    Ok(())
}

#[test]
fn exec_without_a_call_site_still_separates_definitions() -> TestResult {
    let context = TestContext::default();
    let mut module = context.parse_module(
        "namespace debug::missing\npub proc leaf push.42 end\npub proc wrapper exec.leaf end",
    )?;
    for procedure in module.procedures_mut() {
        for op in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = op
                && matches!(instruction.inner(), Instruction::Exec(_))
            {
                *instruction = Span::new(SourceSpan::UNKNOWN, instruction.inner().clone());
            }
        }
    }
    let package = Assembler::new(context.source_manager()).assemble_library(
        "test",
        module,
        None::<String>,
    )?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    let functions = debug.functions();
    assert_eq!(functions.len(), 2);
    assert_ne!(functions[0].source_node, functions[1].source_node);
    assert_eq!(functions[0].mast_root, functions[1].mast_root);
    assert!(debug.nodes().iter().all(|node| node.inline_calls.is_empty()));
    Ok(())
}

#[test]
fn digest_only_exec_does_not_choose_an_ambiguous_alias() -> TestResult {
    let context = TestContext::default();
    let library = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        "namespace dep::math\npub proc leaf push.42 end\npub proc wrapper exec.leaf end",
        None::<String>,
    )?;
    let digest = library
        .manifest
        .exports()
        .find_map(|export| match export {
            PackageExport::Procedure(procedure) => Some(procedure.digest),
            _ => None,
        })
        .unwrap();
    let package = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Dynamic)?
        .assemble_program("test", format!("begin exec.{digest} end"))?;
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    assert!(debug.nodes().iter().all(|node| node.inline_calls.is_empty()));
    Ok(())
}
