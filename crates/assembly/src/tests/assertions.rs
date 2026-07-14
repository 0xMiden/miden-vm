// ASSERTIONS
// ================================================================================================

use super::*;

#[test]
fn assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert
        assert.err=ERR1
        assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assertz_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assertz
        assertz.err=ERR1
        assertz.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assert_eq_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eq
        assert_eq.err=ERR1
        assert_eq.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assert_eqw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eqw
        assert_eqw.err=ERR1
        assert_eqw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert
        u32assert.err=ERR1
        u32assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assert2_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert2
        u32assert2.err=ERR1
        u32assert2.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assertw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assertw
        u32assertw.err=ERR1
        u32assertw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

/// Ensure that assertion and `mtree_verify` error codes are preserved after assembly, including
/// through duplicate procedures with metadata-neutral MAST roots.
#[test]
fn asserts_and_mpverify_with_code_in_duplicate_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    proc f1
        u32assert.err=\"1\"
    end
    proc f2
        u32assert.err=\"2\"
    end
    proc f12
        u32assert.err=\"1\"
        u32assert.err=\"2\"
    end
    proc f21
        u32assert.err=\"2\"
        u32assert.err=\"1\"
    end
    proc g1
        assert.err=\"1\"
    end
    proc g2
        assert.err=\"2\"
    end
    proc g12
        assert.err=\"1\"
        assert.err=\"2\"
    end
    proc g21
        assert.err=\"2\"
        assert.err=\"1\"
    end
    proc fg
        assert.err=\"1\"
        u32assert.err=\"1\"
        assert.err=\"2\"
        u32assert.err=\"2\"

        u32assert.err=\"1\"
        assert.err=\"1\"
        u32assert.err=\"2\"
        assert.err=\"2\"
    end

    proc mpverify
        mtree_verify.err=\"1\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"1\"
    end

    begin
        exec.f1
        exec.f2
        exec.f12
        exec.f21
        exec.g1
        exec.g2
        exec.g12
        exec.g21
        exec.fg
        exec.mpverify
    end
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn dynamic_link_to_ambiguous_same_digest_export_is_rejected() -> TestResult {
    let context = TestContext::default();
    let library_module = parse_module!(
        &context,
        r#"
        namespace lib::a
        pub proc f1
            assert.err="1"
        end

        pub proc f2
            assert.err="2"
        end
        "#
    );
    let library = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        library_module,
        None::<Box<Module>>,
    )?;

    let f1 = QualifiedProcedureName::from_str("lib::a::f1").unwrap();
    let f2 = QualifiedProcedureName::from_str("lib::a::f2").unwrap();
    assert_eq!(library.get_procedure_root_by_path(&f1), library.get_procedure_root_by_path(&f2));
    assert_ne!(library.get_export_node_id(&f1), library.get_export_node_id(&f2));

    let source = source_file!(
        &context,
        "\
        use lib::a

        begin
            exec.a::f2
        end
        "
    );
    let err = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Dynamic)?
        .assemble_program("program", source)
        .expect_err("expected ambiguous dynamic link diagnostic");

    assert_diagnostic!(&err, "ambiguous dynamic procedure link for MAST root");
    assert_diagnostic!(
        &err,
        "dynamic reference cannot select one of the same-digest exported roots"
    );

    Ok(())
}

#[test]
fn mtree_verify_with_code() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const ERR1 = \"1\"

    begin
        mtree_verify
        mtree_verify.err=ERR1
        mtree_verify.err=\"2\"
    end
    "
    );

    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}
