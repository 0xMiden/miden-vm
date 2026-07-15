// COMPILED LIBRARIES
// ================================================================================================

use super::*;

#[test]
fn test_compiled_library() {
    let context = TestContext::new();
    let root = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib

    pub mod mod1
    pub mod mod2
    "
            ))
            .unwrap()
    };
    let mod1 = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib::mod1

    proc internal
        push.5
    end
    pub proc foo
        push.1
        drop
    end
    pub proc bar
        exec.internal
        drop
    end
    "
            ))
            .unwrap()
    };

    let mod2 = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib::mod2

    pub proc foo
        push.7
        add.5
    end
    # Same definition as mod1::foo
    pub proc bar
        push.1
        drop
    end
    "
            ))
            .unwrap()
    };

    let compiled_library = {
        let assembler = Assembler::new(context.source_manager());
        assembler.assemble_library("mylib", root, [mod1, mod2]).unwrap()
    };

    assert_eq!(compiled_library.manifest.num_exports(), 4);

    // Compile program that uses compiled library
    let mut assembler = Assembler::new(context.source_manager());

    assembler.link_package(Arc::from(compiled_library), Linkage::Dynamic).unwrap();

    let program_source = "
    use mylib::mod1
    use mylib::mod2

    proc foo
        push.1
        drop
    end

    begin
        exec.mod1::foo
        exec.mod1::bar
        exec.mod2::foo
        exec.mod2::bar
        exec.foo
    end
    ";

    let _program = assembler.assemble_program("test", program_source).unwrap();
}

#[test]
fn test_reexported_proc_with_same_name_as_local_proc_diff_locals() {
    let context = TestContext::new();
    let root = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test

            pub mod mod1
            pub mod mod2
            "
            ))
            .unwrap()
    };
    let mod1 = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test::mod1

            @locals(8) pub proc foo
                push.1
                drop
            end
            "
            ))
            .unwrap()
    };

    let mod2 = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test::mod2

            use test::mod1
            pub proc foo
                exec.mod1::foo
            end
            "
            ))
            .unwrap()
    };

    let compiled_library = {
        let assembler = Assembler::new(context.source_manager());
        assembler.assemble_library("test", root, [mod1, mod2]).unwrap()
    };

    assert_eq!(compiled_library.manifest.num_exports(), 2);

    // Compile program that uses compiled library
    let mut assembler = Assembler::new(context.source_manager());

    assembler.link_package(Arc::from(compiled_library), Linkage::Dynamic).unwrap();

    let program_source = "
    use test::mod1
    use test::mod2

    @locals(4)
    proc foo
        exec.mod1::foo
        exec.mod2::foo
    end

    begin
        exec.foo
    end
    ";

    let _program = assembler.assemble_program("test", program_source).unwrap();
}
