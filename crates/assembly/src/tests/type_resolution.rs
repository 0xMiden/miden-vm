// TYPE RESOLUTION
// ================================================================================================

use super::*;

#[test]
fn variadic_procedure_signatures_resolve() -> TestResult {
    use miden_assembly_syntax::ast::types::Type;
    use miden_mast_package::PackageExport;

    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::variadic

        pub proc log(prefix: felt, ...)
            nop
        end
        "#
    ))?;

    let package = context.assemble_library("lib", None, module, [])?;

    let signature = package
        .manifest
        .exports()
        .find_map(|export| match export {
            PackageExport::Procedure(proc) if proc.path.to_string().ends_with("log") => {
                proc.signature.clone()
            },
            _ => None,
        })
        .expect("log should be exported with a signature");

    assert_eq!(signature.params(), &[Type::Felt, Type::Variadic]);
    Ok(())
}

#[test]
fn self_recursive_struct_through_a_pointer_resolves() -> TestResult {
    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::list

        pub type Node = struct { value: u32, next: ptr<Node, addrspace(byte)> }

        pub proc entry(head: ptr<Node, addrspace(byte)>)
            nop
        end
        "#
    ))?;

    let package = context
        .assemble_library("lib", None, module, [])
        .expect("a struct recursing through a pointer should resolve");

    use miden_mast_package::PackageExport;

    let node = package
        .manifest
        .exports()
        .find_map(|export| match export {
            PackageExport::Type(ty) if ty.path.to_string().ends_with("Node") => Some(ty.ty.clone()),
            _ => None,
        })
        .expect("Node should be exported");

    // The declaration is recursive, and descending through the backedge comes back to it.
    let miden_assembly_syntax::ast::types::Type::Struct(node_ref) = &node else {
        panic!("expected a struct, got {node:?}");
    };
    assert!(node_ref.is_recursive());
    assert_eq!(node.size_in_bytes(), 8);

    let body = node_ref.get();
    let miden_assembly_syntax::ast::types::Type::Ptr(next) = &body.fields()[1].ty else {
        panic!("expected `next` to be a pointer");
    };
    assert_eq!(next.pointee(), &node);
    Ok(())
}

#[test]
fn a_recursive_type_survives_a_full_package_round_trip() -> TestResult {
    use miden_mast_package::{Package, PackageExport};

    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::tree

        pub type Node = struct { value: u32, next: ptr<Node, addrspace(byte)> }

        pub proc entry(head: ptr<Node, addrspace(byte)>)
            nop
        end
        "#
    ))?;

    let package = context.assemble_library("lib", None, module, [])?;

    let mut bytes = Vec::new();
    package.write_into(&mut bytes);
    let decoded = Package::read_from_bytes(&bytes).expect("package should decode");

    let find = |package: &Package| {
        package
            .manifest
            .exports()
            .find_map(|export| match export {
                PackageExport::Type(ty) if ty.path.to_string().ends_with("Node") => {
                    Some(ty.ty.clone())
                },
                _ => None,
            })
            .expect("Node should be exported")
    };

    let original = find(&package);
    let recovered = find(&decoded);

    // The whole stack agrees: what assembly resolved, the wire format encoded, and decoding
    // rebuilt are the same type, backedge and all.
    assert_eq!(recovered, original);

    let miden_assembly_syntax::ast::types::Type::Struct(node_ref) = &recovered else {
        panic!("expected a struct");
    };
    assert!(node_ref.is_recursive());
    let body = node_ref.get();
    let miden_assembly_syntax::ast::types::Type::Ptr(next) = &body.fields()[1].ty else {
        panic!("expected a pointer");
    };
    assert_eq!(next.pointee(), &recovered);
    Ok(())
}

#[test]
fn mutually_recursive_structs_through_pointers_resolve() -> TestResult {
    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::graph

        pub type A = struct { b: ptr<B, addrspace(byte)> }
        pub type B = struct { a: ptr<A, addrspace(byte)> }

        pub proc entry(node: ptr<A, addrspace(byte)>)
            nop
        end
        "#
    ))?;

    let package = context
        .assemble_library("lib", None, module, [])
        .expect("mutually recursive structs should resolve");

    use miden_mast_package::PackageExport;

    let find = |suffix: &str| {
        package
            .manifest
            .exports()
            .find_map(|export| match export {
                PackageExport::Type(ty) if ty.path.to_string().ends_with(suffix) => {
                    Some(ty.ty.clone())
                },
                _ => None,
            })
            .unwrap_or_else(|| panic!("{suffix} should be exported"))
    };
    let a = find("A");
    let b = find("B");

    // A -> b -> B -> a must come back around to A.
    let miden_assembly_syntax::ast::types::Type::Struct(a_ref) = &a else {
        panic!("expected a struct");
    };
    let a_body = a_ref.get();
    let miden_assembly_syntax::ast::types::Type::Ptr(to_b) = &a_body.fields()[0].ty else {
        panic!("expected a pointer");
    };
    assert_eq!(to_b.pointee(), &b);

    let miden_assembly_syntax::ast::types::Type::Struct(b_ref) = &b else {
        panic!("expected a struct");
    };
    let b_body = b_ref.get();
    let miden_assembly_syntax::ast::types::Type::Ptr(to_a) = &b_body.fields()[0].ty else {
        panic!("expected a pointer");
    };
    assert_eq!(to_a.pointee(), &a);
    Ok(())
}

#[test]
fn directly_self_referential_type_alias_is_diagnosed() -> TestResult {
    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::selfref

        pub type A = struct { inner: A }

        pub proc entry(value: A)
            nop
        end
        "#
    ))?;

    let err = context
        .assemble_library("lib", None, module, [])
        .expect_err("a self-referential type should be rejected");
    assert_diagnostic!(&err, "recursive");
    Ok(())
}

#[test]
fn a_finite_cycle_through_an_alias_resolves() -> TestResult {
    // `A` is an alias, not an aggregate, so it cannot itself carry the recursion. The cycle is
    // still finite, because it passes through `B`, whose field goes via a pointer. Declaration
    // order must not matter.
    for decls in [
        "pub type B = struct { a: A }
        pub type A = ptr<B, addrspace(byte)>",
        "pub type A = ptr<B, addrspace(byte)>
        pub type B = struct { a: A }",
    ] {
        let src = alloc::format!(
            "
        namespace lib::ord
        {decls}
        pub proc entry(x: A)
                         nop
        end
"
        );
        let context = TestContext::new();
        let module = context.parse_module(source_file!(&context, src))?;
        let package = context
            .assemble_library("lib", None, module, [])
            .expect("a finite cycle through an alias should resolve");

        use miden_mast_package::PackageExport;
        let b = package
            .manifest
            .exports()
            .find_map(|export| match export {
                PackageExport::Type(ty) if ty.path.to_string().ends_with("B") => {
                    Some(ty.ty.clone())
                },
                _ => None,
            })
            .expect("B should be exported");
        assert_eq!(b.size_in_bytes(), 4);
    }
    Ok(())
}

#[test]
fn an_alias_used_twice_in_one_aggregate_resolves() -> TestResult {
    // Both fields go through the same alias, and the pointer guards the cycle in each. Re-opening
    // the alias once per resolution is too coarse: the second field is not a new cycle.
    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::twice

        pub type A = ptr<B, addrspace(byte)>
        pub type B = struct { first: A, second: A }

        pub proc entry(x: A)
            nop
        end
        "#
    ))?;

    let package = context
        .assemble_library("lib", None, module, [])
        .expect("an alias used twice should resolve");

    use miden_mast_package::PackageExport;
    let b = package
        .manifest
        .exports()
        .find_map(|export| match export {
            PackageExport::Type(ty) if ty.path.to_string().ends_with("B") => Some(ty.ty.clone()),
            _ => None,
        })
        .expect("B should be exported");
    assert_eq!(b.size_in_bytes(), 8);
    Ok(())
}

#[test]
fn recursive_type_alias_cycle_is_diagnosed() -> TestResult {
    let context = TestContext::new();
    let module = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::cyc

        pub type A = B
        pub type B = A

        pub proc entry(value: A)
            nop
        end
        "#
    ))?;

    let err = context
        .assemble_library("lib", None, module, [])
        .expect_err("an alias cycle should be rejected rather than recursing forever");
    assert_diagnostic!(&err, "recursive");
    Ok(())
}
