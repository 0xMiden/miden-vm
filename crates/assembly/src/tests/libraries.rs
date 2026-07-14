// LIBRARIES
// ================================================================================================

use super::*;

#[test]
fn library_exports() -> Result<(), Report> {
    let context = TestContext::new();

    // build the first library
    let baz = r#"
        namespace lib1::baz

        pub proc baz1
            push.7 push.8 sub
        end
    "#;
    let baz = parse_module!(&context, baz);

    let lib1 = Assembler::new(context.source_manager()).assemble_library(
        "lib1",
        baz,
        None::<Box<Module>>,
    )?;

    // build the second library
    let foo = r#"
        namespace lib2::foo
        proc foo1
            push.1 add
        end

        pub proc foo2
            push.2 add
            exec.foo1
        end

        pub proc foo3
            push.3 mul
            exec.foo1
            exec.foo2
        end
    "#;
    let foo = parse_module!(&context, foo);

    // declare root module
    let root = r#"
        namespace lib2

        pub mod foo

        pub use {baz1 as bar1} from lib1::baz

        pub use {foo2 as bar2} from self::foo

        pub proc bar3
            exec.foo::foo2
        end

        proc bar4
            push.1 push.2 mul
        end

        pub proc bar5
            push.3 sub
            exec.foo::foo2
            exec.bar1
            exec.bar2
            exec.bar4
        end
    "#;
    let root = parse_module!(&context, root);

    let lib2 = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib1), Linkage::Dynamic)?
        .assemble_library("lib2", root, [foo])?;

    let foo2 = Path::new("::lib2::foo::foo2");
    let foo3 = Path::new("::lib2::foo::foo3");
    let bar1 = Path::new("::lib2::bar1");
    let bar2 = Path::new("::lib2::bar2");
    let bar3 = Path::new("::lib2::bar3");
    let bar5 = Path::new("::lib2::bar5");

    // make sure the library exports all exported procedures
    let expected_exports: BTreeSet<Arc<Path>> =
        [foo2.into(), foo3.into(), bar1.into(), bar2.into(), bar3.into(), bar5.into()].into();
    let actual_exports: BTreeSet<_> = lib2.manifest.exports().map(PackageExport::path).collect();
    assert_eq!(expected_exports, actual_exports);

    // make sure foo2, bar2, and bar3 map to the same MastNode
    assert_eq!(lib2.get_export_node_id(foo2), lib2.get_export_node_id(bar2));
    assert_eq!(lib2.get_export_node_id(foo2), lib2.get_export_node_id(bar3));
    assert_all_nodes_reachable_from_roots(lib2.mast_forest());

    // make sure there are 6 roots in the MAST (foo1, foo2, foo3, bar1, bar4, and bar5)
    assert_eq!(lib2.mast_forest().num_procedures(), 6);

    // bar1 should be the only re-export (i.e. the only procedure re-exported from a dependency)
    assert!(!lib2.is_reexport(foo2));
    assert!(!lib2.is_reexport(foo3));
    assert!(lib2.is_reexport(bar1));
    assert!(!lib2.is_reexport(bar2));
    assert!(!lib2.is_reexport(bar3));
    assert!(!lib2.is_reexport(bar5));

    Ok(())
}

#[test]
#[ignore = "disabled until #3040 is resolved"]
fn library_procedure_collision() -> Result<(), Report> {
    let context = TestContext::new();

    // build the first library
    let foo = r#"
        namespace lib1::foo
        pub proc foo1
            push.1
            if.true
                push.1 push.2 add
            else
                push.1 push.2 mul
            end
        end
    "#;
    let foo = parse_module!(&context, foo);
    let lib1 = Assembler::new(context.source_manager()).assemble_library(
        "lib1",
        foo,
        None::<Box<Module>>,
    )?;

    // build the second library which defines the same procedure as the first one
    let bar = r#"
        namespace lib2::bar

        pub use {foo1 as bar1} from lib1::foo

        pub proc bar2
            push.1
            if.true
                push.1 push.2 add
            else
                push.1 push.2 mul
            end
        end
    "#;
    let bar = parse_module!(&context, bar);
    let lib2 = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib1), Linkage::Dynamic)?
        .assemble_library("lib2", bar, None::<Box<Module>>)?;

    // make sure lib2 has the expected exports (i.e., bar1 and bar2)
    assert_eq!(lib2.manifest.num_exports(), 2);

    // The re-exported procedure and the locally defined procedure have the same MAST shape, so
    // they share the same node.
    let lib2_bar_bar1 = QualifiedProcedureName::from_str("lib2::bar::bar1").unwrap();
    let lib2_bar_bar2 = QualifiedProcedureName::from_str("lib2::bar::bar2").unwrap();
    let export_id_bar1 = lib2.get_export_node_id(&lib2_bar_bar1);
    assert!(lib2.mast_forest()[export_id_bar1].is_external());
    let export_id_bar2 = lib2.get_export_node_id(&lib2_bar_bar2);
    assert!(!lib2.mast_forest()[export_id_bar2].is_external());
    assert_ne!(export_id_bar1, export_id_bar2);

    // Keeping those procedures distinct adds one more node to the library forest.
    assert_eq!(lib2.mast_forest().num_nodes(), 6);

    Ok(())
}

#[test]
fn get_module_by_path() {
    let context = TestContext::new();
    // declare foo module
    let foo_source = r#"
        namespace test::foo
        pub proc foo
            add
        end
    "#;
    let foo = parse_module!(&context, foo_source);

    // create the bundle with locations
    let bundle = Assembler::new(context.source_manager())
        .assemble_library("test", foo, None::<Box<Module>>)
        .unwrap();

    let foo_module_descriptor = bundle.module_descriptors().next().unwrap();
    assert_eq!(foo_module_descriptor.path(), &PathBuf::new("::test::foo").unwrap());

    let (_, foo_proc) = foo_module_descriptor.procedures().next().unwrap();
    assert_eq!(foo_proc.name, ProcedureName::new("foo").unwrap());
}

#[test]
fn get_proc_digest_by_name() -> Result<(), Report> {
    let context = TestContext::new();

    let testing_module_source = "
        namespace test::names
        pub proc foo
            push.1.2 add drop
        end

        pub proc bar
            push.5.6 sub drop
        end
    ";
    let testing_module = parse_module!(&context, testing_module_source);

    // create the bundle with locations
    let package = Assembler::new(context.source_manager())
        .assemble_library("test", testing_module, None::<Box<Module>>)
        .context("failed to assemble library from testing module")?;

    // get the vector of library procedure digests
    let library_procedure_digests = package
        .manifest
        .exports()
        .filter_map(|export| match export {
            PackageExport::Procedure(export) => Some(export.digest),
            _ => None,
        })
        .collect::<Vec<Word>>();

    // valid procedure names
    assert!(
        library_procedure_digests.contains(
            &package
                .get_procedure_root_by_path("test::names::foo")
                .expect("procedure with name 'foo' must exist in the test library")
        )
    );
    assert!(
        library_procedure_digests.contains(
            &package
                .get_procedure_root_by_path("test::names::bar")
                .expect("procedure with name 'bar' must exist in the test library")
        )
    );

    // invalid procedure name
    assert_eq!(None, package.get_procedure_root_by_path("test::names::baz"));

    // invalid namespace
    assert_eq!(None, package.get_procedure_root_by_path("invalid::namespace::foo"));

    Ok(())
}
