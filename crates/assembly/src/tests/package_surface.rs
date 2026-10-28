// PACKAGE MODULE SURFACE
// ================================================================================================

use super::*;

#[test]
fn package_module_surface_allows_downstream_import_of_root_module() -> TestResult {
    let context = TestContext::new();
    let dep_root = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib

        pub mod api
        "#
    ))?;
    let dep_api = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::api

        pub proc foo
            push.1
        end
        "#
    ))?;

    let dep =
        Assembler::new(context.source_manager()).assemble_library("dep", dep_root, [dep_api])?;
    assert!(dep.manifest.get_module(Path::new("::pkg::lib")).is_some());
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::api")).is_some());

    let dep_bytes = dep.to_bytes();
    let dep = Arc::new(Package::read_from_bytes(&dep_bytes).map_err(Report::msg)?);
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace consumer

        use pkg::lib

        pub proc call
            exec.lib::api::foo
        end
        "#
    ))?;

    let package = Assembler::new(context.source_manager())
        .with_package(dep, Linkage::Static)?
        .assemble_library("consumer", consumer, None::<Box<Module>>)?;
    let exports = package.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert!(exports.contains(&Arc::from(Path::new("::consumer::call"))));

    Ok(())
}

#[test]
fn package_module_surface_omits_private_submodules() -> TestResult {
    let context = TestContext::new();
    let dep_root = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib

        pub mod api
        mod internal
        "#
    ))?;
    let dep_api = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::api

        use pkg::lib::internal

        pub proc foo
            exec.internal::hidden
        end
        "#
    ))?;
    let dep_internal = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::internal

        pub proc hidden
            push.1
        end
        "#
    ))?;

    let dep = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        dep_root,
        [dep_api, dep_internal],
    )?;
    let root_surface = dep
        .manifest
        .get_module(Path::new("::pkg::lib"))
        .expect("root surface should be present");
    let submodules = root_surface
        .submodules()
        .iter()
        .map(|submodule| submodule.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(submodules, vec!["api"]);
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::api")).is_some());
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::internal")).is_none());

    let dep = Arc::new(Package::read_from_bytes(&dep.to_bytes()).map_err(Report::msg)?);
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace consumer

        use pkg::lib

        pub proc call
            exec.lib::api::foo
        end
        "#
    ))?;

    Assembler::new(context.source_manager())
        .with_package(dep, Linkage::Static)?
        .assemble_library("consumer", consumer, None::<Box<Module>>)?;

    Ok(())
}

fn package_with_single_proc_export(
    context: &TestContext,
    export_path: &'static str,
    modules: impl IntoIterator<Item = PackageModule>,
) -> Result<Arc<Package>, Report> {
    let seed = context.parse_module(source_file!(
        context,
        r#"
        namespace seed

        pub proc foo
            push.1
        end
        "#
    ))?;
    let seed = Assembler::new(context.source_manager()).assemble_library(
        "seed",
        seed,
        None::<Box<Module>>,
    )?;
    let (node, digest) = seed
        .manifest
        .exports()
        .find_map(|export| export.as_procedure())
        .map(|export| (export.node, export.digest))
        .expect("seed package should export one procedure");
    let export = PackageExport::Procedure(ProcedureExport::new(
        Arc::from(Path::new(export_path)),
        node,
        digest,
        None,
    ));

    Package::create_with_modules(
        "dep".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(seed.mast_forest()),
        [export],
        modules,
        None,
    )
    .map(Arc::new)
    .map_err(Report::msg)
}

#[test]
fn package_link_rejects_missing_module_surface_metadata() -> TestResult {
    let context = TestContext::new();
    let dep = package_with_single_proc_export(&context, "::dep::foo", [])?;

    let err = match Assembler::new(context.source_manager()).with_package(dep, Linkage::Static) {
        Ok(_) => panic!("compiled packages without module surfaces should be rejected"),
        Err(err) => err,
    };

    assert_diagnostic!(&err, "invalid module surface metadata for package 'dep'");
    assert_diagnostic!(&err, "package manifest declares export '::dep::foo' in module '::dep'");
    assert_diagnostic!(&err, "no module surface was provided for that module");

    Ok(())
}

#[test]
fn package_link_rejects_incomplete_declared_submodule_surface_metadata() -> TestResult {
    let context = TestContext::new();
    let dep = package_with_single_proc_export(
        &context,
        "::dep::api::foo",
        [PackageModule::new(
            Arc::from(Path::new("::dep")),
            [PackageSubmodule::new(Ident::new("api").unwrap())],
        )],
    )?;

    let err = match Assembler::new(context.source_manager()).with_package(dep, Linkage::Static) {
        Ok(_) => panic!("compiled packages with incomplete module surfaces should be rejected"),
        Err(err) => err,
    };

    assert_diagnostic!(&err, "invalid module surface metadata for package 'dep'");
    assert_diagnostic!(
        &err,
        "package manifest declares submodule '::dep::api' from module '::dep'"
    );
    assert_diagnostic!(&err, "no module surface was provided for it");

    Ok(())
}
