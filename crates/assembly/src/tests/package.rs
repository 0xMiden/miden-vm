use alloc::vec::Vec;
use std::sync::{Arc, LazyLock};

use miden_assembly_syntax::{Version, library::LibraryExport};
use miden_core::{
    mast::MastNodeExt,
    serde::{Deserializable, Serializable},
};
use miden_mast_package::{
    ConstantExport, Package, PackageExport, PackageId, PackageManifest, ProcedureExport,
    TargetType, TypeExport,
};
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};

use crate::{
    Assembler, Library, Parse, ParseOptions, Path,
    ast::ModuleKind,
    testing::{TestContext, parse_module},
};

// PACKAGE SERIALIZATION AND DESERIALIZATION
// ================================================================================================

prop_compose! {
    fn any_package()(name in ".*", artifact in any::<ArbitraryMastArtifact>(), manifest in any::<PackageManifest>()) -> Package {
        let ArbitraryMastArtifact { ty, lib } = artifact;

        // Ensure the manifest reflects exports of the actual MAST artifact.
        let mut exports = Vec::default();
        for export in lib.exports() {
            match export {
                LibraryExport::Procedure(export) => {
                    let digest = lib.mast_forest()[export.node].digest();
                    exports.push(PackageExport::Procedure(ProcedureExport {
                        path: export.path.clone(),
                        digest,
                        signature: export.signature.clone(),
                        attributes: export.attributes.clone(),
                    }));
                },
                LibraryExport::Constant(export) => {
                    exports.push(PackageExport::Constant(ConstantExport {
                        path: export.path.clone(),
                        value: export.value.clone(),
                    }));
                },
                LibraryExport::Type(export) => {
                    exports.push(PackageExport::Type(TypeExport {
                        path: export.path.clone(),
                        ty: export.ty.clone(),
                    }));
                },
            }
        }

        let manifest = PackageManifest::new(exports)
            .and_then(|package_manifest| {
                package_manifest.with_dependencies(manifest.dependencies().cloned())
            })
            .expect("test package manifest should be valid");

        let name = PackageId::from(name);
        let version = Version::new(0, 0, 0);
        Package { name, version, description: None, kind: ty, mast: lib, manifest, sections: Default::default() }
    }
}

#[derive(Debug, Clone)]
struct ArbitraryMastArtifact {
    ty: TargetType,
    lib: Arc<Library>,
}

impl ArbitraryMastArtifact {
    fn library(lib: Arc<Library>) -> Self {
        Self { ty: TargetType::Library, lib }
    }

    fn executable(lib: Arc<Library>) -> Self {
        Self { ty: TargetType::Executable, lib }
    }
}

impl Arbitrary for ArbitraryMastArtifact {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(Self::library(LIB_EXAMPLE.clone())),
            Just(Self::executable(PRG_EXAMPLE.clone()))
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

static LIB_EXAMPLE: LazyLock<Arc<Library>> = LazyLock::new(build_library_example);
static PRG_EXAMPLE: LazyLock<Arc<Library>> = LazyLock::new(build_program_example);

fn build_library_example() -> Arc<Library> {
    let context = TestContext::new();
    // declare foo module
    let foo_src = r#"
        pub proc foo(a: felt, b: felt) -> felt
            add
        end
        pub proc foo_mul(a: felt, b: felt) -> felt
            mul
        end
    "#;
    let foo_module = parse_module!(&context, "test::foo", foo_src);

    // declare bar module
    let bar_src = r#"
        pub proc bar
            mtree_get
        end
        pub proc bar_mul
            mul
        end
    "#;
    let bar_module = parse_module!(&context, "test::bar", bar_src);
    let modules = [foo_module, bar_module];

    // serialize/deserialize the bundle with locations
    Assembler::new(context.source_manager())
        .assemble_library(modules.iter().cloned())
        .expect("failed to assemble library")
}

fn build_program_example() -> Arc<Library> {
    let source = "
    begin
        push.1.2
        add
        drop
    end
    ";
    let assembler = Assembler::default();

    let options = ParseOptions {
        kind: ModuleKind::Executable,
        warnings_as_errors: assembler.warnings_as_errors(),
        path: Some(Path::exec_path().into()),
    };

    let program = source.parse_with_options(assembler.source_manager(), options).unwrap();
    assembler.assemble_executable_modules(program, []).unwrap().into_artifact()
}

#[test]
fn package_serialization_roundtrip() {
    // since the test is quite expensive, 128 cases should be enough to cover all edge cases
    // (default is 256)
    let cases = 128;
    TestRunner::new(Config::with_cases(cases))
        .run(&any_package(), move |package| {
            let bytes = package.to_bytes();
            let deserialized = Package::read_from_bytes(&bytes).unwrap();
            prop_assert_eq!(package, deserialized);
            Ok(())
        })
        .unwrap_or_else(|err| {
            panic!("{err}");
        });
}
