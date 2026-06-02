use alloc::vec::Vec;
use std::sync::{Arc, LazyLock};

use miden_core::serde::{Deserializable, Serializable};
use miden_mast_package::{Dependency, Package, PackageId, PackageManifest, TargetType, Version};
use proptest::{
    prelude::*,
    test_runner::{Config, TestRunner},
};

use crate::{
    Assembler,
    testing::{TestContext, parse_module},
};

// PACKAGE SERIALIZATION AND DESERIALIZATION
// ================================================================================================

prop_compose! {
    fn any_package()(name in ".*", artifact in any::<ArbitraryMastArtifact>(), manifest in any::<PackageManifest>()) -> Package {
        let ArbitraryMastArtifact { ty, package } = artifact;

        // Ensure the manifest reflects exports of the actual MAST artifact.
        let exports = package.manifest.exports().cloned().collect::<Vec<_>>();
        let mut dependencies = Vec::<Dependency>::new();
        for dependency in manifest.dependencies() {
            if dependencies.iter().any(|existing| existing.id() == dependency.id()) {
                continue;
            }
            dependencies.push(dependency.clone());
        }

        let name = PackageId::from(name);
        let version = Version::new(0, 0, 0);
        Package::create(
            name,
            version,
            ty,
            Arc::clone(package.mast_forest()),
            exports,
            dependencies,
        )
        .expect("test package should be valid")
    }
}

#[derive(Debug, Clone)]
struct ArbitraryMastArtifact {
    ty: TargetType,
    package: Arc<Package>,
}

impl ArbitraryMastArtifact {
    fn library(package: Arc<Package>) -> Self {
        Self { ty: TargetType::Library, package }
    }

    fn executable(package: Arc<Package>) -> Self {
        Self { ty: TargetType::Executable, package }
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

static LIB_EXAMPLE: LazyLock<Arc<Package>> = LazyLock::new(build_library_example);
static PRG_EXAMPLE: LazyLock<Arc<Package>> = LazyLock::new(build_program_example);

fn build_library_example() -> Arc<Package> {
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
    let package = Assembler::new(context.source_manager())
        .assemble_library("test", modules.iter().cloned())
        .expect("failed to assemble library");
    Arc::from(package)
}

fn build_program_example() -> Arc<Package> {
    let source = "
    begin
        push.1.2
        add
        drop
    end
    ";

    let package = Assembler::default()
        .assemble_program("test", source)
        .expect("failed to assemble executable");
    Arc::from(package)
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
