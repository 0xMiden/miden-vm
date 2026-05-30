use super::*;

impl Package {
    pub fn generate(
        name: PackageId,
        version: Version,
        kind: TargetType,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Box<Self> {
        use proptest::prelude::*;

        let params = ArbitraryPackageParams {
            name,
            version,
            kind,
            dependencies: Vec::from_iter(dependencies),
        };

        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let value_tree =
            <Package as Arbitrary>::arbitrary_with(params).new_tree(&mut runner).unwrap();
        Box::new(value_tree.current())
    }
}

#[doc(hidden)]
pub struct ArbitraryPackageParams {
    pub name: PackageId,
    pub version: Version,
    pub kind: TargetType,
    pub dependencies: Vec<Dependency>,
}

impl Default for ArbitraryPackageParams {
    fn default() -> Self {
        Self {
            name: PackageId::from("noname"),
            version: Version::new(0, 0, 0),
            kind: TargetType::Library,
            dependencies: vec![],
        }
    }
}

impl proptest::arbitrary::Arbitrary for Package {
    type Parameters = ArbitraryPackageParams;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use alloc::vec;

        use miden_core::{
            mast::{BasicBlockNodeBuilder, MastForestContributor, MastNodeExt},
            operations::Operation,
        };
        use proptest::prelude::*;

        let ArbitraryPackageParams { name, version, kind, dependencies } = params;

        // Packages must have at least one procedure export, so we generate one of those
        // unconditionally, and then generate an arbitrary number of other exports to fill out
        // the package with random items
        (any::<ProcedureExport>(), prop::collection::vec(any::<PackageExport>(), 0..5))
            .prop_map(move |(proc, extra_exports)| {
                let mut exports = vec![PackageExport::Procedure(proc)];
                for export in extra_exports {
                    // Ignore duplicate exports
                    if exports.iter().any(|existing| existing.path() == export.path()) {
                        continue;
                    }
                    exports.push(export);
                }

                // Create a MastForest with actual nodes for the exports
                let mut mast_forest = Box::new(MastForest::new());
                let mut nodes = Vec::with_capacity(exports.len());
                for export in exports.iter_mut() {
                    if let PackageExport::Procedure(export) = export {
                        let node_id =
                            BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
                                .add_to_forest(&mut mast_forest)
                                .unwrap();
                        // Add the node to the forest roots if it's not already there
                        mast_forest.make_root(node_id);
                        nodes.push(node_id);
                        export.node = Some(node_id);
                        export.digest = mast_forest[node_id].digest();
                    }
                }

                // Generate an entrypoint export if needed
                if kind.is_executable() {
                    let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
                        .add_to_forest(&mut mast_forest)
                        .unwrap();
                    // Add the node to the forest roots if it's not already there
                    mast_forest.make_root(node_id);
                    nodes.push(node_id);
                    let path: Arc<Path> =
                        Path::EXEC.join(ast::ProcedureName::MAIN_PROC_NAME).into();
                    exports.push(PackageExport::Procedure(ProcedureExport::new(
                        path,
                        Some(node_id),
                        mast_forest[node_id].digest(),
                        None,
                    )));
                }

                let mast_forest = Arc::from(mast_forest);
                Package::create(
                    name.clone(),
                    version.clone(),
                    kind,
                    mast_forest,
                    exports,
                    dependencies.clone(),
                )
                .expect("invalid package")
            })
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
