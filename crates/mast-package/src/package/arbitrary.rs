use alloc::vec;

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
        use miden_core::{
            Felt,
            mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastNodeExt},
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
                let mut mast_forest_builder = DenseMastForestBuilder::new();
                let mut nodes = Vec::with_capacity(exports.len());
                for export in exports.iter_mut() {
                    if let PackageExport::Procedure(export) = export {
                        let procedure_index = nodes.len() as u64;
                        let node_id = mast_forest_builder
                            .push_node_builder(
                                BasicBlockNodeBuilder::new(vec![
                                    Operation::Push(Felt::new_unchecked(procedure_index)),
                                    Operation::Add,
                                    Operation::Mul,
                                ])
                                .into(),
                            )
                            .unwrap();
                        // Add the node to the forest roots if it's not already there
                        mast_forest_builder.mark_root(node_id);
                        nodes.push(node_id);
                        export.node = Some(node_id);
                        export.digest =
                            mast_forest_builder.get_node_by_id(node_id).unwrap().digest();
                    }
                }

                // Generate an entrypoint export if needed
                if kind.is_executable() {
                    let procedure_index = nodes.len() as u64;
                    let node_id = mast_forest_builder
                        .push_node_builder(
                            BasicBlockNodeBuilder::new(vec![
                                Operation::Push(Felt::new_unchecked(procedure_index)),
                                Operation::Add,
                                Operation::Mul,
                            ])
                            .into(),
                        )
                        .unwrap();
                    // Add the node to the forest roots if it's not already there
                    mast_forest_builder.mark_root(node_id);
                    nodes.push(node_id);
                    let path: Arc<Path> =
                        Path::EXEC.join(ast::ProcedureName::MAIN_PROC_NAME).into();
                    exports.push(PackageExport::Procedure(ProcedureExport::new(
                        path,
                        Some(node_id),
                        mast_forest_builder.get_node_by_id(node_id).unwrap().digest(),
                        None,
                    )));
                }

                let (mast_forest, id_remapping) = mast_forest_builder
                    .finish_with_id_map()
                    .expect("generated MAST forest should be valid");
                for export in exports.iter_mut() {
                    if let PackageExport::Procedure(export) = export
                        && let Some(builder_node_id) = export.node
                    {
                        let node_id = id_remapping
                            .get(builder_node_id)
                            .expect("procedure export should map to a finalized node");
                        export.node = Some(node_id);
                        export.digest = mast_forest[node_id].digest();
                    }
                }

                let mast_forest = Arc::new(mast_forest);
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
