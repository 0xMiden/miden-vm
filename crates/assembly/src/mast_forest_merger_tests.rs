use miden_core::{
    Idx,
    mast::{MastForest, MastForestRootMap, MastNodeExt},
};

use crate::{
    Assembler,
    diagnostics::{IntoDiagnostic, Report},
    testing::TestContext,
};

#[allow(clippy::type_complexity)]
fn merge_programs(
    program_a: &str,
    program_b: &str,
) -> Result<(MastForest, MastForest, MastForest, MastForestRootMap), Report> {
    let context = TestContext::new();
    let module = context.parse_module_with_path("lib::mod".parse().unwrap(), program_a)?;

    let lib_a = Assembler::new(context.source_manager()).assemble_library([module])?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.link_dynamic_library(lib_a.clone())?;
    let lib_b = assembler.assemble_library([program_b])?.mast_forest().as_ref().clone();
    let lib_a = lib_a.mast_forest().as_ref().clone();

    let (merged, root_maps) = MastForest::merge([&lib_a, &lib_b]).into_diagnostic()?;

    Ok((lib_a, lib_b, merged, root_maps))
}

/// Tests that an assembler-produced library's forests can be merged and that external nodes are
/// replaced by their referenced procedures.
#[test]
fn mast_forest_merge_assembler() {
    let lib_a = r#"
  pub proc foo
      push.19
  end

  pub proc qux
      swap drop
  end
"#;

    let lib_b = r#"
  use lib::mod

  pub proc qux_duplicate
      swap drop
  end

  pub proc bar
      push.2
      if.true
          push.3
      else
          while.true
              add
              push.23
          end
      end
      exec.mod::foo
  end"#;

    let (forest_a, forest_b, merged, root_maps) = merge_programs(lib_a, lib_b).unwrap();

    for (forest_idx, forest) in [forest_a, forest_b].into_iter().enumerate() {
        for root in forest.procedure_roots() {
            let original_digest = forest.nodes()[root.to_usize()].digest();
            let new_root = root_maps.map_root(forest_idx, root).unwrap();
            let new_digest = merged.nodes()[new_root.to_usize()].digest();
            assert_eq!(original_digest, new_digest);
        }
    }

    // Assert that the external node for the import was removed during merging.
    merged.nodes().iter().for_each(|node| assert!(!node.is_external()));
}
