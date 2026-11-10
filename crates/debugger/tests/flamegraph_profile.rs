use std::{process::Command, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager, SourceManager,
    ast::{DebugInlineCallInfo, Instruction, Module, ModuleKind, Op},
};
use miden_debug::{
    Executor, ReplaySnapshot,
    flamegraph::FlamegraphProfile,
    processor::{ExecutionOptions, StackInputs, advice::AdviceInputs},
};
use miden_debug_types::Span;

#[test]
fn flamegraph_profile_can_be_collected_from_debug_executor() {
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let source = r#"
begin
    push.1
    push.2
    add
    push.10
    mul
    swap
    drop
end
"#;

    let program = Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();
    let mut debug_executor = Executor::new(vec![]).into_debug(program.into(), source_manager);

    let profile =
        FlamegraphProfile::collect(&mut debug_executor).expect("program execution failed");

    assert!(debug_executor.stopped);
    assert!(profile.total_cycles() > 0);
    assert!(!profile.samples().is_empty());
    assert_eq!(profile.samples().values().sum::<usize>(), profile.total_cycles());
}

#[test]
fn flamegraph_profile_can_be_collected_from_replay_snapshot() {
    let profile =
        FlamegraphProfile::collect_replay(replay_snapshot()).expect("replay execution failed");

    assert!(profile.total_cycles() > 0);
    assert_eq!(profile.samples().values().sum::<usize>(), profile.total_cycles());
}

#[test]
fn flamegraph_profiles_recovered_callers_identically_during_execution_and_replay() {
    let manager = Arc::new(DefaultSourceManager::default());
    let package: Arc<miden_mast_package::Package> = Assembler::new(manager.clone())
        .assemble_program(
            "program",
            "proc inner push.7 drop end proc outer exec.inner push.8 drop end begin exec.outer \
             push.9 drop end",
        )
        .map(Arc::from)
        .unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.clone(), manager);
    let direct = FlamegraphProfile::collect(&mut executor).unwrap();
    let inner = "$exec::$main;[inferred] $exec::outer;[inferred] $exec::inner";
    assert!(
        direct.samples().get(inner).is_some_and(|cycles| *cycles >= 2),
        "{:?}",
        direct.samples()
    );
    assert_eq!(direct.total_cycles(), executor.cycle);

    let replay = FlamegraphProfile::collect_replay(ReplaySnapshot {
        package,
        stack_inputs: StackInputs::default(),
        advice_inputs: AdviceInputs::default(),
        options: ExecutionOptions::default(),
        mast_forests: Vec::new(),
        event_log: Vec::new(),
    })
    .unwrap();
    assert_eq!(replay.samples(), direct.samples());
    assert_eq!(replay.total_cycles(), direct.total_cycles());
}

#[test]
fn flamegraph_labels_source_inline_frames() {
    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Module::parser(Some(ModuleKind::Executable))
        .parse_str(None, "proc inner nop push.7 drop end begin call.inner end", manager.clone())
        .unwrap();
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                let span = instruction.span();
                let location = manager.file_line_col(span).unwrap();
                *instruction = Span::new(
                    span,
                    Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                        "source::inlined",
                        location.clone(),
                        location,
                    )),
                );
            }
        }
    }
    let package = Assembler::new(manager.clone()).assemble_program("program", module).unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.into(), manager);
    let profile = FlamegraphProfile::collect(&mut executor).unwrap();
    assert!(
        profile
            .samples()
            .get("$exec::$main;$exec::inner;[inlined] source::inlined")
            .is_some_and(|cycles| *cycles >= 2),
        "{:?}",
        profile.samples(),
    );
}

#[test]
fn flamegraph_does_not_duplicate_frames_when_events_and_source_are_present() {
    let manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "proc inner emit.event(\"{}\") push.7 drop emit.event(\"{}\") end proc outer \
         emit.event(\"{}\") exec.inner push.8 drop emit.event(\"{}\") end begin \
         emit.event(\"{}\") exec.outer push.9 drop emit.event(\"{}\") end",
        miden_debug::exec::event::FRAME_START_EVENT,
        miden_debug::exec::event::FRAME_END_EVENT,
        miden_debug::exec::event::FRAME_START_EVENT,
        miden_debug::exec::event::FRAME_END_EVENT,
        miden_debug::exec::event::FRAME_START_EVENT,
        miden_debug::exec::event::FRAME_END_EVENT,
    );
    let package = Assembler::new(manager.clone()).assemble_program("program", source).unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.into(), manager);
    let profile = FlamegraphProfile::collect(&mut executor).unwrap();
    let inner_paths = profile
        .samples()
        .iter()
        .filter(|(path, _)| path.contains("inner"))
        .collect::<Vec<_>>();
    assert_eq!(inner_paths.len(), 1, "{:?}", profile.samples());
    assert_eq!(inner_paths[0].0, "$exec::$main;[inferred] $exec::outer;[inferred] $exec::inner");
    assert!(*inner_paths[0].1 >= 2);
    assert_eq!(profile.samples().values().sum::<usize>(), executor.cycle);
}

#[test]
fn stripped_flamegraphs_preserve_cycle_accounting_with_unknown_frames() {
    let manager = Arc::new(DefaultSourceManager::default());
    let mut package = Assembler::new(manager.clone())
        .assemble_program("program", "proc inner push.7 drop end begin call.inner push.9 drop end")
        .unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.clone().into(), manager.clone());
    let with_source = FlamegraphProfile::collect(&mut executor).unwrap();
    package.strip_debug_info().unwrap();
    let mut stripped = Executor::new(vec![]).into_debug(package.into(), manager);
    let profile = FlamegraphProfile::collect(&mut stripped).unwrap();
    assert_eq!(profile.total_cycles(), with_source.total_cycles());
    assert_eq!(profile.total_cycles(), stripped.cycle);
    assert_eq!(profile.samples().values().sum::<usize>(), profile.total_cycles());
    assert_eq!(profile.samples().len(), 1);
}

#[test]
fn flamegraph_retains_event_frames_for_stripped_callees_of_sourced_callers() {
    use miden_assembly::Linkage;
    use miden_debug::exec::event::{FRAME_END_EVENT, FRAME_START_EVENT};

    let manager = Arc::new(DefaultSourceManager::default());
    let mut library = Assembler::new(manager.clone())
        .assemble_library(
            "dep",
            format!(
                "namespace dep::math pub proc target emit.event(\"{FRAME_START_EVENT}\") push.7 \
                 drop push.6 drop emit.event(\"{FRAME_END_EVENT}\") end"
            ),
            None::<String>,
        )
        .unwrap();
    library.strip_debug_info().unwrap();
    let library: Arc<miden_mast_package::Package> = library.into();
    let package = Assembler::new(manager.clone())
        .with_package(library.clone(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", "use dep::math begin exec.math::target push.9 drop end")
        .unwrap();
    let mut executor = Executor::new(vec![]);
    executor.with_package(library).unwrap();
    let mut executor = executor.into_debug(package.into(), manager);
    let profile = FlamegraphProfile::collect(&mut executor).unwrap();
    assert!(
        profile
            .samples()
            .get("$exec::$main;<unknown>")
            .is_some_and(|cycles| *cycles >= 4),
        "{:?}",
        profile.samples(),
    );
    assert_eq!(profile.samples().values().sum::<usize>(), executor.cycle);
}

#[test]
fn flamegraph_cli_accepts_replay_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot_path = temp.path().join("program.mdsnap");
    let flamegraph_path = temp.path().join("program.svg");
    replay_snapshot().write_to_file(&snapshot_path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_miden-debug"))
        .args([
            "flamegraph",
            "--replay",
            snapshot_path.to_str().unwrap(),
            "--output",
            flamegraph_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(flamegraph_path.is_file());
}

fn replay_snapshot() -> ReplaySnapshot {
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program("program", "begin push.1 push.2 add swap drop end")
        .map(Arc::from)
        .unwrap();
    ReplaySnapshot {
        package,
        stack_inputs: StackInputs::default(),
        advice_inputs: AdviceInputs::default(),
        options: ExecutionOptions::default(),
        mast_forests: Vec::new(),
        event_log: Vec::new(),
    }
}
