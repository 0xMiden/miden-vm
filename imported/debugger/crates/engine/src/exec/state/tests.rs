use alloc::string::{String, ToString};
use std::sync::Arc;

use miden_assembly::DefaultSourceManager;
use miden_mast_package::Package;

use super::*;
use crate::exec::Executor;

#[test]
fn callstack_tracks_nested_frame_events() {
    use crate::event::{FRAME_END_EVENT, FRAME_START_EVENT};
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program(
            "program",
            format!(
                r#"
proc inner
    emit.event("{FRAME_START_EVENT}")
    nop
    emit.event("{FRAME_END_EVENT}")
end

proc outer
    emit.event("{FRAME_START_EVENT}")
    exec.inner
    emit.event("{FRAME_END_EVENT}")
end

begin
    emit.event("{FRAME_START_EVENT}")
    exec.outer
    emit.event("{FRAME_END_EVENT}")
end
"#
            ),
        )
        .map(Arc::<Package>::from)
        .unwrap();

    let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(program, source_manager);
    let mut max_depth = 0;
    let mut saw_inner = false;
    let mut snapshots = Vec::new();

    for _ in 0..64 {
        executor.step().unwrap();
        let frames = executor.callstack.frames();
        max_depth = max_depth.max(frames.len());
        snapshots.push(
            frames
                .iter()
                .map(|frame| {
                    frame
                        .procedure("")
                        .map(|name| name.to_string())
                        .unwrap_or_else(|| "<unknown>".to_string())
                })
                .collect::<Vec<_>>(),
        );
        saw_inner |= frames.len() >= 3
            && frames
                .last()
                .and_then(|frame| frame.procedure(""))
                .is_some_and(|name| name.contains("inner"));

        if saw_inner || executor.stopped {
            break;
        }
    }

    assert!(
        max_depth >= 3,
        "expected nested main -> outer -> inner frames, max depth was {max_depth}"
    );
    assert!(
        saw_inner,
        "expected innermost frame to resolve to inner; snapshots: {snapshots:?}"
    );
}

#[test]
fn recovered_backtrace_preserves_exec_callers_without_duplicate_inline_frames() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program(
            "program",
            "proc inner push.7 drop end proc outer exec.inner push.8 drop end begin exec.outer \
             push.9 drop end",
        )
        .map(Arc::<Package>::from)
        .unwrap();
    let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(package, source_manager);
    let mut inner_cycles = 0;
    while !executor.stopped {
        executor.step().unwrap();
        if executor
            .current_asmop
            .as_ref()
            .is_some_and(|op| op.context_name().ends_with("::inner"))
        {
            let frames = executor.callstack.logical_frames("");
            let names = frames.iter().map(|frame| frame.name()).collect::<Vec<_>>();
            assert_eq!(names, ["$exec::$main", "$exec::outer", "$exec::inner"]);
            assert!(frames[1].display_name().starts_with("[inferred] "));
            assert!(frames[2].display_name().starts_with("[inferred] "));
            inner_cycles += 1;
        }
    }
    assert!(inner_cycles >= 2);
}

#[test]
fn recovered_backtrace_handles_calls_dynamic_recursion_and_returns() {
    for source in [
        "proc inner push.7 drop end begin call.inner call.inner push.9 drop end",
        "proc inner dup neq.0 if.true sub.1 push.100 dynexec else nop end end begin procref.inner \
         mem_storew_le.100 dropw push.3 push.100 dynexec drop push.9 drop end",
    ] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let package = miden_assembly::Assembler::new(source_manager.clone())
            .assemble_program("program", source)
            .map(Arc::<Package>::from)
            .unwrap();
        let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(package, source_manager);
        let mut max_depth = 0;
        while !executor.stopped {
            executor.step().unwrap();
            let frames = executor.callstack.logical_frames("");
            max_depth = max_depth.max(frames.len());
            if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.9") {
                assert_eq!(frames.len(), 1, "returned callers must not remain live");
                assert_eq!(frames[0].name(), "$exec::$main");
            }
        }
        assert_eq!(max_depth, if source.contains("dynexec") { 5 } else { 2 });
    }
}

#[test]
fn recovered_backtrace_does_not_duplicate_explicit_event_frames() {
    use crate::event::{FRAME_END_EVENT, FRAME_START_EVENT};
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "proc inner emit.event(\"{FRAME_START_EVENT}\") push.7 drop \
         emit.event(\"{FRAME_END_EVENT}\") end begin emit.event(\"{FRAME_START_EVENT}\") \
         exec.inner emit.event(\"{FRAME_END_EVENT}\") end"
    );
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .map(Arc::<Package>::from)
        .unwrap();
    let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(package, source_manager);
    let mut seen = false;
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
            let frames = executor.callstack.logical_frames("");
            assert_eq!(
                frames.iter().map(|frame| frame.name()).collect::<Vec<_>>(),
                ["$exec::$main", "$exec::inner"]
            );
            assert!(
                executor.callstack.frames().len() >= 2,
                "physical event stack remains available"
            );
            seen = true;
        }
    }
    assert!(seen);
}

#[test]
fn stripped_package_loads_and_executes_without_recovered_frames() {
    use miden_core::serde::Serializable;
    use miden_debug_types::Uri;
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", "begin push.7 add end")
        .unwrap();
    package.strip_debug_info().unwrap();
    let package =
        crate::package::read_package_from_bytes(&package.to_bytes(), &Uri::new("stripped.masp"))
            .unwrap();
    let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(package, source_manager);
    while !executor.stopped {
        executor.step().unwrap();
    }
    assert_eq!(executor.stack_outputs.as_ref()[0], Felt::from_u32(7));
}

#[test]
fn finish_returns_from_uninstrumented_invocations() {
    for invocation in ["exec.inner", "call.inner", "push.100 dynexec"] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let package = miden_assembly::Assembler::new(source_manager.clone())
            .assemble_program(
                "program",
                format!(
                    "proc inner push.7 drop push.6 drop end proc outer {invocation} push.8 drop \
                     end begin procref.inner mem_storew_le.100 dropw exec.outer push.9 drop end"
                ),
            )
            .unwrap();
        let mut executor = Executor::new(vec![]).into_debug(package.into(), source_manager.clone());
        while !executor.stopped {
            executor.step().unwrap();
            if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
                break;
            }
        }
        assert!(!executor.stopped);
        let before = executor.cycle;
        executor.step_until(BreakpointType::Finish, source_manager.as_ref()).unwrap();
        assert!(!executor.stopped, "finish must stop in outer after {invocation}");
        assert!(executor.cycle > before + 1);
        assert!(executor.current_asmop.as_ref().unwrap().context_name().ends_with("::outer"));
        assert_eq!(executor.callstack.logical_frames("").len(), 2);
    }
}

#[test]
fn finish_unwinds_one_recursive_activation_at_a_time() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program(
            "program",
            "proc inner dup neq.0 if.true sub.1 push.100 dynexec else push.7 drop end push.8 drop \
             end begin procref.inner mem_storew_le.100 dropw push.3 push.100 dynexec drop push.9 \
             drop end",
        )
        .unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.into(), source_manager.clone());
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
            break;
        }
    }
    assert_eq!(executor.callstack.logical_frames("").len(), 5);
    for depth in (1..5).rev() {
        executor.step_until(BreakpointType::Finish, source_manager.as_ref()).unwrap();
        assert!(!executor.stopped);
        assert_eq!(executor.callstack.logical_frames("").len(), depth);
    }
    executor.step_until(BreakpointType::Finish, source_manager.as_ref()).unwrap();
    assert!(executor.stopped, "finishing the root must run to completion");
}

#[test]
fn finish_uses_frame_events_when_metadata_is_stripped() {
    use crate::event::{FRAME_END_EVENT, FRAME_START_EVENT};
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "proc inner emit.event(\"{FRAME_START_EVENT}\") push.7 drop push.6 drop \
         emit.event(\"{FRAME_END_EVENT}\") end begin emit.event(\"{FRAME_START_EVENT}\") \
         exec.inner push.9 drop emit.event(\"{FRAME_END_EVENT}\") end"
    );
    let mut package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();
    package.strip_debug_info().unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.into(), source_manager.clone());
    // The fallback includes a synthetic root, followed by the explicit main and inner frames.
    while executor.callstack.frames().len() < 3 && !executor.stopped {
        executor.step().unwrap();
    }
    assert!(!executor.stopped);
    assert!(executor.current_asmop.is_none());
    let before = executor.cycle;
    executor.step_until(BreakpointType::Finish, source_manager.as_ref()).unwrap();
    assert!(!executor.stopped);
    assert!(executor.cycle > before + 1);
    assert_eq!(executor.callstack.frames().len(), 2);
}

#[test]
fn finish_waits_through_nested_calls_and_control_flow() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program(
            "program",
            "proc leaf push.4 drop end proc inner push.7 drop push.1 if.true exec.leaf push.6 \
             drop else nop end repeat.2 push.5 drop end end proc outer exec.inner push.8 drop end \
             begin exec.outer push.9 drop end",
        )
        .unwrap();
    let mut executor = Executor::new(vec![]).into_debug(package.into(), source_manager.clone());
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
            break;
        }
    }
    executor.step_until(BreakpointType::Finish, source_manager.as_ref()).unwrap();
    assert!(!executor.stopped);
    assert!(executor.current_asmop.as_ref().unwrap().context_name().ends_with("::outer"));
    assert_eq!(executor.current_asmop.as_ref().unwrap().op().as_ref(), "push.8");
}

#[test]
fn finish_returns_across_a_dynamic_package_boundary() {
    use miden_assembly::Linkage;
    let manager = Arc::new(DefaultSourceManager::default());
    let library: Arc<Package> = miden_assembly::Assembler::new(manager.clone())
        .assemble_library(
            "dep",
            "namespace dep::math pub proc target push.7 drop push.6 drop end",
            None::<String>,
        )
        .unwrap()
        .into();
    let package = miden_assembly::Assembler::new(manager.clone())
        .with_package(library.clone(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", "use dep::math begin exec.math::target push.9 drop end")
        .unwrap();
    let mut executor = Executor::new(vec![]);
    executor.with_package(library).unwrap();
    let mut executor = executor.into_debug(package.into(), manager.clone());
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
            break;
        }
    }
    assert!(!executor.stopped, "must observe the library invocation");
    executor.step_until(BreakpointType::Finish, manager.as_ref()).unwrap();
    assert!(!executor.stopped);
    assert_eq!(executor.callstack.logical_frames("").len(), 1);
    assert_eq!(executor.current_asmop.as_ref().unwrap().op().as_ref(), "push.9");
}

#[test]
fn finish_uses_callee_events_when_only_the_caller_has_metadata() {
    use miden_assembly::Linkage;

    use crate::event::{FRAME_END_EVENT, FRAME_START_EVENT};
    let manager = Arc::new(DefaultSourceManager::default());
    let mut library = miden_assembly::Assembler::new(manager.clone())
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
    let library: Arc<Package> = library.into();
    let package = miden_assembly::Assembler::new(manager.clone())
        .with_package(library.clone(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", "use dep::math begin exec.math::target push.9 drop end")
        .unwrap();
    let mut executor = Executor::new(vec![]);
    executor.with_package(library).unwrap();
    let mut executor = executor.into_debug(package.into(), manager.clone());
    while executor.callstack.frames().len() < 2 && !executor.stopped {
        executor.step().unwrap();
    }
    assert!(!executor.stopped);
    assert!(executor.current_asmop.is_none());
    assert!(!executor.callstack.has_recovered_current_frame());
    let frames = executor.callstack.logical_frames("");
    assert_eq!(frames.len(), 2, "the stripped callee must remain visible");
    assert_eq!(frames[1].physical_index(), Some(1));
    executor.step_until(BreakpointType::Finish, manager.as_ref()).unwrap();
    assert!(!executor.stopped, "must finish the stripped callee, not its recovered caller");
    assert_eq!(executor.callstack.frames().len(), 1);
}

#[test]
fn caller_locals_survive_callee_name_collision_and_kill() {
    use miden_assembly_syntax::{
        Parse,
        ast::{DebugVarInfo, Instruction, Op},
        debuginfo::{SourceSpan, Span},
    };
    for invocation in ["exec.inner", "call.inner", "push.100 dynexec"] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let mut module = Parse::parse(
            format!(
                "proc inner push.7 nop drop nop push.2 drop end begin procref.inner \
                 mem_storew_le.100 dropw push.42 nop drop {invocation} push.9 drop end"
            ),
            false,
            source_manager.clone(),
        )
        .unwrap();
        for procedure in module.procedures_mut() {
            let mut declaration = true;
            for operation in procedure.body_mut().iter_mut() {
                if let Op::Inst(instruction) = operation
                    && matches!(instruction.inner(), Instruction::Nop)
                {
                    *instruction = Span::new(
                        SourceSpan::default(),
                        Instruction::DebugVar(DebugVarInfo::new(
                            "x",
                            if declaration {
                                DebugVarLocation::Stack(0)
                            } else {
                                DebugVarLocation::Unavailable
                            },
                        )),
                    );
                    declaration = false;
                }
            }
        }
        let package = miden_assembly::Assembler::new(source_manager.clone())
            .assemble_program("program", module)
            .map(Arc::<Package>::from)
            .unwrap();
        let mut executor = Executor::new(Vec::<Felt>::new()).into_debug(package, source_manager);
        let mut returned = false;
        while !executor.stopped {
            executor.step().unwrap();
            if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.9") {
                assert_eq!(
                    executor.debug_vars.get_variable("x").map(|var| var.info.value_location()),
                    Some(&DebugVarLocation::Const(Felt::from_u32(42))),
                    "{invocation}: caller's declaration must survive a callee kill"
                );
                returned = true;
            }
        }
        assert!(returned);
    }
}

fn executor_with_debug_declarations(
    source: &str,
    declarations: impl Fn(bool, usize) -> miden_assembly_syntax::ast::DebugVarInfo,
) -> DebugExecutor {
    let (package, manager) = package_with_debug_declarations(source, declarations);
    Executor::new(Vec::<Felt>::new()).into_debug(package, manager)
}

fn package_with_debug_declarations(
    source: &str,
    declarations: impl Fn(bool, usize) -> miden_assembly_syntax::ast::DebugVarInfo,
) -> (Arc<Package>, Arc<DefaultSourceManager>) {
    use miden_assembly_syntax::{
        Parse,
        ast::{Instruction, Op},
        debuginfo::{SourceSpan, Span},
    };
    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(source, false, manager.clone()).unwrap();
    for procedure in module.procedures_mut() {
        let entry = procedure.is_entrypoint();
        let mut index = 0;
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                *instruction = Span::new(
                    SourceSpan::default(),
                    Instruction::DebugVar(declarations(entry, index)),
                );
                index += 1;
            }
        }
    }
    let package = miden_assembly::Assembler::new(manager.clone())
        .assemble_program("program", module)
        .map(Arc::<Package>::from)
        .unwrap();
    (package, manager)
}

#[test]
fn recursive_locals_belong_to_distinct_invocations_and_retire_on_return() {
    use miden_assembly_syntax::ast::DebugVarInfo;
    let mut executor = executor_with_debug_declarations(
        "proc inner nop dup neq.0 if.true sub.1 push.100 dynexec else push.1 drop end push.8 drop \
         end begin procref.inner mem_storew_le.100 dropw push.99 nop drop push.3 push.100 dynexec \
         drop push.9 drop push.1 push.100 dynexec drop end",
        |_, _| DebugVarInfo::new("x", DebugVarLocation::Stack(0)),
    );
    let mut deepest = Vec::new();
    let mut returned = false;
    let mut identities = alloc::collections::BTreeSet::new();
    while !executor.stopped {
        executor.step().unwrap();
        let frames = executor.callstack.logical_frames("");
        let ids = frames.iter().filter_map(|frame| frame.invocation_id()).collect::<Vec<_>>();
        identities.extend(ids.iter().copied());
        let values = ids
            .iter()
            .filter_map(|id| {
                executor
                    .debug_vars
                    .resolve(*id, "x", executor.processor())
                    .and_then(|var| var.raw)
            })
            .collect::<Vec<_>>();
        if values.len() > deepest.len() {
            deepest = values;
        }
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.9") {
            assert_eq!(ids.len(), 1);
            for old in identities.iter().filter(|id| !ids.contains(id)) {
                assert!(!executor.debug_vars.has_invocation(*old));
            }
            assert_eq!(
                executor.debug_vars.resolve(ids[0], "x", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(99))
            );
            returned = true;
        }
    }
    assert_eq!(deepest, [99, 3, 2, 1, 0].map(Felt::from_u32));
    assert!(returned);
    assert_eq!(identities.len(), 7, "repeated calls receive fresh invocation identities");
    assert!(!executor.debug_vars.has_variables());
    assert!(identities.iter().all(|id| !executor.debug_vars.has_invocation(*id)));
}

#[test]
fn suspended_locals_use_their_own_context_and_post_prologue_frame_pointer() {
    use miden_assembly_syntax::ast::DebugVarInfo;
    for invocation in ["exec.inner", "call.inner", "push.100 dynexec"] {
        let mut executor = executor_with_debug_declarations(
            &format!(
                "@locals(4) proc inner push.7 loc_store.0 nop push.5 drop end @locals(4) proc \
                 outer push.42 loc_store.0 nop push.3 drop {invocation} push.9 drop end begin \
                 procref.inner mem_storew_le.100 dropw exec.outer end"
            ),
            |_, _| DebugVarInfo::new("x", DebugVarLocation::Local(-4)),
        );
        let mut saw_inner = false;
        while !executor.stopped {
            executor.step().unwrap();
            if executor.current_asmop.as_ref().is_some_and(|op| {
                op.context_name().ends_with("::inner") && op.op().as_ref() == "push.5"
            }) {
                let frames = executor.callstack.logical_frames("");
                let outer = frames
                    .iter()
                    .find(|frame| {
                        frame.name().ends_with("::outer") && frame.invocation_id().is_some()
                    })
                    .and_then(|frame| frame.invocation_id())
                    .unwrap_or_else(|| panic!("{invocation}: {frames:?}"));
                let inner = frames
                    .iter()
                    .find(|frame| {
                        frame.name().ends_with("::inner") && frame.invocation_id().is_some()
                    })
                    .and_then(|frame| frame.invocation_id())
                    .unwrap_or_else(|| panic!("{invocation}: {frames:?}"));
                assert_eq!(
                    executor.debug_vars.resolve(outer, "x", executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(42)),
                    "{invocation}: caller FMP/context"
                );
                assert_eq!(
                    executor.debug_vars.resolve(inner, "x", executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(7)),
                    "{invocation}: callee FMP/context"
                );
                saw_inner = true;
            }
        }
        assert!(saw_inner);
    }
}

#[test]
fn frame_base_anchors_refresh_while_active_and_freeze_while_suspended() {
    use miden_assembly_syntax::ast::{
        DebugFrameBase, DebugLocationExpression, DebugLocationExpressionOp, DebugVarInfo,
    };
    let mut executor = executor_with_debug_declarations(
        "proc inner push.1600 mem_store.50 push.99 mem_store.300 push.7 mem_store.400 push.5 drop \
         end begin push.42 mem_store.200 push.88 mem_store.300 push.800 mem_store.50 nop nop nop \
         push.1200 mem_store.50 exec.inner push.9 drop end",
        |_, index| {
            DebugVarInfo::new(
                match index {
                    0 => "framed",
                    1 => "expression",
                    _ => "live",
                },
                match index {
                    0 => DebugVarLocation::ResolvedFrameBase {
                        base: DebugFrameBase::Memory(50),
                        byte_offset: 0,
                    },
                    1 => DebugVarLocation::Expression(
                        DebugLocationExpression::new(vec![
                            DebugLocationExpressionOp::FrameBaseAddress {
                                base: DebugFrameBase::Memory(50),
                                byte_offset: 0,
                            },
                            DebugLocationExpressionOp::DerefBytes,
                        ])
                        .unwrap(),
                    ),
                    _ => DebugVarLocation::Memory(300),
                },
            )
        },
    );
    let mut active_update = false;
    let mut suspended = false;
    while !executor.stopped {
        executor.step().unwrap();
        let Some(caller) = executor
            .callstack
            .logical_frames("")
            .first()
            .and_then(|frame| frame.invocation_id())
        else {
            continue;
        };
        let op = executor.current_asmop.as_ref();
        if op.is_some_and(|op| {
            op.op().as_ref() == "mem_store.50" && op.context_name().ends_with("::$main")
        }) && executor.current_op == Some(Operation::MStore)
            && executor.debug_vars.get_variable("framed").is_some()
        {
            assert_eq!(
                executor.debug_vars.resolve(caller, "framed", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(88))
            );
            active_update = true;
        }
        if op.is_some_and(|op| op.op().as_ref() == "push.5") {
            for name in ["framed", "expression", "live"] {
                assert_eq!(
                    executor.debug_vars.resolve(caller, name, executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(99)),
                    "{name}: frozen base with live storage"
                );
            }
            suspended = true;
        }
    }
    assert!(active_update && suspended);
}

#[test]
fn invocation_local_values_and_ownership_match_during_replay() {
    use miden_assembly_syntax::ast::DebugVarInfo;
    let (package, manager) = package_with_debug_declarations(
        "proc inner push.7 nop drop push.5 drop end begin push.42 nop drop call.inner push.9 drop \
         end",
        |_, _| DebugVarInfo::new("x", DebugVarLocation::Stack(0)),
    );
    let mut direct = Executor::new(vec![]).into_debug(package.clone(), manager.clone());
    let mut replay =
        Executor::new(vec![]).into_debug_with_replay(package, manager, vec![], Default::default());
    fn inspect(executor: &DebugExecutor) -> Vec<(String, Option<Felt>)> {
        executor
            .callstack
            .logical_frames("")
            .iter()
            .filter_map(|frame| {
                let id = frame.invocation_id()?;
                Some((
                    frame.name().to_string(),
                    executor
                        .debug_vars
                        .resolve(id, "x", executor.processor())
                        .and_then(|variable| variable.raw),
                ))
            })
            .collect()
    }
    let mut nested = false;
    while !direct.stopped {
        direct.step().unwrap();
        replay.step().unwrap();
        let actual = inspect(&direct);
        assert_eq!(actual, inspect(&replay));
        nested |= actual
            .iter()
            .map(|(_, value)| *value)
            .eq([Some(Felt::from_u32(42)), Some(Felt::from_u32(7))]);
    }
    assert!(nested && replay.stopped);
}

#[test]
fn unavailable_transient_values_remain_distinct_from_explicit_kills() {
    use miden_assembly_syntax::ast::DebugVarInfo;
    let mut executor = executor_with_debug_declarations(
        "begin nop push.7 drop nop push.9 drop end",
        |_, index| {
            DebugVarInfo::new(
                "x",
                if index == 0 {
                    DebugVarLocation::Stack(u8::MAX)
                } else {
                    DebugVarLocation::Unavailable
                },
            )
        },
    );
    let mut unavailable = false;
    let mut killed = false;
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.7") {
            let current = executor.debug_vars.current_invocation().unwrap();
            let value = executor
                .debug_vars
                .resolve(current, "x", executor.processor())
                .expect("unreadable declarations remain visible");
            assert!(value.raw.is_none());
            assert_eq!(value.value, "<unavailable>");
            unavailable = true;
        }
        if executor.current_asmop.as_ref().is_some_and(|op| op.op().as_ref() == "push.9") {
            assert!(executor.debug_vars.get_variable("x").is_none());
            killed = true;
        }
    }
    assert!(unavailable && killed);
}

fn executor_with_linked_package_locals(invocation: &str, stripped: bool) -> DebugExecutor {
    use miden_assembly::Linkage;
    use miden_assembly_syntax::{
        ast::{DebugVarInfo, Instruction, Module, ModuleKind, Op},
        debuginfo::Span,
    };

    use crate::event::{FRAME_END_EVENT, FRAME_START_EVENT};

    fn declare_locals(module: &mut Module) {
        for procedure in module.procedures_mut() {
            let mut declaration = 0;
            for operation in procedure.body_mut().iter_mut() {
                if let Op::Inst(instruction) = operation
                    && matches!(instruction.inner(), Instruction::Nop)
                {
                    let (name, location) = if declaration == 0 {
                        ("x", DebugVarLocation::Stack(0))
                    } else {
                        ("cell", DebugVarLocation::Memory(200))
                    };
                    *instruction = Span::new(
                        instruction.span(),
                        Instruction::DebugVar(DebugVarInfo::new(name, location)),
                    );
                    declaration += 1;
                }
            }
        }
    }

    let manager = Arc::new(DefaultSourceManager::default());
    let mut library_module = Module::parser(Some(ModuleKind::Library))
        .parse_str(
            None,
            format!(
                "namespace dep::math pub proc target emit.event(\"{FRAME_START_EVENT}\") push.7 \
                 nop drop push.17 mem_store.200 nop push.6 drop emit.event(\"{FRAME_END_EVENT}\") \
                 end"
            ),
            manager.clone(),
        )
        .unwrap();
    declare_locals(&mut library_module);
    let mut library = miden_assembly::Assembler::new(manager.clone())
        .assemble_library("dep", library_module, None::<String>)
        .unwrap();
    if stripped {
        library.strip_debug_info().unwrap();
    }
    let library: Arc<Package> = library.into();
    let mut module = Module::parser(Some(ModuleKind::Executable))
        .parse_str(
            None,
            format!(
                "use dep::math begin procref.math::target mem_storew_le.100 dropw push.42 nop \
                 drop push.88 mem_store.200 nop push.3 drop {invocation} push.9 drop end"
            ),
            manager.clone(),
        )
        .unwrap();
    declare_locals(&mut module);
    let package = miden_assembly::Assembler::new(manager.clone())
        .with_package(library.clone(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", module)
        .unwrap();
    let mut executor = Executor::new(vec![]);
    executor.with_package(library).unwrap();
    executor.into_debug(package.into(), manager)
}

fn check_linked_package_locals(invocation: &str, stripped: bool) {
    let mut executor = executor_with_linked_package_locals(invocation, stripped);
    let mut caller_id = None;
    let mut callee_id = None;
    let mut suspended = false;
    let mut restored = false;
    let caller_cell = if invocation.starts_with("call.") || invocation.ends_with("dyncall") {
        88
    } else {
        // Exec shares the caller's memory context, and ordinary memory-backed locals remain live.
        17
    };
    while !executor.stopped {
        executor.step().unwrap();
        let current = executor.debug_vars.current_invocation();
        let operation = executor.current_asmop.as_ref();

        if operation.is_some_and(|op| op.context_name().ends_with("::$main"))
            && executor.debug_vars.get_variable("x").is_some()
        {
            caller_id.get_or_insert(current.unwrap());
        }
        let in_callee = if stripped {
            !executor.callstack.has_recovered_current_frame()
                && executor.callstack.frames().len() == 2
                && executor
                    .processor()
                    .memory()
                    .read_element(executor.processor().state().ctx(), Felt::from_u32(200))
                    .ok()
                    == Some(Felt::from_u32(17))
        } else {
            operation.is_some_and(|op| op.op().as_ref() == "push.6")
        };
        if in_callee {
            let caller = caller_id.expect("caller declarations must be observed before the call");
            assert_eq!(
                executor.debug_vars.resolve(caller, "x", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(42)),
                "{invocation}: caller's stack snapshot survives package entry"
            );
            assert_eq!(
                executor.debug_vars.resolve(caller, "cell", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(caller_cell)),
                "{invocation}: caller memory uses its own context"
            );
            if stripped {
                assert!(current.is_none(), "stripped callees cannot adopt the caller's identity");
                assert!(!executor.debug_vars.has_variables());
                assert!(
                    executor
                        .callstack
                        .logical_frames("")
                        .iter()
                        .all(|frame| frame.invocation_id().is_none()),
                    "event-only fallback frames cannot claim another invocation's locals"
                );
            } else {
                let callee = current.expect("sourceful library invocation");
                assert_ne!(caller, callee);
                callee_id = Some(callee);
                assert_eq!(
                    executor.debug_vars.resolve(callee, "x", executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(7))
                );
                assert_eq!(
                    executor.debug_vars.resolve(callee, "cell", executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(17))
                );
            }
            suspended = true;
        }
        if operation.is_some_and(|op| op.op().as_ref() == "push.9") {
            assert_eq!(current, caller_id, "return restores the original caller identity");
            let caller = current.unwrap();
            assert_eq!(
                executor.debug_vars.resolve(caller, "x", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(42))
            );
            assert_eq!(
                executor.debug_vars.resolve(caller, "cell", executor.processor()).unwrap().raw,
                Some(Felt::from_u32(caller_cell))
            );
            if let Some(callee) = callee_id {
                assert!(!executor.debug_vars.has_invocation(callee));
            }
            restored = true;
        }
    }
    assert!(
        suspended && restored,
        "{invocation}: must inspect both sides of the package return"
    );
    assert!(!executor.debug_vars.has_variables());
}

#[test]
fn linked_package_locals_keep_invocations_and_memory_contexts() {
    for invocation in
        ["exec.math::target", "call.math::target", "push.100 dynexec", "push.100 dyncall"]
    {
        check_linked_package_locals(invocation, false);
    }
}

#[test]
fn stripped_package_locals_do_not_borrow_the_callers_ownership() {
    for invocation in
        ["exec.math::target", "call.math::target", "push.100 dynexec", "push.100 dyncall"]
    {
        check_linked_package_locals(invocation, true);
    }
}

#[test]
fn caller_frame_base_includes_the_final_write_before_a_merged_exec() {
    use miden_assembly_syntax::ast::{DebugFrameBase, DebugVarInfo};

    // Different batch offsets ensure a padding operation cannot hide a missed refresh at the
    // caller/callee source boundary. A word store keeps its operands, so there is no trailing
    // caller Drop between the final frame-base write and the inlined exec body.
    for padding in 0..16 {
        let mut executor = executor_with_debug_declarations(
            &format!(
                "proc inner push.5 drop end begin push.42 mem_store.200 push.88 mem_store.300 \
                 push.800 mem_store.48 nop {} push.0.0.0.1200 mem_storew_le.48 exec.inner dropw \
                 end",
                "push.3 drop ".repeat(padding),
            ),
            |_, _| {
                DebugVarInfo::new(
                    "x",
                    DebugVarLocation::ResolvedFrameBase {
                        base: DebugFrameBase::Memory(48),
                        byte_offset: 0,
                    },
                )
            },
        );
        let mut suspended = false;
        while !executor.stopped {
            executor.step().unwrap();
            if executor.current_asmop.as_ref().is_some_and(|op| {
                op.context_name().ends_with("::inner") && op.op().as_ref() == "push.5"
            }) {
                let caller = executor.callstack.logical_frames("")[0].invocation_id().unwrap();
                assert_eq!(
                    executor
                        .processor()
                        .memory()
                        .read_element(executor.processor().state().ctx(), Felt::from_u32(48))
                        .unwrap(),
                    Felt::from_u32(1200),
                    "fixture must write the new frame-base address"
                );
                assert_eq!(
                    executor.debug_vars.resolve(caller, "x", executor.processor()).unwrap().raw,
                    Some(Felt::from_u32(88)),
                    "batch offset {padding}: suspended frame must include its final store"
                );
                suspended = true;
            }
        }
        assert!(suspended);
    }
}

#[test]
fn source_inlining_with_the_physical_procedure_name_is_preserved() {
    use miden_assembly_syntax::{
        Parse,
        ast::{DebugInlineCallInfo, Instruction, Op},
        debuginfo::{Span, Spanned},
    };

    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(
        "proc worker nop push.2 mul end begin push.5 exec.worker drop end",
        false,
        source_manager.clone(),
    )
    .unwrap();
    let procedure = module
        .procedures_mut()
        .find(|procedure| procedure.name().as_str() == "worker")
        .unwrap();
    let marker = procedure.body_mut().iter_mut().next().unwrap();
    let span = marker.span();
    let location = source_manager.file_line_col(span).unwrap();
    *marker = Op::Inst(Span::new(
        span,
        Instruction::DebugInlineCall(DebugInlineCallInfo::new(
            "::$exec::worker",
            location.clone(),
            location,
        )),
    ));
    let package = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("same-named-inline", module)
        .map(Arc::from)
        .unwrap();
    let mut executor = Executor::new(Vec::new()).into_debug(package, source_manager);
    let mut checked = false;
    while !executor.stopped {
        executor.step().unwrap();
        if executor.current_op != Some(miden_processor::operation::Operation::Mul) {
            continue;
        }
        let logical = executor.callstack.logical_frames("");
        let worker = logical
            .iter()
            .filter(|frame| frame.name().ends_with("::worker"))
            .collect::<Vec<_>>();
        assert_eq!(worker.len(), 2, "{logical:?}");
        assert_eq!(
            worker
                .iter()
                .filter(|frame| frame.kind() == crate::debug::LogicalFrameKind::Inline)
                .count(),
            1
        );
        checked = true;
    }
    assert!(checked);
}

/// An executor over a finished stepper, as a session that stands in for a remote execution
/// builds it, never steps: a step stops it and leaves the state it displays untouched, the
/// stack and the outputs included, even when `stopped` was not set.
#[test]
fn a_step_over_a_finished_stepper_changes_nothing() {
    use miden_processor::StackInputs;

    let source_manager: Arc<DefaultSourceManager> = Arc::new(DefaultSourceManager::default());
    let mut exec = DebugExecutor::new(
        Stepper::finished(FastProcessor::new(StackInputs::default())),
        DebuggerHost::new(source_manager),
        Arc::new(Default::default()),
        Profiler::default(),
    );
    let stack = vec![Felt::new(7).unwrap(), Felt::new(8).unwrap()];
    // Not the default, so that outputs captured from the untouched processor would show.
    let outputs = StackOutputs::new(&stack).unwrap();
    exec.current_stack = stack.clone();
    exec.stack_outputs = outputs;
    exec.cycle = 42;
    assert!(matches!(exec.step(), Ok(None)));
    assert!(exec.stopped);
    assert_eq!(exec.cycle, 42);
    assert_eq!(exec.current_stack, stack);
    assert_eq!(exec.stack_outputs, outputs);
}

/// An executor over a stepper that ran to its end starts its clock at the cycles that stepper
/// ran, not at zero: the constructor copies the stepper's clock.
#[test]
fn an_executor_over_a_finished_stepper_starts_at_its_clock() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", "begin push.1 push.2 add drop end")
        .map(Arc::<Package>::from)
        .unwrap();
    let (mut stepper, mut host) =
        Executor::new(Vec::new()).into_stepper(program, source_manager).unwrap();
    stepper.run_sync(&mut host, |_| {}).unwrap();
    let cycles = stepper.cycle();
    assert!(cycles > 0);
    let exec = DebugExecutor::new(stepper, host, Arc::new(Default::default()), Profiler::default());
    assert_eq!(exec.cycle, cycles);
}
