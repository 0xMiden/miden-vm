use miden_assembly::{
    Assembler, DefaultSourceManager, Linkage,
    ast::{DebugInlineCallInfo, Instruction, Module, ModuleKind, Op},
};
use miden_debug_types::Span;
use miden_mast_package::Package;

use super::*;

fn run(
    package: Arc<Package>,
    source_manager: Arc<DefaultSourceManager>,
    libraries: &[Arc<Package>],
    mut check: impl FnMut(&AssemblyOp, &[LogicalStackFrame]),
) {
    let mut executor = crate::Executor::new(Vec::new());
    for library in libraries {
        executor.with_package(library.clone()).unwrap();
    }
    let mut executor = executor.into_debug(package, source_manager);
    while !executor.stopped {
        executor.step().unwrap();
        if !executor.stopped
            && let Some(asmop) = executor.current_asmop.as_ref()
        {
            check(asmop, &executor.callstack.logical_frames(""));
        }
    }
}

#[test]
fn repeated_calls_at_one_site_have_distinct_invocation_identities() {
    for invocation in ["call.inner", "exec.inner"] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = format!(
            "proc inner push.7 drop end begin push.2 dup neq.0 while.true {invocation} sub.1 dup \
             neq.0 end drop end"
        );
        let package = Arc::from(
            Assembler::new(source_manager.clone())
                .assemble_program("program", source)
                .unwrap(),
        );
        let mut executor = crate::Executor::new(Vec::new()).into_debug(package, source_manager);
        let mut activations = Vec::new();
        while !executor.stopped {
            executor.step().unwrap();
            if executor.stopped
                || executor.current_op != Some(Operation::Push(miden_core::Felt::from(7u32)))
            {
                continue;
            }
            let frames = executor.callstack.logical_frames("");
            let current = frames.last().unwrap();
            assert!(current.name().ends_with("::inner"));
            activations.push(current.invocation_id().expect("physical invocation"));
        }
        assert_eq!(activations.len(), 2, "{invocation}");
        assert_ne!(activations[0], activations[1], "{invocation}");
    }
}

#[test]
fn caller_source_inline_frames_survive_calls_and_clear_on_return() {
    for invocation in ["call.target", "dynexec"] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let setup = if invocation == "dynexec" {
            "procref.target mem_storew_le.100 dropw push.100"
        } else {
            ""
        };
        let source = format!(
            "proc target push.7 drop end begin {setup} nop nop push.1 drop {invocation} nop \
             push.9 drop end"
        );
        let mut module = Module::parser(Some(ModuleKind::Executable))
            .parse_str(None, source, source_manager.clone())
            .unwrap();
        let entrypoint = module.procedures_mut().find(|proc| proc.is_entrypoint()).unwrap();
        let mut markers = [None, Some("source::caller"), None].into_iter();
        let mut call_site = None;
        for op in entrypoint.body_mut().iter_mut() {
            let Op::Inst(instruction) = op else { continue };
            if !matches!(instruction.inner(), Instruction::Nop) {
                continue;
            }
            let span = instruction.span();
            let replacement = match markers.next().unwrap() {
                Some(name) => {
                    call_site = Some(source_manager.location(span).unwrap());
                    let location = source_manager.file_line_col(span).unwrap();
                    Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                        name,
                        location.clone(),
                        location,
                    ))
                }
                None => Instruction::DebugInlineCallClear,
            };
            *op = Op::Inst(Span::new(span, replacement));
        }
        assert!(markers.next().is_none());
        let package = Arc::from(
            Assembler::new(source_manager.clone())
                .assemble_program("program", module)
                .unwrap(),
        );
        let call_site = call_site.unwrap();
        let mut suspended_locations = None;
        let mut suspended_frames = None;
        let mut target_cycles = 0;
        let mut returned = false;
        run(package, source_manager, &[], |asmop, frames| {
            let names = frames.iter().map(LogicalStackFrame::name).collect::<Vec<_>>();
            if names == ["$exec::$main", "source::caller"] {
                let location = frames[0].assembly_location().unwrap();
                assert_eq!(location.uri, call_site.uri);
                assert_eq!(location.start, call_site.start);
                assert_eq!(frames[1].kind(), LogicalFrameKind::Inline);
                suspended_locations = Some(
                    frames
                        .iter()
                        .map(|frame| frame.assembly_location().cloned())
                        .collect::<Vec<_>>(),
                );
                suspended_frames = Some(frames.to_vec());
            }
            if asmop.context_name().ends_with("::target") {
                assert_eq!(names, ["$exec::$main", "source::caller", "$exec::target"]);
                assert_eq!(
                    frames[..2]
                        .iter()
                        .map(|frame| frame.assembly_location().cloned())
                        .collect::<Vec<_>>(),
                    *suspended_locations.as_ref().expect("caller must be observed before target"),
                    "suspended caller locations must survive {invocation}"
                );
                assert_eq!(frames[2].assembly_location(), asmop.location());
                for (caller, suspended) in frames.iter().zip(suspended_frames.as_ref().unwrap()) {
                    assert!(caller.is_same_source_frame(suspended));
                }
                for frame in frames {
                    let info = frame.debug_info().expect("recovered frame retains its package");
                    let function = frame.function().expect("recovered frame retains its function");
                    assert_eq!(info[function.name_idx].trim_start_matches("::"), frame.name());
                }
                target_cycles += 1;
            }
            if asmop.op().as_ref() == "push.9" {
                assert_eq!(names, ["$exec::$main"], "returned frames must be removed");
                assert_eq!(frames[0].assembly_location(), asmop.location());
                returned = true;
            }
        });
        assert!(target_cycles >= 2, "target must span multiple operations: {invocation}");
        assert!(returned, "caller must resume after {invocation}");
    }
}

#[test]
fn external_exec_has_one_loaded_target_and_restores_the_caller() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let library: Arc<Package> = Arc::from(
        Assembler::new(source_manager.clone())
            .assemble_library(
                "dep",
                "namespace dep::math pub proc target push.7 drop end",
                None::<String>,
            )
            .unwrap(),
    );
    let package = Arc::from(
        Assembler::new(source_manager.clone())
            .with_package(library.clone(), Linkage::Dynamic)
            .unwrap()
            .assemble_program("program", "use dep::math begin exec.math::target push.9 drop end")
            .unwrap(),
    );
    let mut target_cycles = 0;
    let mut returned = false;
    run(package, source_manager, &[library], |asmop, frames| {
        let names = frames.iter().map(LogicalStackFrame::name).collect::<Vec<_>>();
        if asmop.context_name().ends_with("::target") {
            assert_eq!(names, ["$exec::$main", "dep::math::target"]);
            assert_eq!(frames[1].kind(), LogicalFrameKind::Physical);
            assert_eq!(frames[1].assembly_location(), asmop.location());
            assert_eq!(
                frames[0].assembly_location().unwrap().start.to_usize(),
                20,
                "caller must point to exec.math::target"
            );
            target_cycles += 1;
        }
        if asmop.op().as_ref() == "push.9" {
            assert_eq!(names, ["$exec::$main"]);
            assert_eq!(frames[0].assembly_location(), asmop.location());
            returned = true;
        }
    });
    assert!(target_cycles >= 2);
    assert!(returned);
}

#[test]
fn changing_source_inline_depth_stays_inside_the_callee() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut module = Module::parser(Some(ModuleKind::Executable))
        .parse_str(
            None,
            "proc inner push.7 drop nop push.6 drop nop push.5 drop end proc outer exec.inner \
             push.8 drop end begin exec.outer push.9 drop end",
            source_manager.clone(),
        )
        .unwrap();
    let mut entering = true;
    for procedure in module.procedures_mut() {
        for op in procedure.body_mut().iter_mut() {
            let Op::Inst(instruction) = op else { continue };
            if !matches!(instruction.inner(), Instruction::Nop) {
                continue;
            }
            let span = instruction.span();
            let replacement = if entering {
                let location = source_manager.file_line_col(span).unwrap();
                Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                    "source::inline",
                    location.clone(),
                    location,
                ))
            } else {
                Instruction::DebugInlineCallClear
            };
            *op = Op::Inst(Span::new(span, replacement));
            entering = false;
        }
    }
    let package = Arc::from(
        Assembler::new(source_manager.clone())
            .assemble_program("program", module)
            .unwrap(),
    );
    let mut phases = [false; 3];
    run(package, source_manager, &[], |asmop, frames| {
        let phase = match asmop.op().as_ref() {
            "push.7" => 0,
            "push.6" => 1,
            "push.5" => 2,
            _ => return,
        };
        let names = frames.iter().map(LogicalStackFrame::name).collect::<Vec<_>>();
        let expected = if phase == 1 {
            vec!["$exec::$main", "$exec::outer", "$exec::inner", "source::inline"]
        } else {
            vec!["$exec::$main", "$exec::outer", "$exec::inner"]
        };
        assert_eq!(names, expected);
        assert_eq!(frames.last().unwrap().assembly_location(), asmop.location());
        phases[phase] = true;
    });
    assert_eq!(phases, [true; 3]);
}
