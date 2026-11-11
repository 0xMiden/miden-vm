use std::{fs, path::PathBuf};

use miden_assembly_syntax::debuginfo::{DefaultSourceManager, SourceManagerExt};
use miden_debug_types::{ByteIndex, Location, Uri};

use super::*;

#[test]
#[cfg(feature = "std")]
fn resolves_relative_source_locations_from_filesystem() {
    let path = test_source_path("relative");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "fn main() {\n    let x = 1;\n}\n").unwrap();

    let start = "fn main() {\n    ".len() as u32;
    let location = Location::new(
        Uri::from(path.display().to_string()),
        ByteIndex::new(start),
        ByteIndex::new(start + 5),
    );
    let detail = OpDetail::Full {
        op: Operation::Noop,
        location: Some(location),
        resolved: OnceCell::new(),
    };
    let source_manager = DefaultSourceManager::default();

    let resolved = detail.resolve(&source_manager).expect("source should resolve");
    assert_eq!(resolved.line, 2);
    assert!(resolved.source_file.uri().as_str().ends_with("src/lib.rs"));

    fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).ok();
}

#[test]
fn logical_frames_place_innermost_inline_frame_on_top() {
    let path = test_source_path("inline-frames");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = "physical call\nouter call\ninner body\n";
    fs::write(&path, source).unwrap();
    let uri = Uri::from(path.display().to_string());

    let mut frame = CallFrame::new(Some(Arc::from("crate::physical")));
    let outer_start = "physical call\n".len() as u32;
    frame.inline_frames = vec![
        InlineCallFrame {
            name: Arc::from("crate::inner"),
            call_site: Location::new(
                uri.clone(),
                ByteIndex::new(outer_start),
                ByteIndex::new(outer_start + "outer call".len() as u32),
            ),
        },
        InlineCallFrame {
            name: Arc::from("crate::outer"),
            call_site: Location::new(
                uri.clone(),
                ByteIndex::new(0),
                ByteIndex::new("physical call".len() as u32),
            ),
        },
    ];
    let inner_start = "physical call\nouter call\n".len() as u32;
    let asmop = AssemblyOp::new(
        Some(Location::new(
            uri,
            ByteIndex::new(inner_start),
            ByteIndex::new(inner_start + "inner body".len() as u32),
        )),
        "crate::physical".to_string(),
        1,
        "add".to_string(),
    );
    frame.push(Operation::Add, 1, Some(&asmop));

    let mut callstack = CallStack::new(Arc::new(RwLock::new(BTreeMap::new())));
    callstack.frames.push(frame);
    let source_manager = DefaultSourceManager::default();
    // Frame ordering does not depend on the std-only filesystem fallback.
    source_manager.load_file(&path).expect("source should load");
    let logical = callstack.logical_frames("");

    assert_eq!(logical.len(), 3);
    assert_eq!(logical[0].name(), "crate::physical");
    assert_eq!(logical[0].kind(), LogicalFrameKind::Physical);
    assert_eq!(logical[0].resolved(&source_manager).unwrap().line, 1);
    assert_eq!(logical[1].name(), "crate::outer");
    assert_eq!(logical[1].resolved(&source_manager).unwrap().line, 2);
    assert_eq!(logical[2].name(), "crate::inner");
    assert_eq!(logical[2].kind(), LogicalFrameKind::Inline);
    assert_eq!(logical[2].resolved(&source_manager).unwrap().line, 3);

    fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).ok();
}

#[test]
fn control_cycles_replace_and_clear_inline_frames() {
    let inline = InlineCallFrame {
        name: Arc::from("crate::inline"),
        call_site: Location::new(Uri::new("test.masm"), ByteIndex::new(0), ByteIndex::new(1)),
    };
    let mut callstack = CallStack::new(Arc::new(RwLock::new(BTreeMap::new())));

    callstack.next(&StepInfo {
        op: None,
        control: Some(ControlFlowOp::Split),
        asmop: None,
        clk: RowIndex::from(0u32),
        ctx: ContextId::root(),
        inline_frames: std::slice::from_ref(&inline),
    });

    let logical = callstack.logical_frames("");
    assert_eq!(logical.len(), 2);
    assert_eq!(logical[0].name(), "<unknown>");
    assert_eq!(logical[1].name(), "crate::inline");

    callstack.next(&StepInfo {
        op: None,
        control: Some(ControlFlowOp::Respan),
        asmop: None,
        clk: RowIndex::from(1u32),
        ctx: ContextId::root(),
        inline_frames: &[],
    });

    let logical = callstack.logical_frames("");
    assert_eq!(logical.len(), 1);
    assert_eq!(logical[0].name(), "<unknown>");
}

#[test]
fn logical_physical_frame_tracks_exec_procedure_changes() {
    let mut callstack = CallStack::new(Arc::new(RwLock::new(BTreeMap::new())));
    let main = AssemblyOp::new(None, "program::main".to_string(), 1, "add".to_string());
    callstack.next(&StepInfo {
        op: Some(Operation::Add),
        control: None,
        asmop: Some(&main),
        clk: RowIndex::from(0u32),
        ctx: ContextId::root(),
        inline_frames: &[],
    });

    let logical = callstack.logical_frames("");
    assert_eq!(logical[0].name(), "program::main");
    assert_eq!(logical[0].display_name(), "program::main");

    let inline = InlineCallFrame {
        name: Arc::from("source::inline"),
        call_site: Location::new(Uri::new("test.masm"), ByteIndex::new(0), ByteIndex::new(1)),
    };
    let exec = AssemblyOp::new(None, "program::double".to_string(), 1, "mul".to_string());
    callstack.next(&StepInfo {
        op: Some(Operation::Mul),
        control: None,
        asmop: Some(&exec),
        clk: RowIndex::from(1u32),
        ctx: ContextId::root(),
        inline_frames: std::slice::from_ref(&inline),
    });

    let logical = callstack.logical_frames("");
    assert_eq!(logical.len(), 2);
    assert_eq!(logical[0].kind(), LogicalFrameKind::Physical);
    assert_eq!(logical[0].name(), "program::double");
    assert_eq!(logical[0].display_name(), "program::double");
    assert_eq!(logical[1].kind(), LogicalFrameKind::Inline);
}

#[test]
fn control_cycle_tracks_exec_procedure_change_before_first_operation() {
    let mut callstack = CallStack::new(Arc::new(RwLock::new(BTreeMap::new())));
    let main = AssemblyOp::new(None, "program::main".to_string(), 1, "add".to_string());
    callstack.next(&StepInfo {
        op: Some(Operation::Add),
        control: None,
        asmop: Some(&main),
        clk: RowIndex::from(0u32),
        ctx: ContextId::root(),
        inline_frames: &[],
    });

    let exec = AssemblyOp::new(None, "program::double".to_string(), 1, "if.true".to_string());
    callstack.next(&StepInfo {
        op: None,
        control: Some(ControlFlowOp::Split),
        asmop: Some(&exec),
        clk: RowIndex::from(1u32),
        ctx: ContextId::root(),
        inline_frames: &[],
    });

    let logical = callstack.logical_frames("");
    assert_eq!(logical[0].name(), "program::double");
}

#[cfg(feature = "dap")]
#[test]
fn remote_logical_frames_preserve_pre_resolved_locations() {
    let path = test_source_path("remote-logical-frame");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "first line\nsecond line\n").unwrap();

    let source_manager = DefaultSourceManager::default();
    let source_file = source_manager.load_file(&path).expect("source should load");
    let span = SourceSpan::new(source_file.id(), ByteIndex::new(11)..ByteIndex::new(17));
    let remote = ResolvedLocation {
        source_file,
        line: 77,
        col: 13,
        span,
    };
    let callstack = CallStack::from_remote_frames(vec![CallFrame::from_remote(
        Some(Arc::from("remote::procedure")),
        Some(remote.clone()),
    )]);

    let recent = callstack
        .current_frame()
        .unwrap()
        .last_resolved(&source_manager)
        .expect("remote frame should retain its cached location");
    assert_eq!(recent.line, remote.line);
    assert_eq!(recent.col, remote.col);
    assert_eq!(recent.span, remote.span);

    let logical = callstack.logical_frames("");
    let resolved = logical[0]
        .resolved(&source_manager)
        .expect("logical frame should retain its cached location");
    assert_eq!(resolved.source_file.uri(), remote.source_file.uri());
    assert_eq!(resolved.line, remote.line);
    assert_eq!(resolved.col, remote.col);
    assert_eq!(resolved.span, remote.span);

    fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).ok();
}

fn test_source_path(test_name: &str) -> PathBuf {
    PathBuf::from("target")
        .join("debugger-source-tests")
        .join(format!("{}-{}", test_name, std::process::id()))
        .join("src")
        .join("lib.rs")
}

impl InlineCallFrame {
    #[cfg(feature = "dap")]
    pub(crate) fn new_for_test(name: impl Into<Arc<str>>, call_site: Location) -> Self {
        Self {
            name: name.into(),
            call_site,
        }
    }
}

#[test]
fn compact_inline_ranges_preserve_interiors_gaps_and_frame_order() {
    use miden_core::serde::Deserializable;
    use miden_mast_package::debug_info::PackageDebugInfoBuilder;

    let package = miden_assembly::Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("ranges", "begin push.1.2.3.4 dropw push.5.6.7.8 dropw end")
        .unwrap();
    let info = package.debug_info().unwrap().unwrap();
    let (source_index, node) = info
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.op_end - node.op_start >= 14)
        .unwrap();
    let source = DebugSourceNodeId::from(u32::try_from(source_index).unwrap());
    let start = node.op_start;
    let location = node.asm_ops[0].location_idx.into_option().unwrap();
    let definition = info.functions()[0];
    let mut builder = PackageDebugInfoBuilder::from(Box::new(info));
    let mut inner = definition;
    inner.mast_root = Default::default();
    inner.name_idx = builder.add_string("source::inner");
    let inner = builder.add_function(inner);
    let mut outer = definition;
    outer.mast_root = Default::default();
    outer.name_idx = builder.add_string("source::outer");
    let outer = builder.add_function(outer);
    builder[source].inline_calls = vec![
        DebugSourceInlineCall {
            op_idx: start + 2,
            op_end: start + 5,
            callee_idx: inner,
            loc_idx: location,
        },
        DebugSourceInlineCall {
            op_idx: start,
            op_end: start + 10,
            callee_idx: outer,
            loc_idx: location,
        },
        DebugSourceInlineCall {
            op_idx: start + 12,
            op_end: start + 14,
            callee_idx: inner,
            loc_idx: location,
        },
    ];
    let bytes = builder.build().to_bytes_with_standard_limits().unwrap();
    let info = PackageDebugInfo::read_from_bytes(&bytes).unwrap();
    assert_eq!(info[source].inline_calls.len(), 3);
    for (offset, expected) in [
        (0, vec!["source::outer"]),
        (2, vec!["source::inner", "source::outer"]),
        (4, vec!["source::inner", "source::outer"]),
        (5, vec!["source::outer"]),
        (9, vec!["source::outer"]),
        (10, vec![]),
        (11, vec![]),
        (12, vec!["source::inner"]),
        (14, vec![]),
    ] {
        let frames = inline_frames_for_operation(Some((&info, source, start + offset)), []);
        let names = frames.iter().map(|frame| frame.name.as_ref()).collect::<Vec<_>>();
        assert_eq!(names, expected, "operation {offset}");
    }
}
