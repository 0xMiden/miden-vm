use super::*;

#[test]
fn parses_frame_selection() {
    assert!(matches!("frame 2".parse(), Ok(ReplCommand::Frame(2))));
    assert!("frame".parse::<ReplCommand>().is_err());
}

#[test]
fn parses_execution_and_inspection_aliases() {
    for text in ["s", "step", " step "] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Step));
    }
    assert!(matches!("s 12".parse().unwrap(), ReplCommand::StepN(12)));
    assert!(matches!("step 0".parse().unwrap(), ReplCommand::StepN(0)));
    for text in ["n", "next"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Next));
    }
    for text in ["nl", "next-line", "nextline"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::NextLine));
    }
    for text in ["c", "continue"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Continue));
    }
    for text in ["e", "finish"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Finish));
    }
    for text in ["where", "w"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Where));
    }
    for text in ["l", "list"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::List));
    }
    for text in ["bt", "backtrace"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Backtrace));
    }
    for text in ["vars", "variables"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Vars(false)));
    }
    assert!(matches!("vars all".parse().unwrap(), ReplCommand::Vars(true)));
    assert!(matches!("locals".parse().unwrap(), ReplCommand::Locals));
    assert!(matches!("stack".parse().unwrap(), ReplCommand::Stack));
    assert!(matches!("reload".parse().unwrap(), ReplCommand::Reload));
    for text in ["h", "help", "?"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Help));
    }
    for text in ["q", "quit", "exit"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Quit));
    }
}

#[test]
fn parses_breakpoint_and_memory_arguments_and_reports_errors() {
    for text in ["b at 4", "break at 4", "breakpoint at 4"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Break(BreakpointType::StepTo(4))));
    }
    for text in ["bp", "breakpoints"] {
        assert!(matches!(text.parse().unwrap(), ReplCommand::Breakpoints));
    }
    assert!(matches!("delete".parse().unwrap(), ReplCommand::Delete(None)));
    assert!(matches!("d 255".parse().unwrap(), ReplCommand::Delete(Some(255))));
    for text in ["mem 0x10 -t u32", "memory 0x10 -t u32"] {
        let ReplCommand::Memory(expr) = text.parse().unwrap() else {
            panic!("expected memory command")
        };
        assert_eq!(expr.addr.addr, 16);
        assert_eq!(expr.ty, miden_assembly_syntax::ast::types::Type::U32);
    }
    for (text, expected) in [
        ("", "empty command"),
        ("step nope", "invalid step count"),
        ("break", "requires a specification"),
        ("delete 256", "invalid breakpoint id"),
        ("memory", "requires an address"),
        ("frame -1", "invalid frame index"),
        ("unknown", "unknown command"),
    ] {
        assert!(text.parse::<ReplCommand>().unwrap_err().contains(expected));
    }
}
