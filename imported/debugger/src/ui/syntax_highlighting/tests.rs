use std::string::String;

use miden_assembly_syntax::diagnostics::miette::MietteSpanContents;

use super::*;

#[test]
fn fallback_selection_preserves_utf8_and_excludes_trailing_newlines() {
    let source = MietteSpanContents::new(b"text", (0, 4).into(), 0, 0, 1);
    let mut state = NoopHighlighter.start_highlighter_state(&source);
    assert_eq!(state.highlight_line(Cow::Borrowed("text")), vec![Span::raw("text")]);
    let style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);
    for (line, selection, expected) in [
        ("aéz\n", 2..3, ["a", "é", "z"]),
        ("abc\n", 1..99, ["a", "bc", ""]),
        ("abc", 99..100, ["abc", "", ""]),
        ("abc", Range { start: 2, end: 1 }, ["ab", "", "c"]),
    ] {
        let spans = state.highlight_line_with_selection(Cow::Borrowed(line), selection, style);
        assert_eq!(spans.iter().map(|span| span.content.as_ref()).collect::<Vec<_>>(), expected);
        assert_eq!(spans[1].style, style);
        assert_eq!(spans[0].style, Style::default());
        assert_eq!(spans[2].style, Style::default());
    }
}

#[test]
fn syntax_detection_uses_language_extension_and_shebang() {
    let highlighter = SyntectHighlighter::default();
    let source =
        MietteSpanContents::new(b"fn main() {}", (0, 12).into(), 0, 0, 1).with_language("Rust");
    assert_eq!(highlighter.detect_syntax(&source).unwrap().name, "Rust");
    let named =
        MietteSpanContents::new_named("main.rs".into(), b"fn main() {}", (0, 12).into(), 0, 0, 1);
    assert_eq!(highlighter.detect_syntax(&named).unwrap().name, "Rust");
    let shebang = MietteSpanContents::new(b"#!/usr/bin/env python\n", (0, 22).into(), 0, 0, 1);
    assert_eq!(highlighter.detect_syntax(&shebang).unwrap().name, "Python");
    let invalid = MietteSpanContents::new(&[255], (0, 1).into(), 0, 0, 1);
    assert!(highlighter.detect_syntax(&invalid).is_none());
    let unknown = MietteSpanContents::new(b"text", (0, 4).into(), 0, 0, 1).with_language("unknown");
    let mut fallback = highlighter.start_highlighter_state(&unknown);
    assert_eq!(fallback.highlight_line(Cow::Borrowed("text")), vec![Span::raw("text")]);
    let mut state = highlighter.start_highlighter_state(&source);
    let line = "fn main() { let answer = 42; }";
    let spans = state.highlight_line(Cow::Borrowed(line));
    assert_eq!(spans.iter().map(|span| span.content.as_ref()).collect::<String>(), line);
    assert!(spans.iter().any(|span| span.style.fg.is_some()));
    let spans = state.highlight_line_with_selection(
        Cow::Borrowed(line),
        3..7,
        Style::new().fg(Color::Red).bg(Color::Black).add_modifier(Modifier::BOLD),
    );
    assert_eq!(spans.iter().map(|span| span.content.as_ref()).collect::<String>(), line);
    assert!(
        spans
            .iter()
            .any(|span| span.content == "main" && span.style.add_modifier.contains(Modifier::BOLD))
    );
}

#[test]
fn style_conversion_handles_transparency_blending_and_font_modifiers() {
    let transparent = syntax::Color {
        r: 0,
        g: 0,
        b: 0,
        a: 0,
    };
    let background = syntax::Color {
        r: 0,
        g: 100,
        b: 200,
        a: 255,
    };
    let foreground = syntax::Color {
        r: 200,
        g: 100,
        b: 0,
        a: 128,
    };
    let modifiers = Modifier::BOLD | Modifier::ITALIC | Modifier::UNDERLINED;
    let font_style = convert_to_font_style(modifiers | Modifier::REVERSED);
    assert_eq!(convert_font_style(font_style), modifiers);
    assert!(convert_to_font_style(Modifier::empty()).is_empty());
    let style = syntax::Style {
        foreground,
        background,
        font_style,
    };
    assert_eq!(
        convert_style(style, true),
        Style::new()
            .fg(Color::Rgb(100, 100, 99))
            .bg(Color::Rgb(0, 100, 200))
            .add_modifier(modifiers)
    );
    assert_eq!(
        convert_style(style, false),
        Style::new().fg(Color::Rgb(200, 100, 0)).add_modifier(modifiers)
    );
    let opaque = syntax::Style {
        foreground: background,
        ..style
    };
    assert_eq!(blend_fg_color(opaque), Color::Rgb(0, 100, 200));
    let empty = syntax::Style {
        foreground: transparent,
        background: transparent,
        font_style: syntax::FontStyle::empty(),
    };
    assert_eq!(convert_style(empty, true), Style::new());
    assert_eq!(convert_to_syntect_style(Style::new(), false), empty);
    let converted = convert_to_syntect_style(
        Style::new().fg(Color::Red).bg(Color::Blue).add_modifier(modifiers),
        true,
    );
    assert_eq!(
        convert_style(converted, true),
        Style::new()
            .fg(Color::Rgb(128, 0, 0))
            .bg(Color::Rgb(0, 0, 128))
            .add_modifier(modifiers)
    );
}

#[test]
fn ansi_palette_maps_named_and_indexed_colors_to_the_same_rgb() {
    for (index, named, rgb) in [
        (0, Color::Black, [0, 0, 0]),
        (1, Color::Red, [128, 0, 0]),
        (2, Color::Green, [0, 128, 0]),
        (3, Color::Yellow, [128, 128, 0]),
        (4, Color::Blue, [0, 0, 128]),
        (5, Color::Magenta, [128, 0, 128]),
        (6, Color::Cyan, [0, 128, 128]),
        (7, Color::Gray, [192, 192, 192]),
        (8, Color::DarkGray, [128, 128, 128]),
        (9, Color::LightRed, [255, 0, 0]),
        (10, Color::LightGreen, [0, 255, 0]),
        (11, Color::LightYellow, [255, 255, 0]),
        (12, Color::LightBlue, [0, 0, 255]),
        (13, Color::LightMagenta, [255, 0, 255]),
        (14, Color::LightCyan, [0, 255, 255]),
        (15, Color::White, [255, 255, 255]),
    ] {
        let expected = syntax::Color {
            r: rgb[0],
            g: rgb[1],
            b: rgb[2],
            a: 255,
        };
        assert_eq!(convert_to_syntect_color(named), expected);
        assert_eq!(convert_to_syntect_color(Color::Indexed(index)), expected);
    }
    assert_eq!(
        convert_color(convert_to_syntect_color(Color::Rgb(1, 2, 3))),
        Color::Rgb(1, 2, 3)
    );
}
