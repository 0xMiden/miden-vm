use std::{borrow::Cow, boxed::Box, ops::Range, path::Path, rc::Rc, string::ToString, vec::Vec};

mod syntax {
    pub(super) use syntect::{
        highlighting::{
            Color, FontStyle, HighlightIterator, HighlightState, Highlighter, Style, StyleModifier,
            Theme, ThemeSet,
        },
        parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet},
    };
}

use miden_assembly_syntax::diagnostics::miette::SpanContents;
use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

pub trait Highlighter {
    ///  Creates a new [HighlighterState] to begin parsing and highlighting
    /// a [SpanContents].
    ///
    /// The [GraphicalReportHandler](crate::GraphicalReportHandler) will call
    /// this method at the start of rendering a [SpanContents].
    ///
    /// The [SpanContents] is provided as input only so that the [Highlighter]
    /// can detect language syntax and make other initialization decisions prior
    /// to highlighting, but it is not intended that the Highlighter begin
    /// highlighting at this point. The returned [HighlighterState] is
    /// responsible for the actual rendering.
    fn start_highlighter_state(&self, source: &dyn SpanContents<'_>) -> Box<dyn HighlighterState>;
}

/// A stateful highlighter that incrementally highlights lines of a particular
/// source code.
///
/// The [GraphicalReportHandler](crate::GraphicalReportHandler)
/// will create a highlighter state by calling
/// [start_highlighter_state](Highlighter::start_highlighter_state) at the
/// start of rendering, then it will iteratively call
/// [highlight_line](HighlighterState::highlight_line) to render individual
/// highlighted lines. This allows [Highlighter] implementations to maintain
/// mutable parsing and highlighting state.
pub trait HighlighterState {
    /// Highlight an individual line from the source code by returning a vector of [Styled]
    /// regions.
    fn highlight_line<'a>(&mut self, line: Cow<'a, str>) -> Vec<Span<'a>>;
    fn highlight_line_with_selection<'a>(
        &mut self,
        line: Cow<'a, str>,
        selected: Range<usize>,
        style: Style,
    ) -> Vec<Span<'a>>;
}

/// The fallback syntax highlighter.
///
/// This simply returns a line without any styling at all
#[derive(Debug, Clone)]
pub struct NoopHighlighter;

impl Highlighter for NoopHighlighter {
    fn start_highlighter_state(&self, _source: &dyn SpanContents<'_>) -> Box<dyn HighlighterState> {
        Box::new(NoopHighlighterState)
    }
}

impl Default for NoopHighlighter {
    fn default() -> Self {
        NoopHighlighter
    }
}

/// The fallback highlighter state.
#[derive(Debug, Clone)]
pub struct NoopHighlighterState;

impl HighlighterState for NoopHighlighterState {
    fn highlight_line<'a>(&mut self, line: Cow<'a, str>) -> Vec<Span<'a>> {
        vec![Span::raw(line)]
    }

    fn highlight_line_with_selection<'a>(
        &mut self,
        line: Cow<'a, str>,
        selected: Range<usize>,
        style: Style,
    ) -> Vec<Span<'a>> {
        default_line_with_selection(line, selected, style)
    }
}

fn default_line_with_selection(
    line: Cow<'_, str>,
    selected: Range<usize>,
    style: Style,
) -> Vec<Span<'_>> {
    let selected = clamp_byte_selection_to_str(&line, selected);
    let prefix_content =
        core::str::from_utf8(&line.as_bytes()[..selected.start]).expect("invalid selection");
    let selected_content =
        core::str::from_utf8(&line.as_bytes()[selected.clone()]).expect("invalid selection");
    let suffix_content =
        core::str::from_utf8(&line.as_bytes()[selected.end..]).expect("invalid selection");
    let (selected_content, suffix_content) = if suffix_content.is_empty() {
        (selected_content.strip_suffix('\n').unwrap_or(selected_content), suffix_content)
    } else {
        (selected_content, suffix_content.strip_suffix('\n').unwrap_or(suffix_content))
    };
    vec![
        Span::raw(prefix_content.to_string()),
        Span::styled(selected_content.to_string(), style),
        Span::raw(suffix_content.to_string()),
    ]
}

pub fn clamp_byte_selection_to_str(line: &str, selected: Range<usize>) -> Range<usize> {
    fn floor_char_boundary(line: &str, idx: usize) -> usize {
        let mut idx = idx.min(line.len());
        while idx > 0 && !line.is_char_boundary(idx) {
            idx -= 1;
        }
        idx
    }

    let start = floor_char_boundary(line, selected.start);
    let end = floor_char_boundary(line, selected.end).max(start);
    start..end
}

/// Syntax highlighting provided by [syntect](https://docs.rs/syntect/latest/syntect/).
///
/// Currently only 24-bit truecolor output is supported due to syntect themes
/// representing color as RGBA.
#[derive(Debug, Clone)]
pub struct SyntectHighlighter {
    theme: &'static syntax::Theme,
    syntax_set: Rc<syntax::SyntaxSet>,
    use_bg_color: bool,
}

impl Default for SyntectHighlighter {
    fn default() -> Self {
        let theme_set = syntax::ThemeSet::load_defaults();
        let theme = theme_set.themes["base16-ocean.dark"].clone();
        Self::new_themed(theme, false)
    }
}

impl Highlighter for SyntectHighlighter {
    fn start_highlighter_state(&self, source: &dyn SpanContents<'_>) -> Box<dyn HighlighterState> {
        if let Some(syntax) = self.detect_syntax(source) {
            let highlighter = syntax::Highlighter::new(self.theme);
            let parse_state = syntax::ParseState::new(syntax);
            let highlight_state =
                syntax::HighlightState::new(&highlighter, syntax::ScopeStack::new());
            Box::new(SyntectHighlighterState {
                syntax_set: Rc::clone(&self.syntax_set),
                highlighter,
                parse_state,
                highlight_state,
                use_bg_color: self.use_bg_color,
            })
        } else {
            Box::new(NoopHighlighterState)
        }
    }
}

impl SyntectHighlighter {
    /// Create a syntect highlighter with the given theme and syntax set.
    pub fn new(syntax_set: syntax::SyntaxSet, theme: syntax::Theme, use_bg_color: bool) -> Self {
        // This simplifies a lot of things API-wise, we only ever really have one of these anyway
        let theme = Box::leak(Box::new(theme));
        Self {
            theme,
            syntax_set: Rc::new(syntax_set),
            use_bg_color,
        }
    }

    /// Create a syntect highlighter with the given theme and the default syntax set.
    pub fn new_themed(theme: syntax::Theme, use_bg_color: bool) -> Self {
        Self::new(syntax::SyntaxSet::load_defaults_nonewlines(), theme, use_bg_color)
    }

    /// Determine syntect SyntaxReference to use for given SourceCode
    fn detect_syntax(&self, contents: &dyn SpanContents<'_>) -> Option<&syntax::SyntaxReference> {
        // use language if given
        if let Some(language) = contents.language() {
            return self.syntax_set.find_syntax_by_name(language);
        }
        // otherwise try to use any file extension provided in the name
        if let Some(name) = contents.name()
            && let Some(ext) = Path::new(name).extension()
        {
            return self.syntax_set.find_syntax_by_extension(ext.to_string_lossy().as_ref());
        }
        // finally, attempt to guess syntax based on first line
        self.syntax_set.find_syntax_by_first_line(
            core::str::from_utf8(contents.data()).ok()?.split('\n').next()?,
        )
    }
}

/// Stateful highlighting iterator for [SyntectHighlighter]
#[derive(Debug)]
pub(crate) struct SyntectHighlighterState<'h> {
    syntax_set: Rc<syntax::SyntaxSet>,
    highlighter: syntax::Highlighter<'h>,
    parse_state: syntax::ParseState,
    highlight_state: syntax::HighlightState,
    use_bg_color: bool,
}

impl HighlighterState for SyntectHighlighterState<'_> {
    fn highlight_line<'a>(&mut self, line: Cow<'a, str>) -> Vec<Span<'a>> {
        if let Ok(ops) = self.parse_state.parse_line(&line, &self.syntax_set) {
            let use_bg_color = self.use_bg_color;
            syntax::HighlightIterator::new(
                &mut self.highlight_state,
                &ops,
                &line,
                &self.highlighter,
            )
            .map(|(style, str)| Span::styled(str.to_string(), convert_style(style, use_bg_color)))
            .collect()
        } else {
            vec![Span::raw(line)]
        }
    }

    fn highlight_line_with_selection<'a>(
        &mut self,
        line: Cow<'a, str>,
        selected: Range<usize>,
        style: Style,
    ) -> Vec<Span<'a>> {
        let selected = clamp_byte_selection_to_str(&line, selected);
        if let Ok(ops) = self.parse_state.parse_line(&line, &self.syntax_set) {
            let use_bg_color = self.use_bg_color;
            let parts = syntax::HighlightIterator::new(
                &mut self.highlight_state,
                &ops,
                &line,
                &self.highlighter,
            )
            .collect::<Vec<_>>();
            let syntect_style = syntax::StyleModifier {
                foreground: style.fg.map(convert_to_syntect_color),
                background: style.bg.map(convert_to_syntect_color),
                font_style: if style.add_modifier.is_empty() {
                    None
                } else {
                    Some(convert_to_font_style(style.add_modifier))
                },
            };
            syntect::util::modify_range(&parts, selected, syntect_style)
                .into_iter()
                .map(|(style, str)| {
                    Span::styled(str.to_string(), convert_style(style, use_bg_color))
                })
                .collect()
        } else {
            default_line_with_selection(line, selected, style)
        }
    }
}

/// Convert syntect [syntax::Style] into ratatui [Style] */
#[inline]
pub fn convert_style(syntect_style: syntax::Style, use_bg_color: bool) -> Style {
    let fg = syntect_style.foreground;
    let bg = syntect_style.background;
    let mut style = Style::new();
    // Skip transparent colors (alpha=0) to use the terminal's native colors
    if fg.a > 0 {
        let fg_color = if use_bg_color {
            blend_fg_color(syntect_style)
        } else {
            convert_color(fg)
        };
        style = style.fg(fg_color);
    }
    if use_bg_color && bg.a > 0 {
        style = style.bg(convert_color(bg));
    }
    let mods = convert_font_style(syntect_style.font_style);
    style.add_modifier(mods)
}

pub fn convert_to_syntect_style(style: Style, _use_bg_color: bool) -> syntax::Style {
    let fg = style.fg.map(convert_to_syntect_color);
    let bg = style.bg.map(convert_to_syntect_color);
    let fs = convert_to_font_style(style.add_modifier);
    // Use transparent (alpha=0) fallbacks so that convert_style will skip
    // setting explicit colors, letting the terminal's native colors show through.
    // This avoids hardcoded White/Black that break on light/dark terminals.
    let transparent = syntax::Color {
        r: 0,
        g: 0,
        b: 0,
        a: 0,
    };
    syntax::Style {
        foreground: fg.unwrap_or(transparent),
        background: bg.unwrap_or(transparent),
        font_style: fs,
    }
}

/// Blend foreground RGB into background RGB according to alpha channel
#[inline]
fn blend_fg_color(syntect_style: syntax::Style) -> Color {
    let fg = syntect_style.foreground;
    if fg.a == 0xff {
        return convert_color(fg);
    }
    let bg = syntect_style.background;
    let ratio = fg.a as u32;
    let r = (fg.r as u32 * ratio + bg.r as u32 * (255 - ratio)) / 255;
    let g = (fg.g as u32 * ratio + bg.g as u32 * (255 - ratio)) / 255;
    let b = (fg.b as u32 * ratio + bg.b as u32 * (255 - ratio)) / 255;
    Color::from_u32(u32::from_be_bytes([0, r as u8, g as u8, b as u8]))
}

/// Convert syntect color into ratatui color
///
/// Note: ignores alpha channel. use [`blend_fg_color`] if you need that
#[inline]
pub fn convert_color(color: syntax::Color) -> Color {
    Color::from_u32(u32::from_be_bytes([color.a, color.r, color.g, color.b]))
}

/// Convert syntect font style into ratatui modifiers
#[inline]
fn convert_font_style(font_style: syntax::FontStyle) -> Modifier {
    use syntax::FontStyle;

    let mut mods = Modifier::default();
    if font_style.contains(FontStyle::BOLD) {
        mods.insert(Modifier::BOLD);
    }
    if font_style.contains(FontStyle::ITALIC) {
        mods.insert(Modifier::ITALIC);
    }
    if font_style.contains(FontStyle::UNDERLINE) {
        mods.insert(Modifier::UNDERLINED);
    }
    mods
}

pub fn convert_to_font_style(mods: Modifier) -> syntax::FontStyle {
    use syntax::FontStyle;

    let mut style = FontStyle::default();
    if mods.contains(Modifier::BOLD) {
        style.insert(FontStyle::BOLD);
    }
    if mods.contains(Modifier::ITALIC) {
        style.insert(FontStyle::ITALIC);
    }
    if mods.contains(Modifier::UNDERLINED) {
        style.insert(FontStyle::UNDERLINE);
    }
    style
}

pub fn convert_to_syntect_color(color: Color) -> syntax::Color {
    match color {
        Color::Rgb(r, g, b) => syntax::Color { r, g, b, a: 0 },
        Color::Indexed(code) => convert_to_syntect_color(match code {
            0 => Color::Black,
            1 => Color::Red,
            2 => Color::Green,
            3 => Color::Yellow,
            4 => Color::Blue,
            5 => Color::Magenta,
            6 => Color::Cyan,
            7 => Color::Gray,
            8 => Color::DarkGray,
            9 => Color::LightRed,
            10 => Color::LightGreen,
            11 => Color::LightYellow,
            12 => Color::LightBlue,
            13 => Color::LightMagenta,
            14 => Color::LightCyan,
            15 => Color::White,
            code => panic!("unrecognized ansi color index: {code}"),
        }),
        Color::Black => syntax::Color {
            r: 0,
            g: 0,
            b: 0,
            a: u8::MAX,
        },
        Color::Green => syntax::Color {
            r: 0,
            g: 128,
            b: 0,
            a: u8::MAX,
        },
        Color::LightGreen => syntax::Color {
            r: 0,
            g: 255,
            b: 0,
            a: u8::MAX,
        },
        Color::Red => syntax::Color {
            r: 128,
            g: 0,
            b: 0,
            a: u8::MAX,
        },
        Color::LightRed => syntax::Color {
            r: 255,
            g: 0,
            b: 0,
            a: u8::MAX,
        },
        Color::Yellow => syntax::Color {
            r: 128,
            g: 128,
            b: 0,
            a: u8::MAX,
        },
        Color::LightYellow => syntax::Color {
            r: 255,
            g: 255,
            b: 0,
            a: u8::MAX,
        },
        Color::Blue => syntax::Color {
            r: 0,
            g: 0,
            b: 128,
            a: u8::MAX,
        },
        Color::LightBlue => syntax::Color {
            r: 0,
            g: 0,
            b: 255,
            a: u8::MAX,
        },
        Color::DarkGray => syntax::Color {
            r: 128,
            g: 128,
            b: 128,
            a: u8::MAX,
        },
        Color::Gray => syntax::Color {
            r: 192,
            g: 192,
            b: 192,
            a: u8::MAX,
        },
        Color::White => syntax::Color {
            r: 255,
            g: 255,
            b: 255,
            a: u8::MAX,
        },
        Color::Magenta => syntax::Color {
            r: 128,
            g: 0,
            b: 128,
            a: u8::MAX,
        },
        Color::LightMagenta => syntax::Color {
            r: 255,
            g: 0,
            b: 255,
            a: u8::MAX,
        },
        Color::Cyan => syntax::Color {
            r: 0,
            g: 128,
            b: 128,
            a: u8::MAX,
        },
        Color::LightCyan => syntax::Color {
            r: 0,
            g: 255,
            b: 255,
            a: u8::MAX,
        },
        Color::Reset => {
            panic!("invalid syntax color: reset cannot be used for syntax highlighting")
        }
    }
}

#[cfg(test)]
mod tests;
