use std::mem;

use miden_assembly_syntax_cst::{
    Item, Operation, SyntaxKind, SyntaxNode, SyntaxToken,
    ast::{
        BeginBlock, Block, IfOp, Import, Instruction, Procedure, RepeatOp, Signature, SourceFile,
        TypeBody, TypeDecl, WhileOp,
    },
    rowan::{NodeOrToken, ast::AstNode},
};

const INDENT_WIDTH: usize = 4;
const MAX_LINE_WIDTH: usize = 80;

pub fn format_syntax(root: &SyntaxNode) -> String {
    let source = SourceFile::cast(root.clone()).expect("expected source file root");
    let mut lines = Vec::new();
    let (entries, tail) = analyze_children(source.syntax());

    for entry in entries {
        emit_leading_layout(&mut lines, &entry, 0);

        let item = Item::cast(entry.node).expect("expected top-level item");
        let mut rendered = render_item(&item, 0);
        if let Some(comment) = entry.trailing_comment {
            append_inline_comment(&mut rendered, &comment);
        }
        extend_lines(&mut lines, &rendered);
    }

    emit_tail_layout(&mut lines, tail, 0);
    finish_output(lines)
}

#[derive(Debug)]
struct NodeLayout {
    node: SyntaxNode,
    same_line_with_prev: bool,
    blank_lines_before: usize,
    leading_comments: Vec<String>,
    trailing_comment: Option<String>,
}

#[derive(Debug, Default)]
struct ContainerTail {
    blank_lines_before: usize,
    leading_comments: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum IntersticeState {
    SameLineAfterNode,
    StartOfLine,
    AfterContent,
}

#[derive(Debug)]
struct Interstice {
    state: IntersticeState,
    same_line_with_prev: bool,
    blank_lines: usize,
    leading_comments: Vec<String>,
    trailing_comment: Option<String>,
}

impl Interstice {
    fn start_of_container() -> Self {
        Self {
            state: IntersticeState::StartOfLine,
            same_line_with_prev: false,
            blank_lines: 0,
            leading_comments: Vec::new(),
            trailing_comment: None,
        }
    }

    fn after_node() -> Self {
        Self {
            state: IntersticeState::SameLineAfterNode,
            same_line_with_prev: true,
            blank_lines: 0,
            leading_comments: Vec::new(),
            trailing_comment: None,
        }
    }

    fn consume(&mut self, token: &SyntaxToken) {
        match token.kind() {
            SyntaxKind::Whitespace => (),
            SyntaxKind::Newline => match self.state {
                IntersticeState::SameLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.state = IntersticeState::StartOfLine;
                },
                IntersticeState::StartOfLine => {
                    self.same_line_with_prev = false;
                    self.blank_lines += 1;
                },
                IntersticeState::AfterContent => {
                    self.state = IntersticeState::StartOfLine;
                },
            },
            SyntaxKind::Comment | SyntaxKind::DocComment => match self.state {
                IntersticeState::SameLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.trailing_comment = Some(trimmed_comment(token));
                    self.state = IntersticeState::AfterContent;
                },
                IntersticeState::StartOfLine => {
                    self.same_line_with_prev = false;
                    self.leading_comments.push(trimmed_comment(token));
                    self.state = IntersticeState::AfterContent;
                },
                IntersticeState::AfterContent => (),
            },
            _ => (),
        }
    }
}

fn analyze_children(parent: &SyntaxNode) -> (Vec<NodeLayout>, ContainerTail) {
    let mut entries: Vec<NodeLayout> = Vec::new();
    let mut interstice = Interstice::start_of_container();

    for child in parent.children_with_tokens() {
        match child {
            NodeOrToken::Node(node) => {
                if let Some(previous) = entries.last_mut() {
                    previous.trailing_comment = interstice.trailing_comment.take();
                }

                entries.push(NodeLayout {
                    node,
                    same_line_with_prev: !entries.is_empty() && interstice.same_line_with_prev,
                    blank_lines_before: interstice.blank_lines.min(1),
                    leading_comments: mem::take(&mut interstice.leading_comments),
                    trailing_comment: None,
                });
                interstice = Interstice::after_node();
            },
            NodeOrToken::Token(token) => interstice.consume(&token),
        }
    }

    if let Some(previous) = entries.last_mut() {
        previous.trailing_comment = interstice.trailing_comment.take();
    }

    (
        entries,
        ContainerTail {
            blank_lines_before: interstice.blank_lines.min(1),
            leading_comments: interstice.leading_comments,
        },
    )
}

fn render_item(item: &Item, indent: usize) -> String {
    match item {
        Item::ModuleDoc(doc) => render_doc(doc, indent),
        Item::Doc(doc) => render_doc(doc, indent),
        Item::Import(import) => render_import(import, indent),
        Item::Constant(constant) => render_value_declaration(constant.syntax(), indent),
        Item::TypeDecl(type_decl) => render_type_decl(type_decl, indent),
        Item::AdviceMap(advice_map) => render_value_declaration(advice_map.syntax(), indent),
        Item::BeginBlock(begin) => render_begin_block(begin, indent),
        Item::Procedure(procedure) => render_procedure(procedure, indent),
    }
}

fn render_doc(
    doc: &impl AstNode<Language = miden_assembly_syntax_cst::MasmLanguage>,
    indent: usize,
) -> String {
    format!("{}{}", indent_string(indent), doc.syntax().text())
}

fn render_line_form(node: &SyntaxNode, indent: usize) -> String {
    let mut rendered = format!("{}{}", indent_string(indent), render_compact_tokens(node));
    if let Some(comment) = direct_comment_token(node) {
        append_inline_comment(&mut rendered, &comment);
    }
    rendered
}

fn render_import(import: &Import, indent: usize) -> String {
    let compact = format!("{}{}", indent_string(indent), render_compact_tokens(import.syntax()));
    let mut rendered = if line_length(&compact) <= MAX_LINE_WIDTH {
        compact
    } else {
        let Some(path) = import.path() else {
            return render_line_form(import.syntax(), indent);
        };

        let mut header = indent_string(indent);
        if import.visibility().is_some() {
            header.push_str("pub ");
        }
        header.push_str("use");

        let path_tokens = significant_tokens(path.syntax());
        let alias_tokens = significant_tokens_after_child(import.syntax(), path.syntax());
        let mut lines = render_path_lines(&header, &path_tokens, indent);
        if !alias_tokens.is_empty() {
            let alias = render_token_sequence(&alias_tokens);
            if let Some(last) = lines.last_mut() {
                if line_length(last) + 1 + line_length(&alias) <= MAX_LINE_WIDTH {
                    last.push(' ');
                    last.push_str(&alias);
                } else {
                    lines.push(format!("{}{}", indent_string(indent + INDENT_WIDTH), alias));
                }
            }
        }
        lines.join("\n")
    };

    if let Some(comment) = direct_comment_token(import.syntax()) {
        append_inline_comment(&mut rendered, &comment);
    }

    rendered
}

fn render_value_declaration(node: &SyntaxNode, indent: usize) -> String {
    let Some(value) = direct_child_of_kind(node, SyntaxKind::Expr) else {
        return render_line_form(node, indent);
    };

    let prefix_tokens = significant_tokens_before_child(node, &value);
    let value_tokens = significant_tokens(&value);

    let compact = format!(
        "{}{}",
        indent_string(indent),
        render_token_sequence(&combine_tokens(&prefix_tokens, &value_tokens))
    );

    let mut rendered = if line_length(&compact) <= MAX_LINE_WIDTH {
        compact
    } else {
        let header = format!("{}{}", indent_string(indent), render_token_sequence(&prefix_tokens));
        let body = render_token_lines(&value_tokens, indent + INDENT_WIDTH, true).join("\n");
        format!("{header}\n{body}")
    };

    if let Some(comment) = direct_comment_token(node) {
        append_inline_comment(&mut rendered, &comment);
    }

    rendered
}

fn render_type_decl(type_decl: &TypeDecl, indent: usize) -> String {
    let mut rendered = render_type_decl_prefix(type_decl, indent);

    if let Some(body) = type_decl.body() {
        rendered.push_str(&render_type_body(&body, indent, line_length(&rendered)));
    }

    if let Some(comment) = direct_comment_token(type_decl.syntax()) {
        append_inline_comment(&mut rendered, &comment);
    }

    rendered
}

fn render_type_decl_prefix(type_decl: &TypeDecl, indent: usize) -> String {
    let mut rendered = indent_string(indent);

    if type_decl.visibility().is_some() {
        rendered.push_str("pub ");
    }

    if let Some(keyword) = type_decl.keyword_token() {
        rendered.push_str(keyword.text());
    }

    if let Some(name) = type_decl.name_token() {
        rendered.push(' ');
        rendered.push_str(name.text());
    }

    rendered
}

fn render_type_body(body: &TypeBody, indent: usize, prefix_width: usize) -> String {
    let text = body.syntax().text().to_string();
    let has_multiline_body = text.contains('\n');
    let has_comment = body
        .syntax()
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .any(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment));

    let compact_body = render_compact_tokens(body.syntax());
    if !has_multiline_body
        && !has_comment
        && prefix_width + 1 + line_length(&compact_body) <= MAX_LINE_WIDTH
    {
        return format!(" {compact_body}");
    }

    if !has_multiline_body && !has_comment {
        if let Some(braced_body) = render_wrapped_braced_type_body(body, indent) {
            return braced_body;
        }
        return format!("\n{}{}", indent_string(indent + INDENT_WIDTH), compact_body);
    }

    let lines = trim_line_ends(&text);
    if lines.is_empty() {
        return String::new();
    }

    let mut rendered = String::new();
    rendered.push(' ');
    rendered.push_str(lines[0].trim());

    for line in lines.iter().skip(1) {
        rendered.push('\n');
        if line.trim().is_empty() {
            continue;
        }

        let trimmed = line.trim();
        let line_indent = if trimmed.starts_with('}') {
            indent
        } else {
            indent + INDENT_WIDTH
        };
        rendered.push_str(&indent_string(line_indent));
        rendered.push_str(trimmed);
    }

    rendered
}

fn render_begin_block(begin: &BeginBlock, indent: usize) -> String {
    let mut rendered = format!("{}begin", indent_string(indent));
    if let Some(block) = begin.block() {
        let body = render_block(&block, indent + INDENT_WIDTH);
        if !body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&body);
        }
    }
    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_procedure(procedure: &Procedure, indent: usize) -> String {
    let mut lines = Vec::new();

    for attribute in procedure.attributes() {
        lines.push(format!(
            "{}{}",
            indent_string(indent),
            render_compact_tokens(attribute.syntax())
        ));
    }

    let mut header = indent_string(indent);
    if procedure.visibility().is_some() {
        header.push_str("pub ");
    }
    header.push_str("proc");
    if let Some(name) = procedure.name_token() {
        header.push(' ');
        header.push_str(name.text());
    }
    if let Some(signature) = procedure.signature() {
        lines.extend(render_signature_lines(&header, &signature, indent));
    } else {
        lines.push(header);
    }

    if let Some(block) = procedure.block() {
        let body = render_block(&block, indent + INDENT_WIDTH);
        if !body.is_empty() {
            lines.extend(body.split('\n').map(ToOwned::to_owned));
        }
    }

    lines.push(format!("{}end", indent_string(indent)));
    lines.join("\n")
}

fn render_signature_lines(
    header_prefix: &str,
    signature: &Signature,
    indent: usize,
) -> Vec<String> {
    let compact_signature = render_token_sequence_with_style(
        &significant_tokens(signature.syntax()),
        SpacingStyle::TypeBodyItem,
    );
    let compact = format!("{header_prefix}{compact_signature}");
    if line_length(&compact) <= MAX_LINE_WIDTH {
        return vec![compact];
    }

    let tokens = significant_tokens(signature.syntax());
    let Some(params_close) = matching_group_end(&tokens, 0, SyntaxKind::LParen, SyntaxKind::RParen)
    else {
        return vec![compact];
    };

    let params = split_top_level_items(&tokens[1..params_close]);
    let result_tokens =
        if tokens.get(params_close + 1).map(SyntaxToken::kind) == Some(SyntaxKind::RArrow) {
            &tokens[(params_close + 2)..]
        } else {
            &tokens[0..0]
        };

    let mut lines = vec![format!("{header_prefix}(")];
    let param_count = params.len();
    for (index, param) in params.into_iter().enumerate() {
        if param.is_empty() {
            continue;
        }

        let mut param_lines = render_token_lines_with_style(
            &param,
            indent + INDENT_WIDTH,
            true,
            SpacingStyle::TypeBodyItem,
        );
        if index + 1 != param_count {
            if let Some(last_line) = param_lines.last_mut() {
                last_line.push(',');
            }
        }
        lines.extend(param_lines);
    }

    let mut closing = format!("{})", indent_string(indent));
    if result_tokens.is_empty() {
        lines.push(closing);
        return lines;
    }

    if let Some((open_index, close_index)) =
        outer_group_indices(result_tokens, SyntaxKind::LParen, SyntaxKind::RParen)
    {
        if open_index == 0 {
            let items = split_top_level_items(&result_tokens[1..close_index]);
            let result =
                render_token_sequence_with_style(result_tokens, SpacingStyle::TypeBodyItem);
            if items.len() <= 1
                && line_length(&closing) + 4 + line_length(&result) <= MAX_LINE_WIDTH
            {
                closing.push_str(" -> ");
                closing.push_str(&result);
                lines.push(closing);
                return lines;
            }

            closing.push_str(" -> (");
            lines.push(closing);

            let item_count = items.len();
            for (index, item) in items.into_iter().enumerate() {
                if item.is_empty() {
                    continue;
                }

                let mut item_lines = render_token_lines_with_style(
                    &item,
                    indent + INDENT_WIDTH,
                    true,
                    SpacingStyle::TypeBodyItem,
                );
                if index + 1 != item_count {
                    if let Some(last_line) = item_lines.last_mut() {
                        last_line.push(',');
                    }
                }
                lines.extend(item_lines);
            }

            lines.push(format!("{})", indent_string(indent)));
            return lines;
        }
    }

    let result = render_token_sequence_with_style(result_tokens, SpacingStyle::TypeBodyItem);
    if line_length(&closing) + 4 + line_length(&result) <= MAX_LINE_WIDTH {
        closing.push_str(" -> ");
        closing.push_str(&result);
        lines.push(closing);
        return lines;
    }

    closing.push_str(" ->");
    lines.push(closing);
    lines.extend(render_token_lines_with_style(
        result_tokens,
        indent + INDENT_WIDTH,
        true,
        SpacingStyle::TypeBodyItem,
    ));
    lines
}

fn render_block(block: &Block, indent: usize) -> String {
    let (entries, tail) = analyze_children(block.syntax());
    let mut lines = Vec::new();
    let mut current_instruction_line: Option<String> = None;

    for entry in entries {
        if entry.blank_lines_before > 0 || !entry.leading_comments.is_empty() {
            flush_instruction_line(&mut lines, &mut current_instruction_line);
        }

        emit_leading_layout(&mut lines, &entry, indent);

        let operation = Operation::cast(entry.node.clone()).expect("expected operation node");
        match operation {
            Operation::Instruction(instruction) => {
                render_instruction(
                    &mut lines,
                    &mut current_instruction_line,
                    &instruction,
                    &entry,
                    indent,
                );
            },
            Operation::If(if_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_if(&if_op, indent);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
            Operation::While(while_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_while(&while_op, indent);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
            Operation::Repeat(repeat_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_repeat(&repeat_op, indent);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
        }
    }

    flush_instruction_line(&mut lines, &mut current_instruction_line);
    emit_tail_layout(&mut lines, tail, indent);
    lines.join("\n")
}

fn render_instruction(
    lines: &mut Vec<String>,
    current_instruction_line: &mut Option<String>,
    instruction: &Instruction,
    entry: &NodeLayout,
    indent: usize,
) {
    let op_text = render_compact_tokens(instruction.syntax());
    let rendered_indent = indent_string(indent);

    let can_append = current_instruction_line.is_some()
        && entry.same_line_with_prev
        && entry.trailing_comment.is_none();

    if can_append {
        let line = current_instruction_line.as_mut().expect("line exists");
        let candidate_len = line.len() + 1 + op_text.len();
        if candidate_len <= MAX_LINE_WIDTH {
            line.push(' ');
            line.push_str(&op_text);
            return;
        }

        flush_instruction_line(lines, current_instruction_line);
    } else if current_instruction_line.is_some() {
        flush_instruction_line(lines, current_instruction_line);
    }

    let mut line = format!("{rendered_indent}{op_text}");
    if let Some(comment) = entry.trailing_comment.as_deref() {
        append_inline_comment(&mut line, comment);
        lines.push(line);
    } else {
        *current_instruction_line = Some(line);
    }
}

fn render_if(if_op: &IfOp, indent: usize) -> String {
    let mut rendered =
        format!("{}{}", indent_string(indent), render_prefix_before_first_block(if_op.syntax()));

    if let Some(then_block) = if_op.then_block() {
        let then_body = render_block(&then_block, indent + INDENT_WIDTH);
        if !then_body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&then_body);
        }
    }

    if let Some(else_block) = if_op.else_block() {
        rendered.push('\n');
        rendered.push_str(&format!("{}else", indent_string(indent)));
        let else_body = render_block(&else_block, indent + INDENT_WIDTH);
        if !else_body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&else_body);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_while(while_op: &WhileOp, indent: usize) -> String {
    let mut rendered = format!(
        "{}{}",
        indent_string(indent),
        render_prefix_before_first_block(while_op.syntax())
    );

    if let Some(body) = while_op.body() {
        let block = render_block(&body, indent + INDENT_WIDTH);
        if !block.is_empty() {
            rendered.push('\n');
            rendered.push_str(&block);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_repeat(repeat_op: &RepeatOp, indent: usize) -> String {
    let mut rendered = format!(
        "{}{}",
        indent_string(indent),
        render_prefix_before_first_block(repeat_op.syntax())
    );

    if let Some(body) = repeat_op.body() {
        let block = render_block(&body, indent + INDENT_WIDTH);
        if !block.is_empty() {
            rendered.push('\n');
            rendered.push_str(&block);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_prefix_before_first_block(node: &SyntaxNode) -> String {
    let mut tokens = Vec::new();
    for child in node.children_with_tokens() {
        match child {
            NodeOrToken::Node(child_node) if child_node.kind() == SyntaxKind::Block => break,
            NodeOrToken::Node(child_node) => tokens.extend(significant_tokens(&child_node)),
            NodeOrToken::Token(token) if !token.kind().is_trivia() => tokens.push(token),
            NodeOrToken::Token(_) => (),
        }
    }
    render_token_sequence(&tokens)
}

fn render_compact_tokens(node: &SyntaxNode) -> String {
    render_token_sequence(&significant_tokens(node))
}

fn render_wrapped_braced_type_body(body: &TypeBody, indent: usize) -> Option<String> {
    let tokens = significant_tokens(body.syntax());
    let (open_index, close_index) =
        outer_group_indices(&tokens, SyntaxKind::LBrace, SyntaxKind::RBrace)?;

    let prefix_tokens = &tokens[..=open_index];
    let suffix_tokens = &tokens[close_index..];
    let items = split_top_level_items(&tokens[(open_index + 1)..close_index]);

    let mut rendered = String::new();
    rendered.push(' ');
    rendered.push_str(&render_token_sequence(prefix_tokens));

    for item in items {
        if item.is_empty() {
            continue;
        }

        rendered.push('\n');
        rendered.push_str(&format!(
            "{}{},",
            indent_string(indent + INDENT_WIDTH),
            render_token_sequence_with_style(&item, SpacingStyle::TypeBodyItem)
        ));
    }

    rendered.push('\n');
    rendered.push_str(&indent_string(indent));
    rendered.push_str(&render_token_sequence(suffix_tokens));
    Some(rendered)
}

fn render_token_lines(
    tokens: &[SyntaxToken],
    indent: usize,
    prefer_multiline_groups: bool,
) -> Vec<String> {
    render_token_lines_with_style(tokens, indent, prefer_multiline_groups, SpacingStyle::Default)
}

fn render_token_lines_with_style(
    tokens: &[SyntaxToken],
    indent: usize,
    prefer_multiline_groups: bool,
    style: SpacingStyle,
) -> Vec<String> {
    if prefer_multiline_groups {
        if let Some((open_index, close_index)) =
            outer_group_indices(tokens, SyntaxKind::LBracket, SyntaxKind::RBracket)
        {
            return render_delimited_group(tokens, indent, open_index, close_index, style);
        }

        if let Some((open_index, close_index)) =
            outer_group_indices(tokens, SyntaxKind::LParen, SyntaxKind::RParen)
        {
            if open_index > 0 {
                return render_delimited_group(tokens, indent, open_index, close_index, style);
            }
        }
    }

    let compact = render_token_sequence_with_style(tokens, style);
    let inline = format!("{}{}", indent_string(indent), compact);
    if line_length(&inline) <= MAX_LINE_WIDTH {
        return vec![inline];
    }

    if let Some((open_index, close_index)) =
        outer_group_indices(tokens, SyntaxKind::LBracket, SyntaxKind::RBracket)
    {
        return render_delimited_group(tokens, indent, open_index, close_index, style);
    }

    if let Some((open_index, close_index)) =
        outer_group_indices(tokens, SyntaxKind::LParen, SyntaxKind::RParen)
    {
        if open_index > 0 {
            return render_delimited_group(tokens, indent, open_index, close_index, style);
        }
    }

    vec![inline]
}

fn render_delimited_group(
    tokens: &[SyntaxToken],
    indent: usize,
    open_index: usize,
    close_index: usize,
    style: SpacingStyle,
) -> Vec<String> {
    let opener = render_token_sequence(&tokens[..=open_index]);
    let closer = render_token_sequence(&tokens[close_index..]);
    let items = split_top_level_items(&tokens[(open_index + 1)..close_index]);
    let item_count = items.len();

    let mut lines = vec![format!("{}{}", indent_string(indent), opener)];
    for (index, item) in items.into_iter().enumerate() {
        if item.is_empty() {
            continue;
        }

        let mut item_lines =
            render_token_lines_with_style(&item, indent + INDENT_WIDTH, true, style);
        if index + 1 != item_count
            && let Some(last_line) = item_lines.last_mut()
        {
            last_line.push(',');
        }
        lines.extend(item_lines);
    }
    lines.push(format!("{}{}", indent_string(indent), closer));
    lines
}

fn render_token_sequence(tokens: &[SyntaxToken]) -> String {
    render_token_sequence_with_style(tokens, SpacingStyle::Default)
}

#[derive(Clone, Copy)]
enum SpacingStyle {
    Default,
    TypeBodyItem,
}

fn render_token_sequence_with_style(tokens: &[SyntaxToken], style: SpacingStyle) -> String {
    let mut rendered = String::new();
    let mut previous: Option<&SyntaxToken> = None;

    for token in tokens {
        if let Some(previous_token) = previous
            && needs_space(previous_token, token, style)
        {
            rendered.push(' ');
        }
        rendered.push_str(token.text());
        previous = Some(token);
    }

    rendered
}

fn render_path_lines(header: &str, path_tokens: &[SyntaxToken], indent: usize) -> Vec<String> {
    let pieces = split_path_pieces(path_tokens);
    let Some(first) = pieces.first() else {
        return vec![header.to_string()];
    };

    let mut lines = Vec::new();
    let mut current = format!("{header} {first}");
    for piece in pieces.iter().skip(1) {
        if line_length(&current) + line_length(piece) <= MAX_LINE_WIDTH {
            current.push_str(piece);
        } else {
            lines.push(current);
            current = format!("{}{}", indent_string(indent + INDENT_WIDTH), piece);
        }
    }
    lines.push(current);
    lines
}

fn significant_tokens(node: &SyntaxNode) -> Vec<SyntaxToken> {
    node.descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| {
            !token.kind().is_trivia()
                && !matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment)
        })
        .collect()
}

fn significant_tokens_before_child(node: &SyntaxNode, child: &SyntaxNode) -> Vec<SyntaxToken> {
    let mut tokens = Vec::new();

    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(candidate) if candidate == *child => break,
            NodeOrToken::Node(candidate) => tokens.extend(significant_tokens(&candidate)),
            NodeOrToken::Token(token)
                if !token.kind().is_trivia()
                    && !matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment) =>
            {
                tokens.push(token)
            },
            NodeOrToken::Token(_) => (),
        }
    }

    tokens
}

fn significant_tokens_after_child(node: &SyntaxNode, child: &SyntaxNode) -> Vec<SyntaxToken> {
    let mut tokens = Vec::new();
    let mut seen_child = false;

    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(candidate) if candidate == *child => seen_child = true,
            NodeOrToken::Node(candidate) if seen_child => {
                tokens.extend(significant_tokens(&candidate))
            },
            NodeOrToken::Node(_) => (),
            NodeOrToken::Token(token)
                if seen_child
                    && !token.kind().is_trivia()
                    && !matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment) =>
            {
                tokens.push(token)
            },
            NodeOrToken::Token(_) => (),
        }
    }

    tokens
}

fn direct_child_of_kind(node: &SyntaxNode, kind: SyntaxKind) -> Option<SyntaxNode> {
    node.children().find(|child| child.kind() == kind)
}

fn combine_tokens(prefix: &[SyntaxToken], suffix: &[SyntaxToken]) -> Vec<SyntaxToken> {
    prefix.iter().cloned().chain(suffix.iter().cloned()).collect()
}

fn outer_group_indices(
    tokens: &[SyntaxToken],
    open: SyntaxKind,
    close: SyntaxKind,
) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut open_index = None;
    for (index, token) in tokens.iter().enumerate() {
        match token.kind() {
            kind if kind == open => {
                if depth == 0 {
                    open_index = Some(index);
                }
                depth += 1;
            },
            kind if kind == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (index + 1 == tokens.len())
                        .then_some((open_index.expect("open index set at depth 0"), index));
                }
            },
            _ => (),
        }
    }

    None
}

fn matching_group_end(
    tokens: &[SyntaxToken],
    open_index: usize,
    open: SyntaxKind,
    close: SyntaxKind,
) -> Option<usize> {
    if tokens.get(open_index).map(SyntaxToken::kind) != Some(open) {
        return None;
    }

    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open_index) {
        match token.kind() {
            kind if kind == open => depth += 1,
            kind if kind == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            },
            _ => (),
        }
    }

    None
}

fn split_path_pieces(tokens: &[SyntaxToken]) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut current = String::new();

    for token in tokens {
        if token.kind() == SyntaxKind::ColonColon && !current.is_empty() {
            pieces.push(mem::take(&mut current));
        }

        current.push_str(token.text());
    }

    if !current.is_empty() {
        pieces.push(current);
    }

    pieces
}

fn split_top_level_items(tokens: &[SyntaxToken]) -> Vec<Vec<SyntaxToken>> {
    let mut items = Vec::new();
    let mut current = Vec::new();
    let mut angles = 0usize;
    let mut parens = 0usize;
    let mut brackets = 0usize;
    let mut braces = 0usize;

    for token in tokens {
        match token.kind() {
            SyntaxKind::LAngle => angles += 1,
            SyntaxKind::RAngle => angles = angles.saturating_sub(1),
            SyntaxKind::LParen => parens += 1,
            SyntaxKind::RParen => parens = parens.saturating_sub(1),
            SyntaxKind::LBracket => brackets += 1,
            SyntaxKind::RBracket => brackets = brackets.saturating_sub(1),
            SyntaxKind::LBrace => braces += 1,
            SyntaxKind::RBrace => braces = braces.saturating_sub(1),
            SyntaxKind::Comma if angles == 0 && parens == 0 && brackets == 0 && braces == 0 => {
                items.push(mem::take(&mut current));
                continue;
            },
            _ => (),
        }

        current.push(token.clone());
    }

    if !current.is_empty() {
        items.push(current);
    }

    items
}

fn direct_comment_token(node: &SyntaxNode) -> Option<String> {
    node.children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment))
        .map(|token| trimmed_comment(&token))
}

fn emit_leading_layout(lines: &mut Vec<String>, entry: &NodeLayout, indent: usize) {
    if entry.blank_lines_before > 0 && !lines.is_empty() {
        push_blank_line(lines);
    }

    for comment in &entry.leading_comments {
        lines.push(format!("{}{}", indent_string(indent), comment));
    }
}

fn emit_tail_layout(lines: &mut Vec<String>, tail: ContainerTail, indent: usize) {
    if tail.leading_comments.is_empty() {
        return;
    }

    if tail.blank_lines_before > 0 && !lines.is_empty() {
        push_blank_line(lines);
    }

    for comment in tail.leading_comments {
        lines.push(format!("{}{}", indent_string(indent), comment));
    }
}

fn flush_instruction_line(lines: &mut Vec<String>, current_instruction_line: &mut Option<String>) {
    if let Some(line) = current_instruction_line.take() {
        lines.push(line);
    }
}

fn extend_lines(lines: &mut Vec<String>, rendered: &str) {
    lines.extend(rendered.split('\n').map(ToOwned::to_owned));
}

fn finish_output(lines: Vec<String>) -> String {
    if lines.is_empty() {
        return String::new();
    }

    let mut rendered = lines.join("\n");
    rendered.push('\n');
    rendered
}

fn push_blank_line(lines: &mut Vec<String>) {
    if !matches!(lines.last(), Some(line) if line.is_empty()) {
        lines.push(String::new());
    }
}

fn append_inline_comment(rendered: &mut String, comment: &str) {
    if !rendered.ends_with([' ', '\n']) {
        rendered.push(' ');
    }
    rendered.push_str(comment);
}

fn indent_string(indent: usize) -> String {
    " ".repeat(indent)
}

fn line_length(text: &str) -> usize {
    text.chars().count()
}

fn trimmed_comment(token: &SyntaxToken) -> String {
    token.text().trim_end().to_string()
}

fn trim_line_ends(text: &str) -> Vec<String> {
    text.lines().map(|line| line.trim_end().to_string()).collect()
}

fn needs_space(previous: &SyntaxToken, next: &SyntaxToken, style: SpacingStyle) -> bool {
    use SyntaxKind::{
        At, Colon, ColonColon, Comma, Dot, DotDot, Equal, LAngle, LBrace, LBracket, LParen, Minus,
        Plus, RAngle, RArrow, RBrace, RBracket, RParen, Slash, SlashSlash, Star,
    };

    let previous_kind = previous.kind();
    let next_kind = next.kind();

    if previous_kind == At {
        return false;
    }

    if matches!(previous_kind, Dot | ColonColon | LAngle | LParen | LBracket | LBrace) {
        return false;
    }

    if matches!(
        next_kind,
        Dot | ColonColon | DotDot | Comma | LAngle | RAngle | RParen | RBracket | RBrace
    ) {
        return false;
    }

    if next_kind == LParen {
        return false;
    }

    if matches!(style, SpacingStyle::TypeBodyItem) && next_kind == Colon {
        return false;
    }

    if previous_kind == DotDot {
        return false;
    }

    if matches!(
        previous_kind,
        Comma | Equal | RArrow | Colon | Plus | Minus | Star | Slash | SlashSlash
    ) {
        return true;
    }

    if matches!(next_kind, Equal | RArrow | Colon | Plus | Minus | Star | Slash | SlashSlash) {
        return true;
    }

    if next_kind == LBrace {
        return true;
    }

    true
}

#[cfg(test)]
mod tests {
    use miden_assembly_syntax_cst::parse_text;

    use super::{MAX_LINE_WIDTH, format_syntax};

    #[test]
    fn formats_top_level_forms_and_anchors_comments() {
        let source = "\
#! docs
pub   use   miden::core::mem  ->  memory

# const comment
pub const EVENT=event(\"miden::event\")
adv_map   TABLE=[0x01,0x02]
begin
 swap  dup.1 add
 # branch
 if.true
  nop
 else
  mul
 end
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let formatted = format_syntax(&parse.syntax());
        let expected = "\
#! docs
pub use miden::core::mem -> memory

# const comment
pub const EVENT = event(\"miden::event\")
adv_map TABLE = [0x01, 0x02]
begin
    swap dup.1 add
    # branch
    if.true
        nop
    else
        mul
    end
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn breaks_grouped_instruction_lines_when_they_overflow() {
        let source = "\
begin
    instruction_alpha_one instruction_beta_two instruction_gamma_three instruction_delta_four
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let formatted = format_syntax(&parse.syntax());
        let body_lines =
            formatted.lines().skip(1).take_while(|line| *line != "end").collect::<Vec<_>>();

        assert!(
            body_lines.len() >= 2,
            "expected at least two formatted body lines, got {body_lines:?}"
        );
        assert!(body_lines.iter().all(|line| line.len() <= MAX_LINE_WIDTH));
        assert!(formatted.contains("\n    instruction_delta_four\n"));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn wraps_long_constants_and_advice_maps() {
        let source = "\
const VERY_LONG_EVENT = event(\"miden::core::collections::sorted_array::lowerbound_key_value\")
adv_map CIRCUIT_COMMITMENT = [1, 0, 0, 0, 2305843126251553075, 114890375379, 2305843283017859381]
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let formatted = format_syntax(&parse.syntax());
        let expected = "\
const VERY_LONG_EVENT =
    event(
        \"miden::core::collections::sorted_array::lowerbound_key_value\"
    )
adv_map CIRCUIT_COMMITMENT =
    [
        1,
        0,
        0,
        0,
        2305843126251553075,
        114890375379,
        2305843283017859381
    ]
";

        assert_eq!(formatted, expected);
        assert!(formatted.lines().all(|line| line.len() <= MAX_LINE_WIDTH));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn wraps_long_type_bodies_and_normalizes_multiline_body_comments() {
        let source = "\
pub type VeryLongTypeName = struct { lower_bound_key_value: u128, upper_bound_key_value: u128 }

enum Status : u16 {
# ready
READY,
# waiting
WAITING = 2,
}
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let formatted = format_syntax(&parse.syntax());
        let expected = "\
pub type VeryLongTypeName = struct {
    lower_bound_key_value: u128,
    upper_bound_key_value: u128,
}

enum Status : u16 {
    # ready
    READY,
    # waiting
    WAITING = 2,
}
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn wraps_long_imports_and_procedure_headers_without_mangling_generic_types() {
        let source = "\
pub use ::miden::core::collections::sorted_array::lowerbound_key_value -> lowerbound_key_value

pub proc println_debug_message_with_context(message: ptr<u8, addrspace(byte)>, context: ptr<u8, addrspace(byte)>) -> (result: ptr<u8, addrspace(byte)>, status: i1)
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let formatted = format_syntax(&parse.syntax());
        let expected = "\
pub use ::miden::core::collections::sorted_array::lowerbound_key_value
    -> lowerbound_key_value

pub proc println_debug_message_with_context(
    message: ptr<u8, addrspace(byte)>,
    context: ptr<u8, addrspace(byte)>
) -> (
    result: ptr<u8, addrspace(byte)>,
    status: i1
)
    nop
end
";

        assert_eq!(formatted, expected);
        assert!(formatted.lines().all(|line| line.len() <= MAX_LINE_WIDTH));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }
}
