use std::mem;

use miden_assembly_syntax_cst::{
    Item, Operation, SyntaxKind, SyntaxNode, SyntaxToken,
    ast::{
        BeginBlock, Block, DoWhileOp, IfOp, Import, ImportKind, ImportSpecifier, Instruction,
        Procedure, RepeatOp, Signature, SourceFile, TypeBody, TypeDecl, WhileOp,
    },
    rowan::{NodeOrToken, ast::AstNode},
};

use crate::config::Config;

pub fn format_syntax(config: &Config, root: &SyntaxNode) -> String {
    let source = SourceFile::cast(root.clone()).expect("expected source file root");
    let mut lines = Vec::new();
    let (entries, tail) = analyze_children(source.syntax());

    for entry in entries {
        emit_leading_layout(&mut lines, &entry, 0);

        let item = Item::cast(entry.node).expect("expected top-level item");
        let mut rendered = render_item(&item, 0, config);
        if let Some(comment) = entry.trailing_comment {
            append_inline_comment(&mut rendered, &comment);
        }
        extend_lines(&mut lines, &rendered);
        emit_trailing_comments(&mut lines, &entry.trailing_comments, 0);
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
    trailing_comments: Vec<String>,
}

#[derive(Debug, Default)]
struct ContainerTail {
    blank_lines_before: usize,
    leading_comments: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum IntersticeState {
    SameLineAfterNode,
    StartOfLineAfterNode,
    StartOfLine,
    AfterLeadingComment,
    AfterTrailingComment,
}

#[derive(Debug)]
struct Interstice {
    state: IntersticeState,
    same_line_with_prev: bool,
    blank_lines: usize,
    leading_comments: Vec<String>,
    trailing_comment: Option<String>,
    trailing_comments: Vec<String>,
}

impl Interstice {
    fn start_of_container() -> Self {
        Self {
            state: IntersticeState::StartOfLine,
            same_line_with_prev: false,
            blank_lines: 0,
            leading_comments: Vec::new(),
            trailing_comment: None,
            trailing_comments: Vec::new(),
        }
    }

    fn after_node() -> Self {
        Self {
            state: IntersticeState::SameLineAfterNode,
            same_line_with_prev: true,
            blank_lines: 0,
            leading_comments: Vec::new(),
            trailing_comment: None,
            trailing_comments: Vec::new(),
        }
    }

    fn consume(&mut self, token: &SyntaxToken) {
        match token.kind() {
            SyntaxKind::Whitespace => (),
            SyntaxKind::Newline => match self.state {
                IntersticeState::SameLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.state = IntersticeState::StartOfLineAfterNode;
                },
                IntersticeState::StartOfLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.blank_lines += 1;
                    self.state = IntersticeState::StartOfLine;
                },
                IntersticeState::StartOfLine => {
                    self.same_line_with_prev = false;
                    self.blank_lines += 1;
                },
                IntersticeState::AfterLeadingComment => {
                    self.state = IntersticeState::StartOfLine;
                },
                IntersticeState::AfterTrailingComment => {
                    self.state = IntersticeState::StartOfLineAfterNode;
                },
            },
            SyntaxKind::Comment | SyntaxKind::DocComment => match self.state {
                IntersticeState::SameLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.trailing_comment = Some(trimmed_comment(token));
                    self.state = IntersticeState::AfterTrailingComment;
                },
                IntersticeState::StartOfLineAfterNode => {
                    self.same_line_with_prev = false;
                    self.trailing_comments.push(trimmed_comment(token));
                    self.state = IntersticeState::AfterTrailingComment;
                },
                IntersticeState::StartOfLine => {
                    self.same_line_with_prev = false;
                    self.leading_comments.push(trimmed_comment(token));
                    self.state = IntersticeState::AfterLeadingComment;
                },
                IntersticeState::AfterLeadingComment | IntersticeState::AfterTrailingComment => (),
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
                    previous.trailing_comments = mem::take(&mut interstice.trailing_comments);
                }

                entries.push(NodeLayout {
                    node,
                    same_line_with_prev: !entries.is_empty() && interstice.same_line_with_prev,
                    blank_lines_before: interstice.blank_lines.min(1),
                    leading_comments: mem::take(&mut interstice.leading_comments),
                    trailing_comment: None,
                    trailing_comments: Vec::new(),
                });
                interstice = Interstice::after_node();
            },
            NodeOrToken::Token(token) => interstice.consume(&token),
        }
    }

    if let Some(previous) = entries.last_mut() {
        previous.trailing_comment = interstice.trailing_comment.take();
        previous.trailing_comments = mem::take(&mut interstice.trailing_comments);
    }

    (
        entries,
        ContainerTail {
            blank_lines_before: interstice.blank_lines.min(1),
            leading_comments: interstice.leading_comments,
        },
    )
}

fn render_item(item: &Item, indent: usize, config: &Config) -> String {
    match item {
        Item::Doc(doc) => render_doc(doc, indent),
        Item::Namespace(namespace) => render_line_form(namespace.syntax(), indent),
        Item::ExternPackage(package) => render_line_form(package.syntax(), indent),
        Item::Submodule(submodule) => render_line_form(submodule.syntax(), indent),
        Item::Import(import) => render_import(import, indent, config),
        Item::Constant(constant) => render_value_declaration(constant.syntax(), indent, config),
        Item::TypeDecl(type_decl) => render_type_decl(type_decl, indent, config),
        Item::AdviceMap(advice_map) => {
            render_value_declaration(advice_map.syntax(), indent, config)
        },
        Item::BeginBlock(begin) => render_begin_block(begin, indent, config),
        Item::Procedure(procedure) => render_procedure(procedure, indent, config),
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

fn render_import(import: &Import, indent: usize, config: &Config) -> String {
    let Some(path) = import.module_path() else {
        return render_line_form(import.syntax(), indent);
    };

    let mut header = indent_string(indent);
    if import.visibility().is_some() {
        header.push_str("pub ");
    }
    header.push_str("use");

    let path = render_token_sequence(&significant_tokens(path.syntax()));
    let mut lines = match import.kind() {
        ImportKind::Module => render_module_import_lines(import, header, path, indent, config),
        ImportKind::Items => render_item_import_lines(import, header, path, indent, config),
    };

    let mut rendered = if lines.len() == 1 && line_length(&lines[0]) <= config.max_line_length() {
        lines.remove(0)
    } else {
        lines.join("\n")
    };

    if let Some(comment) = direct_comment_token(import.syntax()) {
        append_inline_comment(&mut rendered, &comment);
    }

    rendered
}

fn render_module_import_lines(
    import: &Import,
    header: String,
    path: String,
    indent: usize,
    config: &Config,
) -> Vec<String> {
    let mut line = format!("{header} {path}");
    let Some(alias) = import.module_alias_token().map(render_single_token) else {
        return vec![line];
    };

    let alias = format!("as {alias}");
    if line_length(&line) + 1 + line_length(&alias) <= config.max_line_length() {
        line.push(' ');
        line.push_str(&alias);
        vec![line]
    } else {
        vec![line, format!("{}{}", indent_string(indent + config.indent_size()), alias)]
    }
}

fn render_item_import_lines(
    import: &Import,
    header: String,
    path: String,
    indent: usize,
    config: &Config,
) -> Vec<String> {
    if let Some(import_list) = import.import_list()
        && has_comment_token(import_list.syntax())
    {
        return render_commented_item_import_lines(
            import_list.syntax(),
            header,
            path,
            indent,
            config,
        );
    }

    let specs = import.item_specs().map(render_import_specifier).collect::<Vec<_>>().join(", ");
    let items = format!("{{{specs}}}");
    let from = format!("from {path}");
    let line = format!("{header} {items} {from}");

    if line_length(&line) <= config.max_line_length() {
        vec![line]
    } else {
        vec![
            format!("{header} {items}"),
            format!("{}{}", indent_string(indent + config.indent_size()), from),
        ]
    }
}

fn render_commented_item_import_lines(
    import_list: &SyntaxNode,
    header: String,
    path: String,
    indent: usize,
    config: &Config,
) -> Vec<String> {
    let mut list_lines = render_token_stream_with_comments(
        &all_tokens(import_list),
        indent,
        SpacingStyle::Default,
        config,
    );
    let Some(first_line) = list_lines.first_mut() else {
        return vec![format!("{header} {{}} from {path}")];
    };
    *first_line = format!("{header} {}", first_line.trim_start());

    let from = format!("from {path}");
    match list_lines.last_mut() {
        Some(last_line)
            if last_line.trim_start().starts_with('}')
                && line_length(last_line) + 1 + line_length(&from) <= config.max_line_length() =>
        {
            last_line.push(' ');
            last_line.push_str(&from);
        },
        _ => list_lines.push(format!("{}{}", indent_string(indent + config.indent_size()), from)),
    }

    list_lines
}

fn render_import_specifier(spec: ImportSpecifier) -> String {
    let Some(name) = spec.name_token().map(render_single_token) else {
        return render_compact_tokens(spec.syntax());
    };

    match spec.alias_token().map(render_single_token) {
        Some(alias) => format!("{name} as {alias}"),
        None => name,
    }
}

fn render_single_token(token: SyntaxToken) -> String {
    render_token_sequence(&[token])
}

fn render_value_declaration(node: &SyntaxNode, indent: usize, config: &Config) -> String {
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

    let mut rendered = if has_comment_token(&value) {
        let header = format!("{}{}", indent_string(indent), render_token_sequence(&prefix_tokens));
        let body = render_expression_with_comments(&value, indent + config.indent_size(), config)
            .join("\n");
        format!("{header}\n{body}")
    } else if line_length(&compact) <= config.max_line_length() {
        compact
    } else {
        let header = format!("{}{}", indent_string(indent), render_token_sequence(&prefix_tokens));
        let body = render_token_lines(&value_tokens, indent + config.indent_size(), true, config)
            .join("\n");
        format!("{header}\n{body}")
    };

    if let Some(comment) = direct_comment_token(node) {
        append_inline_comment(&mut rendered, &comment);
    }

    rendered
}

fn render_type_decl(type_decl: &TypeDecl, indent: usize, config: &Config) -> String {
    let mut rendered = render_type_decl_prefix(type_decl, indent);

    if let Some(body) = type_decl.body() {
        rendered.push_str(&render_type_body(&body, indent, line_length(&rendered), config));
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

fn render_type_body(
    body: &TypeBody,
    indent: usize,
    prefix_width: usize,
    config: &Config,
) -> String {
    let text = body.syntax().text().to_string();
    let has_multiline_body = text.contains('\n');
    let has_comment = body
        .syntax()
        .descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .any(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment));

    let compact_body = render_inline_type_body(body);
    if !has_multiline_body
        && !has_comment
        && prefix_width + 1 + line_length(&compact_body) <= config.max_line_length()
    {
        return format!(" {compact_body}");
    }

    if !has_multiline_body && !has_comment {
        if let Some(braced_body) = render_wrapped_braced_type_body(body, indent, config) {
            return braced_body;
        }
        return format!("\n{}{}", indent_string(indent + config.indent_size()), compact_body);
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
            indent + config.indent_size()
        };
        rendered.push_str(&indent_string(line_indent));
        rendered.push_str(trimmed);
    }

    rendered
}

fn render_begin_block(begin: &BeginBlock, indent: usize, config: &Config) -> String {
    let mut rendered = format!("{}begin", indent_string(indent));
    if let Some(comment) = comment_before_child_of_kind(begin.syntax(), SyntaxKind::Block, 0) {
        append_inline_comment(&mut rendered, &comment);
    }
    if let Some(block) = begin.block() {
        let body = render_block(&block, indent + config.indent_size(), config);
        if !body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&body);
        }
    }
    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_procedure(procedure: &Procedure, indent: usize, config: &Config) -> String {
    let mut lines = render_procedure_attribute_prologue(procedure, indent);

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
        lines.extend(render_signature_lines(&header, &signature, indent, config));
    } else {
        lines.push(header);
    }
    if let Some(comment) = comment_before_child_of_kind(procedure.syntax(), SyntaxKind::Block, 0)
        && let Some(last_line) = lines.last_mut()
    {
        append_inline_comment(last_line, &comment);
    }

    let body_comments =
        standalone_comments_before_child_of_kind(procedure.syntax(), SyntaxKind::Block, 0);
    if !body_comments.is_empty() {
        lines.extend(
            body_comments.into_iter().map(|comment| {
                format!("{}{}", indent_string(indent + config.indent_size()), comment)
            }),
        );
    }

    if let Some(block) = procedure.block() {
        let body = render_block(&block, indent + config.indent_size(), config);
        if !body.is_empty() {
            lines.extend(body.split('\n').map(ToOwned::to_owned));
        }
    }

    lines.push(format!("{}end", indent_string(indent)));
    lines.join("\n")
}

fn render_procedure_attribute_prologue(procedure: &Procedure, indent: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut inline_comment_target = None;
    let mut same_line = false;

    for element in procedure.syntax().children_with_tokens() {
        match element {
            NodeOrToken::Node(child) if child.kind() == SyntaxKind::Attribute => {
                lines.push(format!("{}{}", indent_string(indent), render_compact_tokens(&child)));
                inline_comment_target = Some(lines.len() - 1);
                same_line = true;
            },
            NodeOrToken::Node(child)
                if matches!(
                    child.kind(),
                    SyntaxKind::Visibility | SyntaxKind::Signature | SyntaxKind::Block
                ) =>
            {
                break;
            },
            NodeOrToken::Node(_) => {
                inline_comment_target = None;
                same_line = false;
            },
            NodeOrToken::Token(token) => match token.kind() {
                SyntaxKind::Comment | SyntaxKind::DocComment => {
                    let comment = trimmed_comment(&token);
                    if same_line && let Some(target) = inline_comment_target {
                        append_inline_comment(&mut lines[target], &comment);
                    } else {
                        lines.push(format!("{}{}", indent_string(indent), comment));
                    }
                    inline_comment_target = Some(lines.len() - 1);
                    same_line = true;
                },
                SyntaxKind::Whitespace => {},
                SyntaxKind::Newline => {
                    inline_comment_target = None;
                    same_line = false;
                },
                SyntaxKind::Ident if token.text() == "proc" => break,
                kind if !kind.is_trivia() => break,
                _ => {},
            },
        }
    }

    lines
}

fn render_signature_lines(
    header_prefix: &str,
    signature: &Signature,
    indent: usize,
    config: &Config,
) -> Vec<String> {
    let has_comments = has_comment_tokens(&all_tokens(signature.syntax()));
    let compact_signature = (!has_comments).then(|| {
        render_token_sequence_with_style(
            &significant_tokens(signature.syntax()),
            SpacingStyle::TypeBodyItem,
        )
    });
    if let Some(compact_signature) = compact_signature.as_ref() {
        let compact = format!("{header_prefix}{compact_signature}");
        if line_length(&compact) <= config.max_line_length() {
            return vec![compact];
        }
    }

    let tokens = if has_comments {
        trim_outer_whitespace_tokens(&all_tokens(signature.syntax()))
    } else {
        significant_tokens(signature.syntax())
    };
    let Some(params_open) = tokens.iter().position(|token| token.kind() == SyntaxKind::LParen)
    else {
        return compact_signature
            .map(|signature| vec![format!("{header_prefix}{signature}")])
            .unwrap_or_else(|| vec![header_prefix.to_string()]);
    };
    let Some(params_close) =
        matching_group_end(&tokens, params_open, SyntaxKind::LParen, SyntaxKind::RParen)
    else {
        return compact_signature
            .map(|signature| vec![format!("{header_prefix}{signature}")])
            .unwrap_or_else(|| vec![header_prefix.to_string()]);
    };

    let params = split_top_level_items(&tokens[(params_open + 1)..params_close])
        .into_iter()
        .map(|item| trim_outer_whitespace_tokens(&item))
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    let result_tokens = result_tokens_after_params(&tokens, params_close);

    let mut lines = vec![format!("{header_prefix}(")];
    let param_count = params.len();
    for (index, param) in params.into_iter().enumerate() {
        let mut param_lines =
            render_signature_item_lines(&param, indent + config.indent_size(), config);
        if index + 1 != param_count
            && let Some(last_line) = param_lines.last_mut()
        {
            last_line.push(',');
        }
        lines.extend(param_lines);
    }

    let mut closing = format!("{})", indent_string(indent));
    if result_tokens.is_empty() {
        lines.push(closing);
        return lines;
    }

    let result_has_comments = has_comment_tokens(&result_tokens);

    if let Some((open_index, close_index)) =
        outer_group_indices(&result_tokens, SyntaxKind::LParen, SyntaxKind::RParen)
        && open_index == 0
    {
        let items = split_top_level_items(&result_tokens[1..close_index])
            .into_iter()
            .map(|item| trim_outer_whitespace_tokens(&item))
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>();
        let result = render_token_sequence_with_style(&result_tokens, SpacingStyle::TypeBodyItem);
        if items.len() <= 1
            && !result_has_comments
            && line_length(&closing) + 4 + line_length(&result) <= config.max_line_length()
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
            let mut item_lines =
                render_signature_item_lines(&item, indent + config.indent_size(), config);
            if index + 1 != item_count
                && let Some(last_line) = item_lines.last_mut()
            {
                last_line.push(',');
            }
            lines.extend(item_lines);
        }

        lines.push(format!("{})", indent_string(indent)));
        return lines;
    }

    let result = render_token_sequence_with_style(&result_tokens, SpacingStyle::TypeBodyItem);
    if !result_has_comments
        && line_length(&closing) + 4 + line_length(&result) <= config.max_line_length()
    {
        closing.push_str(" -> ");
        closing.push_str(&result);
        lines.push(closing);
        return lines;
    }

    closing.push_str(" ->");
    lines.push(closing);
    lines.extend(render_signature_item_lines(
        &result_tokens,
        indent + config.indent_size(),
        config,
    ));
    lines
}

fn render_block(block: &Block, indent: usize, config: &Config) -> String {
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
                    config,
                );
            },
            Operation::If(if_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_if(&if_op, indent, config);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
            Operation::While(while_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_while(&while_op, indent, config);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
            Operation::DoWhile(do_while_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_do_while(&do_while_op, indent, config);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
            Operation::Repeat(repeat_op) => {
                flush_instruction_line(&mut lines, &mut current_instruction_line);
                let mut rendered = render_repeat(&repeat_op, indent, config);
                if let Some(comment) = entry.trailing_comment {
                    append_inline_comment(&mut rendered, &comment);
                }
                extend_lines(&mut lines, &rendered);
            },
        }

        if !entry.trailing_comments.is_empty() {
            flush_instruction_line(&mut lines, &mut current_instruction_line);
            emit_trailing_comments(&mut lines, &entry.trailing_comments, indent);
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
    config: &Config,
) {
    let tokens = all_tokens(instruction.syntax());
    if has_comment_tokens(&tokens) {
        flush_instruction_line(lines, current_instruction_line);

        let mut rendered_lines = render_token_stream_with_comments(
            &tokens,
            indent,
            SpacingStyle::CompactInstruction,
            config,
        );
        if let Some(comment) = entry.trailing_comment.as_deref()
            && let Some(last_line) = rendered_lines.last_mut()
        {
            append_inline_comment(last_line, comment);
        }

        lines.extend(rendered_lines);
        return;
    }

    let op_text = render_instruction_tokens(instruction.syntax());
    let rendered_indent = indent_string(indent);

    let can_append = current_instruction_line.is_some()
        && entry.same_line_with_prev
        && entry.trailing_comment.is_none();

    if can_append {
        let line = current_instruction_line.as_mut().expect("line exists");
        let candidate_len = line.len() + 1 + op_text.len();
        if candidate_len <= config.max_line_length() {
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

fn render_if(if_op: &IfOp, indent: usize, config: &Config) -> String {
    let mut rendered =
        format!("{}{}", indent_string(indent), render_prefix_before_first_block(if_op.syntax()));
    if let Some(comment) = comment_before_child_of_kind(if_op.syntax(), SyntaxKind::Block, 0) {
        append_inline_comment(&mut rendered, &comment);
    }

    if let Some(then_block) = if_op.then_block() {
        let then_body = render_block(&then_block, indent + config.indent_size(), config);
        if !then_body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&then_body);
        }
    }

    if let Some(else_block) = if_op.else_block() {
        rendered.push('\n');
        let mut else_line = format!("{}else", indent_string(indent));
        if let Some(comment) = comment_before_child_of_kind(if_op.syntax(), SyntaxKind::Block, 1) {
            append_inline_comment(&mut else_line, &comment);
        }
        rendered.push_str(&else_line);
        let else_body = render_block(&else_block, indent + config.indent_size(), config);
        if !else_body.is_empty() {
            rendered.push('\n');
            rendered.push_str(&else_body);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_while(while_op: &WhileOp, indent: usize, config: &Config) -> String {
    let mut rendered = format!(
        "{}{}",
        indent_string(indent),
        render_prefix_before_first_block(while_op.syntax())
    );
    if let Some(comment) = comment_before_child_of_kind(while_op.syntax(), SyntaxKind::Block, 0) {
        append_inline_comment(&mut rendered, &comment);
    }

    if let Some(body) = while_op.body() {
        let block = render_block(&body, indent + config.indent_size(), config);
        if !block.is_empty() {
            rendered.push('\n');
            rendered.push_str(&block);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_do_while(do_while_op: &DoWhileOp, indent: usize, config: &Config) -> String {
    // Render the `do` keyword (everything before the first block).
    let mut rendered = format!(
        "{}{}",
        indent_string(indent),
        render_prefix_before_first_block(do_while_op.syntax())
    );
    if let Some(comment) = comment_before_child_of_kind(do_while_op.syntax(), SyntaxKind::Block, 0)
    {
        append_inline_comment(&mut rendered, &comment);
    }

    if let Some(body) = do_while_op.body() {
        let block = render_block(&body, indent + config.indent_size(), config);
        if !block.is_empty() {
            rendered.push('\n');
            rendered.push_str(&block);
        }
    }

    // Render the `while` keyword that introduces the condition block.
    rendered.push('\n');
    rendered.push_str(&format!("{}while", indent_string(indent)));
    if let Some(comment) = comment_before_child_of_kind(do_while_op.syntax(), SyntaxKind::Block, 1)
    {
        append_inline_comment(&mut rendered, &comment);
    }

    if let Some(condition) = do_while_op.condition() {
        let block = render_block(&condition, indent + config.indent_size(), config);
        if !block.is_empty() {
            rendered.push('\n');
            rendered.push_str(&block);
        }
    }

    rendered.push('\n');
    rendered.push_str(&format!("{}end", indent_string(indent)));
    rendered
}

fn render_repeat(repeat_op: &RepeatOp, indent: usize, config: &Config) -> String {
    let mut rendered = format!(
        "{}{}",
        indent_string(indent),
        render_prefix_before_first_block(repeat_op.syntax())
    );
    if let Some(comment) = comment_before_child_of_kind(repeat_op.syntax(), SyntaxKind::Block, 0) {
        append_inline_comment(&mut rendered, &comment);
    }

    if let Some(body) = repeat_op.body() {
        let block = render_block(&body, indent + config.indent_size(), config);
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

fn render_wrapped_braced_type_body(
    body: &TypeBody,
    indent: usize,
    config: &Config,
) -> Option<String> {
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
            indent_string(indent + config.indent_size()),
            render_token_sequence_with_style(&item, SpacingStyle::TypeBodyItem)
        ));
    }

    rendered.push('\n');
    rendered.push_str(&indent_string(indent));
    rendered.push_str(&render_token_sequence(suffix_tokens));
    Some(rendered)
}

fn render_inline_type_body(body: &TypeBody) -> String {
    let tokens = significant_tokens(body.syntax());
    let Some((open_index, close_index)) =
        outer_group_indices(&tokens, SyntaxKind::LBrace, SyntaxKind::RBrace)
    else {
        return render_token_sequence(&tokens);
    };

    let prefix = render_token_sequence(&tokens[..=open_index]);
    let suffix = render_token_sequence(&tokens[close_index..]);
    let items = split_top_level_items(&tokens[(open_index + 1)..close_index])
        .into_iter()
        .map(|item| trim_outer_whitespace_tokens(&item))
        .filter(|item| !item.is_empty())
        .map(|item| render_token_sequence_with_style(&item, SpacingStyle::TypeBodyItem))
        .collect::<Vec<_>>();

    if items.is_empty() {
        format!("{prefix}{suffix}")
    } else {
        format!("{prefix} {} {suffix}", items.join(", "))
    }
}

fn render_token_lines(
    tokens: &[SyntaxToken],
    indent: usize,
    prefer_multiline_groups: bool,
    config: &Config,
) -> Vec<String> {
    render_token_lines_with_style(
        tokens,
        indent,
        prefer_multiline_groups,
        SpacingStyle::Default,
        config,
    )
}

fn render_token_lines_with_style(
    tokens: &[SyntaxToken],
    indent: usize,
    prefer_multiline_groups: bool,
    style: SpacingStyle,
    config: &Config,
) -> Vec<String> {
    if prefer_multiline_groups {
        if let Some((open_index, close_index)) =
            outer_group_indices(tokens, SyntaxKind::LBracket, SyntaxKind::RBracket)
        {
            return render_delimited_group(tokens, indent, open_index, close_index, style, config);
        }

        if let Some((open_index, close_index)) =
            outer_group_indices(tokens, SyntaxKind::LParen, SyntaxKind::RParen)
            && open_index > 0
        {
            return render_delimited_group(tokens, indent, open_index, close_index, style, config);
        }
    }

    let compact = render_token_sequence_with_style(tokens, style);
    let inline = format!("{}{}", indent_string(indent), compact);
    if line_length(&inline) <= config.max_line_length() {
        return vec![inline];
    }

    if let Some((open_index, close_index)) =
        outer_group_indices(tokens, SyntaxKind::LBracket, SyntaxKind::RBracket)
    {
        return render_delimited_group(tokens, indent, open_index, close_index, style, config);
    }

    if let Some((open_index, close_index)) =
        outer_group_indices(tokens, SyntaxKind::LParen, SyntaxKind::RParen)
    {
        return render_delimited_group(tokens, indent, open_index, close_index, style, config);
    }

    vec![inline]
}

fn render_delimited_group(
    tokens: &[SyntaxToken],
    indent: usize,
    open_index: usize,
    close_index: usize,
    style: SpacingStyle,
    config: &Config,
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

        let mut item_lines = render_token_lines_with_style(
            &item,
            indent + config.indent_size(),
            true,
            style,
            config,
        );
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

fn render_expression_with_comments(
    expr: &SyntaxNode,
    indent: usize,
    config: &Config,
) -> Vec<String> {
    render_token_stream_with_comments(&all_tokens(expr), indent, SpacingStyle::Default, config)
}

fn render_token_stream_with_comments(
    tokens: &[SyntaxToken],
    indent: usize,
    style: SpacingStyle,
    config: &Config,
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut previous: Option<SyntaxToken> = None;
    let mut nesting = LineNesting::default();
    let mut pending_blank_lines = 0usize;
    let mut just_flushed_line = false;

    for token in tokens {
        match token.kind() {
            SyntaxKind::Whitespace => (),
            SyntaxKind::Newline => {
                if just_flushed_line {
                    just_flushed_line = false;
                    continue;
                }

                if !current.is_empty() {
                    lines.push(mem::take(&mut current));
                    previous = None;
                    just_flushed_line = true;
                } else {
                    pending_blank_lines += 1;
                }
            },
            SyntaxKind::Comment | SyntaxKind::DocComment => {
                while pending_blank_lines > 0 {
                    push_blank_line(&mut lines);
                    pending_blank_lines -= 1;
                }

                if current.is_empty() {
                    current.push_str(&indent_string(
                        indent + nesting.line_indent_offset(token.kind()) * config.indent_size(),
                    ));
                    current.push_str(&trimmed_comment(token));
                } else {
                    append_inline_comment(&mut current, &trimmed_comment(token));
                }

                lines.push(mem::take(&mut current));
                previous = None;
                just_flushed_line = true;
            },
            _ => {
                while pending_blank_lines > 0 {
                    push_blank_line(&mut lines);
                    pending_blank_lines -= 1;
                }
                just_flushed_line = false;

                if current.is_empty() {
                    current.push_str(&indent_string(
                        indent + nesting.line_indent_offset(token.kind()) * config.indent_size(),
                    ));
                }

                if let Some(previous_token) = previous.as_ref()
                    && needs_space(previous_token, token, style)
                {
                    current.push(' ');
                }

                current.push_str(token.text());
                previous = Some(token.clone());
                nesting.bump(token.kind());
            },
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

fn render_token_sequence(tokens: &[SyntaxToken]) -> String {
    render_token_sequence_with_style(tokens, SpacingStyle::Default)
}

fn render_instruction_tokens(node: &SyntaxNode) -> String {
    render_token_sequence_with_style(&significant_tokens(node), SpacingStyle::CompactInstruction)
}

#[derive(Clone, Copy)]
enum SpacingStyle {
    Default,
    CompactInstruction,
    TypeBodyItem,
}

#[derive(Default)]
struct LineNesting {
    parens: usize,
    brackets: usize,
    braces: usize,
}

impl LineNesting {
    fn bump(&mut self, kind: SyntaxKind) {
        match kind {
            SyntaxKind::LParen => self.parens += 1,
            SyntaxKind::RParen => self.parens = self.parens.saturating_sub(1),
            SyntaxKind::LBracket => self.brackets += 1,
            SyntaxKind::RBracket => self.brackets = self.brackets.saturating_sub(1),
            SyntaxKind::LBrace => self.braces += 1,
            SyntaxKind::RBrace => self.braces = self.braces.saturating_sub(1),
            _ => (),
        }
    }

    fn line_indent_offset(&self, next_kind: SyntaxKind) -> usize {
        let depth = self.parens + self.brackets + self.braces;
        if matches!(next_kind, SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace) {
            depth.saturating_sub(1)
        } else {
            depth
        }
    }
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

fn all_tokens(node: &SyntaxNode) -> Vec<SyntaxToken> {
    node.descendants_with_tokens().filter_map(NodeOrToken::into_token).collect()
}

fn has_comment_tokens(tokens: &[SyntaxToken]) -> bool {
    tokens
        .iter()
        .any(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment))
}

fn has_comment_token(node: &SyntaxNode) -> bool {
    node.descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .any(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment))
}

fn significant_tokens(node: &SyntaxNode) -> Vec<SyntaxToken> {
    node.descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
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

fn direct_child_of_kind(node: &SyntaxNode, kind: SyntaxKind) -> Option<SyntaxNode> {
    node.children().find(|child| child.kind() == kind)
}

fn combine_tokens(prefix: &[SyntaxToken], suffix: &[SyntaxToken]) -> Vec<SyntaxToken> {
    prefix.iter().cloned().chain(suffix.iter().cloned()).collect()
}

fn trim_outer_whitespace_tokens(tokens: &[SyntaxToken]) -> Vec<SyntaxToken> {
    let start = tokens
        .iter()
        .position(|token| !matches!(token.kind(), SyntaxKind::Whitespace | SyntaxKind::Newline));
    let end = tokens
        .iter()
        .rposition(|token| !matches!(token.kind(), SyntaxKind::Whitespace | SyntaxKind::Newline));

    match (start, end) {
        (Some(start), Some(end)) if start <= end => tokens[start..=end].to_vec(),
        _ => Vec::new(),
    }
}

fn result_tokens_after_params(tokens: &[SyntaxToken], params_close: usize) -> Vec<SyntaxToken> {
    let Some(arrow_offset) = tokens
        .iter()
        .enumerate()
        .skip(params_close + 1)
        .find_map(|(index, token)| (token.kind() == SyntaxKind::RArrow).then_some(index))
    else {
        return Vec::new();
    };

    trim_outer_whitespace_tokens(&tokens[(arrow_offset + 1)..])
}

fn render_signature_item_lines(
    tokens: &[SyntaxToken],
    indent: usize,
    config: &Config,
) -> Vec<String> {
    if has_comment_tokens(tokens) {
        render_token_stream_with_comments(tokens, indent, SpacingStyle::TypeBodyItem, config)
    } else {
        render_token_lines_with_style(tokens, indent, true, SpacingStyle::TypeBodyItem, config)
    }
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
        .filter_map(NodeOrToken::into_token)
        .find(|token| matches!(token.kind(), SyntaxKind::Comment | SyntaxKind::DocComment))
        .map(|token| trimmed_comment(&token))
}

fn comment_before_child_of_kind(
    node: &SyntaxNode,
    child_kind: SyntaxKind,
    occurrence: usize,
) -> Option<String> {
    let mut inline_comment = None;
    let mut line_has_syntax = false;
    let mut seen = 0usize;

    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(child) => {
                if child.kind() == child_kind {
                    if seen == occurrence {
                        return inline_comment;
                    }
                    seen += 1;
                }
                inline_comment = None;
                update_line_has_syntax_from_text(&mut line_has_syntax, &child.text().to_string());
            },
            NodeOrToken::Token(token) => match token.kind() {
                SyntaxKind::Comment | SyntaxKind::DocComment if line_has_syntax => {
                    inline_comment = Some(trimmed_comment(&token));
                },
                SyntaxKind::Comment | SyntaxKind::DocComment | SyntaxKind::Whitespace => (),
                SyntaxKind::Newline => line_has_syntax = false,
                kind if !kind.is_trivia() => {
                    inline_comment = None;
                    update_line_has_syntax_from_text(&mut line_has_syntax, token.text());
                },
                _ => (),
            },
        }
    }

    None
}

fn standalone_comments_before_child_of_kind(
    node: &SyntaxNode,
    child_kind: SyntaxKind,
    occurrence: usize,
) -> Vec<String> {
    let mut comments = Vec::new();
    let mut pending_comment: Option<String> = None;
    let mut pending_same_line_with_syntax = false;
    let mut line_has_syntax = false;
    let mut seen = 0usize;

    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(child) => {
                if child.kind() == child_kind {
                    if seen == occurrence {
                        if let Some(comment) =
                            pending_comment.take().filter(|_| !pending_same_line_with_syntax)
                        {
                            comments.push(comment);
                        }
                        return comments;
                    }
                    seen += 1;
                }

                comments.clear();
                pending_comment = None;
                pending_same_line_with_syntax = false;
                update_line_has_syntax_from_text(&mut line_has_syntax, &child.text().to_string());
            },
            NodeOrToken::Token(token) => match token.kind() {
                SyntaxKind::Comment | SyntaxKind::DocComment => {
                    if let Some(comment) =
                        pending_comment.take().filter(|_| !pending_same_line_with_syntax)
                    {
                        comments.push(comment);
                    }
                    pending_comment = Some(trimmed_comment(&token));
                    pending_same_line_with_syntax = line_has_syntax;
                },
                SyntaxKind::Whitespace => (),
                SyntaxKind::Newline => {
                    line_has_syntax = false;
                },
                kind if !kind.is_trivia() => {
                    comments.clear();
                    pending_comment = None;
                    pending_same_line_with_syntax = false;
                    update_line_has_syntax_from_text(&mut line_has_syntax, token.text());
                },
                _ => (),
            },
        }
    }

    Vec::new()
}

fn emit_trailing_comments(lines: &mut Vec<String>, comments: &[String], indent: usize) {
    for comment in comments {
        lines.push(format!("{}{}", indent_string(indent), comment));
    }
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

fn update_line_has_syntax_from_text(line_has_syntax: &mut bool, text: &str) {
    for character in text.chars() {
        if character == '\n' {
            *line_has_syntax = false;
        } else if !character.is_whitespace() {
            *line_has_syntax = true;
        }
    }
}

fn needs_space(previous: &SyntaxToken, next: &SyntaxToken, style: SpacingStyle) -> bool {
    use SyntaxKind::*;

    let previous_kind = previous.kind();
    let next_kind = next.kind();

    if matches!(previous_kind, At | Dot | ColonColon | LAngle | LParen | LBracket | LBrace) {
        return false;
    }

    if next_kind == LParen && matches!(previous_kind, Ident | SpecialIdent | QuotedIdent) {
        return false;
    }

    match next_kind {
        Dot | ColonColon | DotDot | Comma | LAngle | RAngle | RParen | RBracket | RBrace => false,
        LBracket | Equal if matches!(style, SpacingStyle::CompactInstruction) => false,
        Colon if matches!(style, SpacingStyle::TypeBodyItem) => false,
        Tombstone | Error | SourceFile | Doc | Namespace | ExternPackage | Submodule | Import
        | ImportList | ImportSpecifier | Constant | TypeDecl | AdviceMap | BeginBlock
        | Procedure | Attribute | Visibility | Signature | Block | IfOp | WhileOp | DoWhileOp
        | RepeatOp | Instruction | Path | Expr | TypeBody | Whitespace | Newline | Comment
        | DocComment | Ident | SpecialIdent | Number | QuotedIdent | QuotedString | At | Bang
        | Colon | Equal | LBrace | LBracket | LParen | Minus | Plus | RArrow | Semicolon
        | Slash | SlashSlash | Star => match previous_kind {
            Equal if matches!(style, SpacingStyle::CompactInstruction) => false,
            DotDot => false,
            Comma | Equal | RArrow | Colon | Plus | Minus | Star | Slash | SlashSlash => true,
            _ => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use miden_assembly_syntax_cst::parse_text;

    use super::{Config, format_syntax};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root should be two levels above crates/miden-format")
            .to_path_buf()
    }

    fn checked_in_masm_corpus() -> Vec<PathBuf> {
        let root = repo_root();
        let mut files = Vec::new();
        for relative in [
            "crates/lib/core/asm",
            "miden-vm/masm-examples",
            "miden-vm/tests/integration/cli/data",
        ] {
            collect_masm_files(&root.join(relative), &mut files);
        }
        files.sort();
        files
    }

    fn collect_masm_files(dir: &Path, files: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("failed to read a directory entry under {}: {error}", dir.display())
            });
            let path = entry.path();
            if path.is_dir() {
                collect_masm_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "masm") {
                files.push(path);
            }
        }
    }

    fn representative_formatter_sources() -> &'static [&'static str] {
        &[
            "\
#! docs
use   miden::core::mem   as   memory

# const comment
pub const EVENT=event(\"miden::event\")
adv_map   TABLE=[0x01,0x02]
type T   = struct {f:u32,   other: felt}
begin
 swap  dup.1 add
 # branch
 if.true
  nop
 else
  mul
 end
end
",
            "\
@inline # keep me
# keep standalone
@locals(1)
pub proc foo  nop end
",
            "\
pub proc println_debug_message_with_context(
    # message
    message: ptr<u8, addrspace(byte)>,
    # context
    context: ptr<u8, addrspace(byte)>
) -> (
    # result
    result: ptr<u8, addrspace(byte)>,
    status: i1 # status
) # proc
    nop
end
",
        ]
    }

    fn assert_format_idempotent(input: &str, label: impl core::fmt::Display) {
        let config = Config::default();
        let parse = parse_text(input);
        assert!(
            !parse.has_errors(),
            "unexpected parse diagnostics for {label}: {:?}",
            parse.diagnostics()
        );

        let formatted = format_syntax(&config, &parse.syntax());
        let reparsed = parse_text(&formatted);
        assert!(
            !reparsed.has_errors(),
            "formatted output did not parse for {label}: {:?}",
            reparsed.diagnostics()
        );

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted, "formatter was not idempotent for {label}");
    }

    #[test]
    fn formatter_is_idempotent_for_representative_sources() {
        for (index, source) in representative_formatter_sources().iter().enumerate() {
            assert_format_idempotent(source, format_args!("representative source {index}"));
        }
    }

    #[test]
    fn formatter_is_idempotent_for_checked_in_masm_corpus() {
        let files = checked_in_masm_corpus();
        assert!(
            !files.is_empty(),
            "expected the checked-in MASM corpus to contain at least one source file"
        );

        for path in files {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            assert_format_idempotent(&source, path.display());
        }
    }

    #[test]
    fn preserves_space_before_parenthesized_value_expressions() {
        let source = "\
const X = (1)
const Y = event(\"miden::event\")
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config {
            max_line_length: Some(80),
            ..Config::default()
        };
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
const X = (1)
const Y = event(\"miden::event\")
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn wraps_root_parenthesized_value_expressions() {
        let source = "const X = (alpha, beta, gamma, delta, epsilon, zeta)\n";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config {
            max_line_length: Some(40),
            ..Config::default()
        };
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
const X =
    (
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        zeta
    )
";

        assert_eq!(formatted, expected);
        assert!(formatted.lines().all(|line| line.len() <= config.max_line_length()));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn formats_namespace_extern_package_and_submodule_forms() {
        let source = "\
namespace   app::main # root
extern   package   \"miden:base@1.0.0\"
pub   mod   lib
mod   private
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
namespace app::main # root
extern package \"miden:base@1.0.0\"
pub mod lib
mod private
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn formats_top_level_forms_and_anchors_comments() {
        let source = "\
#! docs
use   miden::core::mem   as   memory

# const comment
pub const EVENT=event(\"miden::event\")
adv_map   TABLE=[0x01,0x02]
type T   = struct {f:u32,   other: felt}
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

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
#! docs
use miden::core::mem as memory

# const comment
pub const EVENT = event(\"miden::event\")
adv_map TABLE = [0x01, 0x02]
type T = struct { f: u32, other: felt }
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

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn breaks_grouped_instruction_lines_when_they_overflow() {
        let source = "\
begin
    instruction_alpha_one instruction_beta_two instruction_gamma_three instruction_delta_four instruction_five
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let body_lines =
            formatted.lines().skip(1).take_while(|line| *line != "end").collect::<Vec<_>>();

        assert!(
            body_lines.len() >= 2,
            "expected at least two formatted body lines, got {body_lines:?}"
        );
        assert!(body_lines.iter().all(|line| line.len() <= config.max_line_length()));
        assert!(formatted.contains("\n    instruction_five\n"));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn preserves_comments_inside_instruction_token_groups() {
        let source = "\
begin
    foo(
        # arg
        bar,
        baz
    )
    emit.event([
        # first
        1,
        2
    ])
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
begin
    foo(
        # arg
        bar,
        baz
    )
    emit.event([
            # first
            1,
            2
        ])
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn preserves_compact_instruction_bracket_suffixes_across_formatting_passes() {
        let source = "\
pub proc has_callbacks
    push.ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_ROOT_SLOT[0..2]
    exec.has_non_empty_slot
    push.ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_ROOT_SLOT[0..2]
    exec.has_non_empty_slot
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        assert_eq!(formatted, source);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn preserves_compact_instruction_error_operands() {
        let source = "\
pub proc checks
    assert.err=ERR_FOO
    assert.err=\"message\"
    u32assert2.err=\"number of storage map elements should fit into a u32\"
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        assert_eq!(formatted, source);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn wraps_long_constants_and_advice_maps() {
        let source = "\
const VERY_LONG_EVENT = event(\"miden::core::collections::sorted_array::lowerbound_key_value::extra_long\")
adv_map CIRCUIT_COMMITMENT = [1, 0, 0, 0, 2305843126251553075, 114890375379, 2305843283017859381, 123]
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
const VERY_LONG_EVENT =
    event(
        \"miden::core::collections::sorted_array::lowerbound_key_value::extra_long\"
    )
adv_map CIRCUIT_COMMITMENT =
    [
        1,
        0,
        0,
        0,
        2305843126251553075,
        114890375379,
        2305843283017859381,
        123
    ]
";

        assert_eq!(formatted, expected);
        assert!(formatted.lines().all(|line| line.len() <= config.max_line_length()));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn wraps_long_type_bodies_and_normalizes_multiline_body_comments() {
        let source = "\
pub type VeryLongTypeName = struct { lower_bound_key_value: u128, upper_bound_key_value: u128, extra_field: felt }

enum Status : u16 {
# ready
READY,
# waiting
WAITING = 2,
}
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub type VeryLongTypeName = struct {
    lower_bound_key_value: u128,
    upper_bound_key_value: u128,
    extra_field: felt,
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
    fn format_import_module_and_item_forms() {
        let source = "\
use   some::module   as   sm
use   foo
use   {foo,bar  as  baz,\"as\" as \"from\"}   from   some::module # items
pub   use   {alpha}   from   core
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
use some::module as sm
use foo
use {foo, bar as baz, \"as\" as \"from\"} from some::module # items
pub use {alpha} from core
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn format_import_preserves_comments_inside_item_list() {
        let source = "\
use   {
foo, # first import
# exported under baz
bar   as   baz,
\"as\" as \"from\" # contextual
}   from   some::module # import
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
use {
    foo, # first import
    # exported under baz
    bar as baz,
    \"as\" as \"from\" # contextual
} from some::module # import
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn format_import_wraps_commented_item_import_from_clause() {
        let source = "\
pub use {
foo, # first import
bar as baz
} from ::miden::core::collections::sorted_array
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config {
            max_line_length: Some(40),
            ..Config::default()
        };
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub use {
    foo, # first import
    bar as baz
}
    from ::miden::core::collections::sorted_array
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn format_import_wraps_long_item_imports_without_breaking_module_paths() {
        let source = "\
pub use { lowerbound_key_value as lowerbound_key_value_long_alias } from ::miden::core::collections::sorted_array

pub proc println_debug_message_with_context(message: ptr<u8, addrspace(byte)>, context: ptr<u8, addrspace(byte)>) -> (result: ptr<u8, addrspace(byte)>, status: i1)
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config {
            max_line_length: Some(80),
            ..Config::default()
        };
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub use {lowerbound_key_value as lowerbound_key_value_long_alias}
    from ::miden::core::collections::sorted_array

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
        assert!(formatted.lines().all(|line| line.len() <= config.max_line_length()));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", parse.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn wraps_long_imports_and_procedure_headers_without_mangling_generic_types() {
        let source = "\
use ::miden::core::collections::sorted_array as lowerbound_key_value_really_long_alias

pub proc println_debug_message_with_context(message: ptr<u8, addrspace(byte)>, context: ptr<u8, addrspace(byte)>) -> (result: ptr<u8, addrspace(byte)>, status: i1)
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config {
            max_line_length: Some(80),
            ..Config::default()
        };
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
use ::miden::core::collections::sorted_array
    as lowerbound_key_value_really_long_alias

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
        assert!(formatted.lines().all(|line| line.len() <= config.max_line_length()));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn wrapped_long_imports_do_not_break_on_components() {
        let source = "\
use miden::protocol::kernel_proc_offsets::tx_update_expiration_block_delta_offset_plus_enough_extra_to_wrap
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
use miden::protocol::kernel_proc_offsets::tx_update_expiration_block_delta_offset_plus_enough_extra_to_wrap
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn preserves_root_import_spacing_and_structured_header_comments() {
        let source = "\
use {panic} from ::miden::utils # import

begin # begin
 if.true # if
  while.true # while
   repeat.2 # repeat
    nop
   end
   end
 else # else
  nop
 end
end

pub proc long_name(arg: ptr<u8, addrspace(byte)>) # proc
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
use {panic} from ::miden::utils # import

begin # begin
    if.true # if
        while.true # while
            repeat.2 # repeat
                nop
            end
        end
    else # else
        nop
    end
end

pub proc long_name(arg: ptr<u8, addrspace(byte)>) # proc
    nop
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn formats_do_while_loop() {
        let source = "\
begin
do
push.1 add
while
dup.0 neq.0
end
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
begin
    do
        push.1 add
    while
        dup.0 neq.0
    end
end
";

        assert_eq!(formatted, expected);

        // Formatting is idempotent.
        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn preserves_standalone_body_comments_after_headers() {
        let source = "\
begin
    # begin body
    if.true
        # then body
        nop
    else
        # else body
        nop
    end
end

pub proc get_native_storage_slot_type
    # convert the index into a memory offset
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        assert_eq!(formatted, source);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn preserves_stack_comments_after_the_preceding_instruction() {
        let source = "\
pub proc set_item
    dup.4 exec.get_item_raw
    # => [OLD_VALUE, VALUE, slot_ptr]

    swapw movup.8
    # => [slot_ptr, VALUE, OLD_VALUE]
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        assert_eq!(formatted, source);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn preserves_comments_between_procedure_attributes() {
        let source = "\
@inline # keep me
# keep standalone
@locals(1)
pub proc foo  nop end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
@inline # keep me
# keep standalone
@locals(1)
pub proc foo
    nop
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn preserves_comments_inside_wrapped_procedure_signatures() {
        let source = "\
pub proc println_debug_message_with_context(
    # message
    message: ptr<u8, addrspace(byte)>,
    # context
    context: ptr<u8, addrspace(byte)>
) -> (
    # result
    result: ptr<u8, addrspace(byte)>,
    status: i1 # status
) # proc
    nop
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub proc println_debug_message_with_context(
    # message
    message: ptr<u8, addrspace(byte)>,
    # context
    context: ptr<u8, addrspace(byte)>
) -> (
    # result
    result: ptr<u8, addrspace(byte)>,
    status: i1 # status
) # proc
    nop
end
";

        assert_eq!(formatted, expected);
        assert!(formatted.lines().all(|line| line.len() <= config.max_line_length()));

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn preserves_comments_inside_multiline_value_expressions() {
        let source = "\
const LONG = event(
    # message
    foo(bar, baz),
    # id
    qux
)

adv_map TABLE = [
    # first
    [1, 2],
    # second
    event(foo(bar, baz)),
]
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
const LONG =
    event(
        # message
        foo(bar, baz),
        # id
        qux
    )

adv_map TABLE =
    [
        # first
        [1, 2],
        # second
        event(foo(bar, baz)),
    ]
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());
    }

    #[test]
    fn leading_comment_in_procedure_body_is_correctly_placed_when_signature_is_wrapped() {
        let source = "\
pub proc tx_prepare_fpi(foreign_account_id: AccountId, foreign_proc_root: word, foreign_procedure_input_15: felt)
    # validate the provided foreign account ID
    push.1
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub proc tx_prepare_fpi(
    foreign_account_id: AccountId,
    foreign_proc_root: word,
    foreign_procedure_input_15: felt
)
    # validate the provided foreign account ID
    push.1
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }

    #[test]
    fn leading_comment_in_procedure_body_is_correctly_placed_when_signature_fits_on_one_line() {
        let source = "\
pub proc tx_prepare_fpi(foreign_account_id: AccountId)
    # validate the provided foreign account ID
    push.1
end
";

        let parse = parse_text(source);
        assert!(!parse.has_errors(), "{:?}", parse.diagnostics());

        let config = Config::default();
        let formatted = format_syntax(&config, &parse.syntax());
        let expected = "\
pub proc tx_prepare_fpi(foreign_account_id: AccountId)
    # validate the provided foreign account ID
    push.1
end
";

        assert_eq!(formatted, expected);

        let reparsed = parse_text(&formatted);
        assert!(!reparsed.has_errors(), "{:?}", reparsed.diagnostics());

        let reformatted = format_syntax(&config, &reparsed.syntax());
        assert_eq!(reformatted, formatted);
    }
}
