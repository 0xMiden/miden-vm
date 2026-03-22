use rowan::GreenNodeBuilder;

use crate::{
    diagnostics::Diagnostic,
    lexer::tokenize,
    syntax::{SyntaxKind, SyntaxNode},
};

#[derive(Debug, Clone)]
pub struct Parse {
    green_node: rowan::GreenNode,
    diagnostics: Vec<Diagnostic>,
}

impl Parse {
    pub fn syntax(&self) -> SyntaxNode {
        SyntaxNode::new_root(self.green_node.clone())
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

pub fn parse_text(input: &str) -> Parse {
    let mut builder = GreenNodeBuilder::new();
    let mut diagnostics = Vec::new();

    builder.start_node(SyntaxKind::SourceFile.into());
    for token in tokenize(input) {
        if token.kind() == SyntaxKind::Error {
            diagnostics.push(Diagnostic::new(
                token.span(),
                format!("unrecognized token `{}`", token.text()),
            ));
        }
        builder.token(token.kind().into(), token.text());
    }
    builder.finish_node();

    Parse {
        green_node: builder.finish(),
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse_text, syntax::SyntaxKind};

    #[test]
    fn builds_a_lossless_source_file_root() {
        let parse = parse_text("begin\n    repeat.4\n        swap dup.1 add\n    end\nend\n");
        assert!(!parse.has_errors());
        assert_eq!(parse.syntax().kind(), SyntaxKind::SourceFile);
    }

    #[test]
    fn surfaces_invalid_tokens_as_diagnostics() {
        let parse = parse_text("begin\n    §\nend\n");
        assert!(parse.has_errors());
        assert_eq!(parse.diagnostics().len(), 1);
    }
}
