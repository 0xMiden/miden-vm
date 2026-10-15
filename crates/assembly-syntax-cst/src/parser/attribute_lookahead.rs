use alloc::vec::Vec;

use super::{SyntaxKind, Token, is_name_like};

/// Precomputed lookahead for declaration recovery inside type annotations.
///
/// For each token position, it caches where to continue after skipping trivia and any consecutive
/// attributes starting there. Shared group endpoints and cached failures avoid rescanning long,
/// nested, or malformed attribute sequences. The resulting token is only a candidate. Parser
/// recovery checks whether it actually starts a declaration.
pub(super) struct AttributeLookahead {
    /// Index of the next candidate token after skipping trivia and consecutive attributes.
    ///
    /// Significant non-attribute tokens point to themselves. `None` means an attribute is
    /// malformed or no token remains. The extra entry at `tokens.len()` represents EOF and is
    /// `None`, so a lookup just after a group ending at the final token safely finds no candidate.
    candidates: Vec<Option<usize>>,
    /// Token visits during index construction, retained to test linear work without timing checks.
    #[cfg(test)]
    token_visits: usize,
}

impl AttributeLookahead {
    /// Builds the index in O(n) time and space for an immutable token sequence.
    ///
    /// Argument groups require properly nested parentheses, brackets, and braces. Failed lookahead
    /// is cached too, so malformed suffixes do not cause repeated scans.
    pub(super) fn new(tokens: &[Token<'_>]) -> Self {
        let mut lookahead = Self {
            candidates: vec![None; tokens.len() + 1],
            #[cfg(test)]
            token_visits: 0,
        };

        // Example: `@inline @locals([1, {2}]) proc foo`
        // Pass 1 caches matching group endpoints:
        //   `(` ... `)`
        //    `[` ... `]`
        //     `{` ... `}`
        let group_ends = lookahead.index_argument_groups(tokens);

        // Pass 2 builds suffix candidates from right to left:
        //   `@inline` ───────────────┐
        //   `@locals(...)` ──────────┴──> `proc`
        // The parser still checks whether the candidate starts a declaration.
        lookahead.index_attribute_suffixes(tokens, &group_ends);
        lookahead
    }

    /// Returns a candidate after the attribute sequence at `index` in constant time.
    ///
    /// The result does not establish that the candidate starts a declaration. `None` means that
    /// the attribute sequence is malformed or no significant token follows it.
    ///
    /// # Panics
    ///
    /// Panics if `index` exceeds the length of the token sequence used to build this index.
    pub(super) fn declaration_after(&self, index: usize) -> Option<usize> {
        self.candidates[index]
    }

    fn index_argument_groups(&mut self, tokens: &[Token<'_>]) -> Vec<Option<usize>> {
        let mut ends = vec![None; tokens.len()];
        let mut stack = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            #[cfg(test)]
            {
                self.token_visits += 1;
            }
            let close = match token.kind() {
                SyntaxKind::LParen => SyntaxKind::RParen,
                SyntaxKind::LBracket => SyntaxKind::RBracket,
                SyntaxKind::LBrace => SyntaxKind::RBrace,
                kind @ (SyntaxKind::RParen | SyntaxKind::RBracket | SyntaxKind::RBrace) => {
                    if let Some((open, expected)) = stack.pop()
                        && kind == expected
                    {
                        ends[open] = Some(index);
                    } else {
                        // A mismatched closer invalidates every enclosing argument group.
                        stack.clear();
                    }
                    continue;
                },
                _ => continue,
            };
            stack.push((index, close));
        }
        ends
    }

    fn index_attribute_suffixes(&mut self, tokens: &[Token<'_>], group_ends: &[Option<usize>]) {
        // Right-to-left indexing lets every attribute reuse its suffix, including failed lookahead.
        let mut next = [tokens.len(); 2];
        for (index, token) in tokens.iter().enumerate().rev() {
            #[cfg(test)]
            {
                self.token_visits += 1;
            }
            let kind = token.kind();
            self.candidates[index] = if kind.is_trivia() {
                self.candidates[index + 1]
            } else if kind == SyntaxKind::At {
                self.attribute_candidate(tokens, group_ends, next)
            } else {
                Some(index)
            };
            if !kind.is_trivia() {
                next = [index, next[0]];
            }
        }
    }

    fn attribute_candidate(
        &self,
        tokens: &[Token<'_>],
        group_ends: &[Option<usize>],
        [name, after_name]: [usize; 2],
    ) -> Option<usize> {
        if !is_name_like(tokens.get(name)?.kind()) {
            return None;
        }
        let tail = if tokens.get(after_name)?.kind() == SyntaxKind::LParen {
            group_ends[after_name]? + 1
        } else {
            after_name
        };
        self.candidates[tail]
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use super::AttributeLookahead;
    use crate::{lexer::tokenize_text, syntax::SyntaxKind};

    fn attribute_candidates(source: &str) -> Vec<Option<String>> {
        let tokens = tokenize_text(source);
        let lookahead = AttributeLookahead::new(&tokens);
        tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| token.kind() == SyntaxKind::At)
            .map(|(index, _)| {
                lookahead
                    .declaration_after(index)
                    .map(|candidate| tokens[candidate].text().into())
            })
            .collect()
    }

    #[test]
    fn indexes_attribute_suffixes_and_failures() {
        for (source, expected) in [
            ("@packed @packed {", vec![Some("{"), Some("{")]),
            ("@inline @locals(1) pub proc foo", vec![Some("pub"), Some("pub")]),
            (
                "@inline #! docs\n@locals([1, {2}]) # comment\nproc foo",
                vec![Some("proc"), Some("proc")],
            ),
            ("@inline @", vec![None, None]),
            ("@inline @42 proc foo", vec![None, None]),
            ("@inline @locals()", vec![None, None]),
            ("@inline @locals(", vec![None, None]),
            ("@outer(@inner()) proc foo", vec![Some("proc"), Some(")")]),
            ("@outer(@inner() proc foo", vec![None, Some("proc")]),
            ("@outer([)] @inline proc foo", vec![None, Some("proc")]),
            ("@outer([) @inner()] @inline proc foo", vec![None, Some("]"), Some("proc")]),
        ] {
            let expected =
                expected.into_iter().map(|value| value.map(String::from)).collect::<Vec<_>>();
            assert_eq!(attribute_candidates(source), expected, "{source}");
        }
    }

    /// Verifies that index construction visits each token once per pass, without timing checks.
    fn assert_linear_index(source: &str) {
        let tokens = tokenize_text(source);
        let lookahead = AttributeLookahead::new(&tokens);
        // Model recovery looking up every attribute before checking the construction visit count.
        for (index, token) in tokens.iter().enumerate() {
            if token.kind() == SyntaxKind::At {
                let _ = lookahead.declaration_after(index);
            }
        }
        assert_eq!(lookahead.token_visits, 2 * tokens.len());
    }

    #[test]
    fn indexes_repeated_attributes_in_linear_work() {
        for count in [128, 256, 512] {
            for tail in ["{", "= 1", "", "proc foo", "@broken("] {
                assert_linear_index(&format!("{} {tail}", "@packed ".repeat(count)));
            }
        }
    }

    #[test]
    fn indexes_nested_and_malformed_arguments_in_linear_work() {
        for count in [128, 256, 512] {
            for tail in [")".repeat(count), String::new(), "]".repeat(count)] {
                assert_linear_index(&format!("{}{tail} proc foo", "@attr(".repeat(count)));
            }
        }
    }
}
