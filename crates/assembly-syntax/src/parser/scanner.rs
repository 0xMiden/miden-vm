use core::ops::Range;

// SCANNER
// ================================================================================================

/// [Scanner] handles the low-level details of reading characters from a raw input stream of bytes.
/// It decodes those bytes into UTF-8 characters, and associates each character with the
/// [miden_debug_types::ByteIndex] at which it occurs.
///
/// The [Scanner] is intended to be consumed by a lexer, which handles converting the stream of
/// characters into a token stream for use by the parser.
///
/// ## Scanner Lifecycle
///
/// The following illustrates how content flows from the raw input stream through the scanner.
///
/// ```ignore
/// lexer <- (peek) <- pending <- source
///       <- (pop) <- current <- pending <- source
/// ```
///
/// As shown above, the lexer is "pulling" characters from the scanner.
///
/// When "peeking" a character, we return the character currently in the `pending` field, but if
/// `pending` is empty, we read enough bytes from the source to construct a UTF-8 character, and
/// store it as `pending`, as well as returning it to the lexer.
///
/// When "popping" a character (i.e. we are advancing the scanner in the input), we are returning
/// the character in the `current` field, and then moving the character in `pending` into `current`.
/// Accordingly, if any of those fields is empty, we must pull from the next field in the chain,
/// reading bytes from the input as we go.
pub struct Scanner<'input> {
    input: &'input str,
    chars: core::iter::Peekable<core::str::CharIndices<'input>>,
    current: (usize, char),
    pending: (usize, char),
    start: usize,
    end: usize,
}

impl<'input> Scanner<'input> {
    /// Construct a new [Scanner] for the given `source`.
    pub fn new(input: &'input str) -> Self {
        let end = input.len();
        assert!(end < u32::MAX as usize, "file too large");

        let mut chars = input.char_indices().peekable();
        let current = chars.next().unwrap_or((0, '\0'));
        let pending = chars.next().unwrap_or((end, '\0'));
        Self {
            input,
            chars,
            current,
            pending,
            start: 0,
            end,
        }
    }

    /// Returns the byte offset representing the start of the source
    pub fn start(&self) -> usize {
        self.start
    }

    /// Advance scanner pipeline by a single character.
    ///
    /// `pending` becomes `current`, and bytes are read from the input to repopulate `pending`.
    #[inline]
    pub fn advance(&mut self) {
        self.current = self.pending;
        self.pending = self.chars.next().unwrap_or((self.end, '\0'));
    }

    /// Return the current character and advance our position in the source
    #[inline]
    pub fn pop(&mut self) -> (usize, char) {
        let current = self.current;
        self.advance();
        current
    }

    /// Return the next character in the input, but do not advance.
    #[inline]
    pub fn peek(&self) -> (usize, char) {
        self.pending
    }

    /// Return the character after the next character in the input, but do not advance.
    #[inline]
    pub fn peek_next(&mut self) -> (usize, char) {
        self.chars.peek().copied().unwrap_or((self.end, '\0'))
    }

    /// Get current character in the input.
    #[inline]
    pub fn read(&self) -> (usize, char) {
        self.current
    }

    /// Get a string slice representing the given range in the underlying source
    #[inline]
    pub fn slice(&self, span: impl Into<Range<usize>>) -> &'input str {
        let range = span.into();
        let bytes = &self.input.as_bytes()[range];
        core::str::from_utf8(bytes).expect("invalid slice indices")
    }
}
