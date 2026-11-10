use miden_debug_types::Uri;

use super::{ErrorKind, Glob, GlobBuilder, Token, Token::*};

#[derive(Clone, Copy, Debug, Default)]
struct Options {
    casei: Option<bool>,
    litsep: Option<bool>,
    bsesc: Option<bool>,
    ealtre: Option<bool>,
    unccls: Option<bool>,
}

macro_rules! syntax {
    ($name:ident, $pat:expr, $tokens:expr) => {
        #[test]
        fn $name() {
            let pat = Glob::new($pat).unwrap();
            assert_eq!($tokens, pat.tokens.0);
        }
    };
}

macro_rules! syntaxerr {
    ($name:ident, $pat:expr, $err:expr) => {
        #[test]
        fn $name() {
            let err = Glob::new($pat).unwrap_err();
            assert_eq!(&$err, err.kind());
        }
    };
}

macro_rules! toregex {
    ($name:ident, $pat:expr, $re:expr) => {
        toregex!($name, $pat, $re, Options::default());
    };
    ($name:ident, $pat:expr, $re:expr, $options:expr) => {
        #[test]
        fn $name() {
            let mut builder = GlobBuilder::new($pat);
            if let Some(casei) = $options.casei {
                builder.case_insensitive(casei);
            }
            if let Some(litsep) = $options.litsep {
                builder.literal_separator(litsep);
            }
            if let Some(bsesc) = $options.bsesc {
                builder.backslash_escape(bsesc);
            }
            if let Some(ealtre) = $options.ealtre {
                builder.empty_alternates(ealtre);
            }
            if let Some(unccls) = $options.unccls {
                builder.allow_unclosed_class(unccls);
            }

            let pat = builder.build().unwrap();
            assert_eq!(format!("(?-u){}", $re), pat.regex());
        }
    };
}

macro_rules! matches {
    ($name:ident, $pat:expr, $path:expr) => {
        matches!($name, $pat, $path, Options::default());
    };
    ($name:ident, $pat:expr, $path:expr, $options:expr) => {
        #[test]
        fn $name() {
            let mut builder = GlobBuilder::new($pat);
            if let Some(casei) = $options.casei {
                builder.case_insensitive(casei);
            }
            if let Some(litsep) = $options.litsep {
                builder.literal_separator(litsep);
            }
            if let Some(bsesc) = $options.bsesc {
                builder.backslash_escape(bsesc);
            }
            if let Some(ealtre) = $options.ealtre {
                builder.empty_alternates(ealtre);
            }
            let pat = builder.build().unwrap();
            let matcher = pat.compile_matcher();
            let path = Uri::from($path);
            assert!(matcher.is_match(&path));
        }
    };
}

macro_rules! nmatches {
    ($name:ident, $pat:expr, $path:expr) => {
        nmatches!($name, $pat, $path, Options::default());
    };
    ($name:ident, $pat:expr, $path:expr, $options:expr) => {
        #[test]
        fn $name() {
            let mut builder = GlobBuilder::new($pat);
            if let Some(casei) = $options.casei {
                builder.case_insensitive(casei);
            }
            if let Some(litsep) = $options.litsep {
                builder.literal_separator(litsep);
            }
            if let Some(bsesc) = $options.bsesc {
                builder.backslash_escape(bsesc);
            }
            if let Some(ealtre) = $options.ealtre {
                builder.empty_alternates(ealtre);
            }
            let pat = builder.build().unwrap();
            let matcher = pat.compile_matcher();
            let path = Uri::from($path);
            assert!(!matcher.is_match(&path));
        }
    };
}

fn class(s: char, e: char) -> Token {
    Class {
        negated: false,
        ranges: vec![(s, e)],
    }
}

fn classn(s: char, e: char) -> Token {
    Class {
        negated: true,
        ranges: vec![(s, e)],
    }
}

fn rclass(ranges: &[(char, char)]) -> Token {
    Class {
        negated: false,
        ranges: ranges.to_vec(),
    }
}

fn rclassn(ranges: &[(char, char)]) -> Token {
    Class {
        negated: true,
        ranges: ranges.to_vec(),
    }
}

syntax!(literal1, "a", vec![Literal('a')]);
syntax!(literal2, "ab", vec![Literal('a'), Literal('b')]);
syntax!(any1, "?", vec![Any]);
syntax!(any2, "a?b", vec![Literal('a'), Any, Literal('b')]);
syntax!(seq1, "*", vec![ZeroOrMore]);
syntax!(seq2, "a*b", vec![Literal('a'), ZeroOrMore, Literal('b')]);
syntax!(
    seq3,
    "*a*b*",
    vec![ZeroOrMore, Literal('a'), ZeroOrMore, Literal('b'), ZeroOrMore,]
);
syntax!(rseq1, "**", vec![RecursivePrefix]);
syntax!(rseq2, "**/", vec![RecursivePrefix]);
syntax!(rseq3, "/**", vec![RecursiveSuffix]);
syntax!(rseq4, "/**/", vec![RecursiveZeroOrMore]);
syntax!(rseq5, "a/**/b", vec![Literal('a'), RecursiveZeroOrMore, Literal('b'),]);
syntax!(cls1, "[a]", vec![class('a', 'a')]);
syntax!(cls2, "[!a]", vec![classn('a', 'a')]);
syntax!(cls3, "[a-z]", vec![class('a', 'z')]);
syntax!(cls4, "[!a-z]", vec![classn('a', 'z')]);
syntax!(cls5, "[-]", vec![class('-', '-')]);
syntax!(cls6, "[]]", vec![class(']', ']')]);
syntax!(cls7, "[*]", vec![class('*', '*')]);
syntax!(cls8, "[!!]", vec![classn('!', '!')]);
syntax!(cls9, "[a-]", vec![rclass(&[('a', 'a'), ('-', '-')])]);
syntax!(cls10, "[-a-z]", vec![rclass(&[('-', '-'), ('a', 'z')])]);
syntax!(cls11, "[a-z-]", vec![rclass(&[('a', 'z'), ('-', '-')])]);
syntax!(cls12, "[-a-z-]", vec![rclass(&[('-', '-'), ('a', 'z'), ('-', '-')]),]);
syntax!(cls13, "[]-z]", vec![class(']', 'z')]);
syntax!(cls14, "[--z]", vec![class('-', 'z')]);
syntax!(cls15, "[ --]", vec![class(' ', '-')]);
syntax!(cls16, "[0-9a-z]", vec![rclass(&[('0', '9'), ('a', 'z')])]);
syntax!(cls17, "[a-z0-9]", vec![rclass(&[('a', 'z'), ('0', '9')])]);
syntax!(cls18, "[!0-9a-z]", vec![rclassn(&[('0', '9'), ('a', 'z')])]);
syntax!(cls19, "[!a-z0-9]", vec![rclassn(&[('a', 'z'), ('0', '9')])]);
syntax!(cls20, "[^a]", vec![classn('a', 'a')]);
syntax!(cls21, "[^a-z]", vec![classn('a', 'z')]);

syntaxerr!(err_unclosed1, "[", ErrorKind::UnclosedClass);
syntaxerr!(err_unclosed2, "[]", ErrorKind::UnclosedClass);
syntaxerr!(err_unclosed3, "[!", ErrorKind::UnclosedClass);
syntaxerr!(err_unclosed4, "[!]", ErrorKind::UnclosedClass);
syntaxerr!(err_range1, "[z-a]", ErrorKind::InvalidRange('z', 'a'));
syntaxerr!(err_range2, "[z--]", ErrorKind::InvalidRange('z', '-'));
syntaxerr!(err_alt1, "{a,b", ErrorKind::UnclosedAlternates);
syntaxerr!(err_alt2, "{a,{b,c}", ErrorKind::UnclosedAlternates);
syntaxerr!(err_alt3, "a,b}", ErrorKind::UnopenedAlternates);
syntaxerr!(err_alt4, "{a,b}}", ErrorKind::UnopenedAlternates);

const CASEI: Options = Options {
    casei: Some(true),
    litsep: None,
    bsesc: None,
    ealtre: None,
    unccls: None,
};
const SLASHLIT: Options = Options {
    casei: None,
    litsep: Some(true),
    bsesc: None,
    ealtre: None,
    unccls: None,
};
const NOBSESC: Options = Options {
    casei: None,
    litsep: None,
    bsesc: Some(false),
    ealtre: None,
    unccls: None,
};
const BSESC: Options = Options {
    casei: None,
    litsep: None,
    bsesc: Some(true),
    ealtre: None,
    unccls: None,
};
const EALTRE: Options = Options {
    casei: None,
    litsep: None,
    bsesc: Some(true),
    ealtre: Some(true),
    unccls: None,
};
const UNCCLS: Options = Options {
    casei: None,
    litsep: None,
    bsesc: None,
    ealtre: None,
    unccls: Some(true),
};

toregex!(allow_unclosed_class_single, r"[", r"^\[$", &UNCCLS);
toregex!(allow_unclosed_class_many, r"[abc", r"^\[abc$", &UNCCLS);
toregex!(allow_unclosed_class_empty1, r"[]", r"^\[\]$", &UNCCLS);
toregex!(allow_unclosed_class_empty2, r"[][", r"^\[\]\[$", &UNCCLS);
toregex!(allow_unclosed_class_negated_unclosed, r"[!", r"^\[!$", &UNCCLS);
toregex!(allow_unclosed_class_negated_empty, r"[!]", r"^\[!\]$", &UNCCLS);
toregex!(allow_unclosed_class_brace1, r"{[abc,xyz}", r"^(?:\[abc|xyz)$", &UNCCLS);
toregex!(allow_unclosed_class_brace2, r"{[abc,[xyz}", r"^(?:\[abc|\[xyz)$", &UNCCLS);
toregex!(allow_unclosed_class_brace3, r"{[abc],[xyz}", r"^(?:[abc]|\[xyz)$", &UNCCLS);

toregex!(re_empty, "", "^$");

toregex!(re_casei, "a", "(?i)^a$", &CASEI);

toregex!(re_slash1, "?", r"^[^/]$", SLASHLIT);
toregex!(re_slash2, "*", r"^[^/]*$", SLASHLIT);

toregex!(re1, "a", "^a$");
toregex!(re2, "?", "^.$");
toregex!(re3, "*", "^.*$");
toregex!(re4, "a?", "^a.$");
toregex!(re5, "?a", "^.a$");
toregex!(re6, "a*", "^a.*$");
toregex!(re7, "*a", "^.*a$");
toregex!(re8, "[*]", r"^[\*]$");
toregex!(re9, "[+]", r"^[\+]$");
toregex!(re10, "+", r"^\+$");
toregex!(re11, "☃", r"^\xe2\x98\x83$");
toregex!(re12, "**", r"^.*$");
toregex!(re13, "**/", r"^.*$");
toregex!(re14, "**/*", r"^(?:/?|.*/).*$");
toregex!(re15, "**/**", r"^.*$");
toregex!(re16, "**/**/*", r"^(?:/?|.*/).*$");
toregex!(re17, "**/**/**", r"^.*$");
toregex!(re18, "**/**/**/*", r"^(?:/?|.*/).*$");
toregex!(re19, "a/**", r"^a/.*$");
toregex!(re20, "a/**/**", r"^a/.*$");
toregex!(re21, "a/**/**/**", r"^a/.*$");
toregex!(re22, "a/**/b", r"^a(?:/|/.*/)b$");
toregex!(re23, "a/**/**/b", r"^a(?:/|/.*/)b$");
toregex!(re24, "a/**/**/**/b", r"^a(?:/|/.*/)b$");
toregex!(re25, "**/b", r"^(?:/?|.*/)b$");
toregex!(re26, "**/**/b", r"^(?:/?|.*/)b$");
toregex!(re27, "**/**/**/b", r"^(?:/?|.*/)b$");
toregex!(re28, "a**", r"^a.*.*$");
toregex!(re29, "**a", r"^.*.*a$");
toregex!(re30, "a**b", r"^a.*.*b$");
toregex!(re31, "***", r"^.*.*.*$");
toregex!(re32, "/a**", r"^/a.*.*$");
toregex!(re33, "/**a", r"^/.*.*a$");
toregex!(re34, "/a**b", r"^/a.*.*b$");
toregex!(re35, "{a,b}", r"^(?:a|b)$");
toregex!(re36, "{a,{b,c}}", r"^(?:a|(?:b|c))$");
toregex!(re37, "{{a,b},{c,d}}", r"^(?:(?:a|b)|(?:c|d))$");

matches!(match1, "a", "a");
matches!(match2, "a*b", "a_b");
matches!(match3, "a*b*c", "abc");
matches!(match4, "a*b*c", "a_b_c");
matches!(match5, "a*b*c", "a___b___c");
matches!(match6, "abc*abc*abc", "abcabcabcabcabcabcabc");
matches!(match7, "a*a*a*a*a*a*a*a*a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
matches!(match8, "a*b[xyz]c*d", "abxcdbxcddd");
matches!(match9, "*.rs", ".rs");
matches!(match10, "☃", "☃");

matches!(matchrec1, "some/**/needle.txt", "some/needle.txt");
matches!(matchrec2, "some/**/needle.txt", "some/one/needle.txt");
matches!(matchrec3, "some/**/needle.txt", "some/one/two/needle.txt");
matches!(matchrec4, "some/**/needle.txt", "some/other/needle.txt");
matches!(matchrec5, "**", "abcde");
matches!(matchrec6, "**", "");
matches!(matchrec7, "**", ".asdf");
matches!(matchrec8, "**", "/x/.asdf");
matches!(matchrec9, "some/**/**/needle.txt", "some/needle.txt");
matches!(matchrec10, "some/**/**/needle.txt", "some/one/needle.txt");
matches!(matchrec11, "some/**/**/needle.txt", "some/one/two/needle.txt");
matches!(matchrec12, "some/**/**/needle.txt", "some/other/needle.txt");
matches!(matchrec13, "**/test", "one/two/test");
matches!(matchrec14, "**/test", "one/test");
matches!(matchrec15, "**/test", "test");
matches!(matchrec16, "/**/test", "/one/two/test");
matches!(matchrec17, "/**/test", "/one/test");
matches!(matchrec18, "/**/test", "/test");
matches!(matchrec19, "**/.*", ".abc");
matches!(matchrec20, "**/.*", "abc/.abc");
matches!(matchrec21, "**/foo/bar", "foo/bar");
matches!(matchrec22, ".*/**", ".abc/abc");
matches!(matchrec23, "test/**", "test/");
matches!(matchrec24, "test/**", "test/one");
matches!(matchrec25, "test/**", "test/one/two");
matches!(matchrec26, "some/*/needle.txt", "some/one/needle.txt");

matches!(matchrange1, "a[0-9]b", "a0b");
matches!(matchrange2, "a[0-9]b", "a9b");
matches!(matchrange3, "a[!0-9]b", "a_b");
matches!(matchrange4, "[a-z123]", "1");
matches!(matchrange5, "[1a-z23]", "1");
matches!(matchrange6, "[123a-z]", "1");
matches!(matchrange7, "[abc-]", "-");
matches!(matchrange8, "[-abc]", "-");
matches!(matchrange9, "[-a-c]", "b");
matches!(matchrange10, "[a-c-]", "b");
matches!(matchrange11, "[-]", "-");
matches!(matchrange12, "a[^0-9]b", "a_b");

matches!(matchpat1, "*hello.txt", "hello.txt");
matches!(matchpat2, "*hello.txt", "gareth_says_hello.txt");
matches!(matchpat3, "*hello.txt", "some/path/to/hello.txt");
matches!(matchpat4, "*hello.txt", "some\\path\\to\\hello.txt");
matches!(matchpat5, "*hello.txt", "/an/absolute/path/to/hello.txt");
matches!(matchpat6, "*some/path/to/hello.txt", "some/path/to/hello.txt");
matches!(matchpat7, "*some/path/to/hello.txt", "a/bigger/some/path/to/hello.txt");

matches!(matchescape, "_[[]_[]]_[?]_[*]_!_", "_[_]_?_*_!_");

matches!(matchcasei1, "aBcDeFg", "aBcDeFg", CASEI);
matches!(matchcasei2, "aBcDeFg", "abcdefg", CASEI);
matches!(matchcasei3, "aBcDeFg", "ABCDEFG", CASEI);
matches!(matchcasei4, "aBcDeFg", "AbCdEfG", CASEI);

matches!(matchalt1, "a,b", "a,b");
matches!(matchalt2, ",", ",");
matches!(matchalt3, "{a,b}", "a");
matches!(matchalt4, "{a,b}", "b");
matches!(matchalt5, "{**/src/**,foo}", "abc/src/bar");
matches!(matchalt6, "{**/src/**,foo}", "foo");
matches!(matchalt7, "{[}],foo}", "}");
matches!(matchalt8, "{foo}", "foo");
matches!(matchalt9, "{}", "");
matches!(matchalt10, "{,}", "");
matches!(matchalt11, "{*.foo,*.bar,*.wat}", "test.foo");
matches!(matchalt12, "{*.foo,*.bar,*.wat}", "test.bar");
matches!(matchalt13, "{*.foo,*.bar,*.wat}", "test.wat");
matches!(matchalt14, "foo{,.txt}", "foo.txt");
nmatches!(matchalt15, "foo{,.txt}", "foo");
matches!(matchalt16, "foo{,.txt}", "foo", EALTRE);
matches!(matchalt17, "{a,b{c,d}}", "bc");
matches!(matchalt18, "{a,b{c,d}}", "bd");
matches!(matchalt19, "{a,b{c,d}}", "a");

matches!(matchslash1, "abc/def", "abc/def", SLASHLIT);
#[cfg(unix)]
nmatches!(matchslash2, "abc?def", "abc/def", SLASHLIT);
#[cfg(not(unix))]
nmatches!(matchslash2, "abc?def", "abc\\def", SLASHLIT);
nmatches!(matchslash3, "abc*def", "abc/def", SLASHLIT);
matches!(matchslash4, "abc[/]def", "abc/def", SLASHLIT); // differs
#[cfg(unix)]
nmatches!(matchslash5, "abc\\def", "abc/def", SLASHLIT);
#[cfg(not(unix))]
matches!(matchslash5, "abc\\def", "abc/def", SLASHLIT);

matches!(matchbackslash1, "\\[", "[", BSESC);
matches!(matchbackslash2, "\\?", "?", BSESC);
matches!(matchbackslash3, "\\*", "*", BSESC);
matches!(matchbackslash4, "\\[a-z]", "\\a", NOBSESC);
matches!(matchbackslash5, "\\?", "\\a", NOBSESC);
matches!(matchbackslash6, "\\*", "\\\\", NOBSESC);
#[cfg(unix)]
matches!(matchbackslash7, "\\a", "a");
#[cfg(not(unix))]
matches!(matchbackslash8, "\\a", "/a");

nmatches!(matchnot1, "a*b*c", "abcd");
nmatches!(matchnot2, "abc*abc*abc", "abcabcabcabcabcabcabca");
nmatches!(matchnot3, "some/**/needle.txt", "some/other/notthis.txt");
nmatches!(matchnot4, "some/**/**/needle.txt", "some/other/notthis.txt");
nmatches!(matchnot5, "/**/test", "test");
nmatches!(matchnot6, "/**/test", "/one/notthis");
nmatches!(matchnot7, "/**/test", "/notthis");
nmatches!(matchnot8, "**/.*", "ab.c");
nmatches!(matchnot9, "**/.*", "abc/ab.c");
nmatches!(matchnot10, ".*/**", "a.bc");
nmatches!(matchnot11, ".*/**", "abc/a.bc");
nmatches!(matchnot12, "a[0-9]b", "a_b");
nmatches!(matchnot13, "a[!0-9]b", "a0b");
nmatches!(matchnot14, "a[!0-9]b", "a9b");
nmatches!(matchnot15, "[!-]", "-");
nmatches!(matchnot16, "*hello.txt", "hello.txt-and-then-some");
nmatches!(matchnot17, "*hello.txt", "goodbye.txt");
nmatches!(matchnot18, "*some/path/to/hello.txt", "some/path/to/hello.txt-and-then-some");
nmatches!(matchnot19, "*some/path/to/hello.txt", "some/other/path/to/hello.txt");
nmatches!(matchnot20, "a", "foo/a");
nmatches!(matchnot21, "./foo", "foo");
nmatches!(matchnot22, "**/foo", "foofoo");
nmatches!(matchnot23, "**/foo/bar", "foofoo/bar");
nmatches!(matchnot24, "/*.c", "mozilla-sha1/sha1.c");
nmatches!(matchnot25, "*.c", "mozilla-sha1/sha1.c", SLASHLIT);
nmatches!(
    matchnot26,
    "**/m4/ltoptions.m4",
    "csharp/src/packages/repositories.config",
    SLASHLIT
);
nmatches!(matchnot27, "a[^0-9]b", "a0b");
nmatches!(matchnot28, "a[^0-9]b", "a9b");
nmatches!(matchnot29, "[^-]", "-");
nmatches!(matchnot30, "some/*/needle.txt", "some/needle.txt");
nmatches!(matchrec31, "some/*/needle.txt", "some/one/two/needle.txt", SLASHLIT);
nmatches!(matchrec32, "some/*/needle.txt", "some/one/two/three/needle.txt", SLASHLIT);
nmatches!(matchrec33, ".*/**", ".abc");
nmatches!(matchrec34, "foo/**", "foo");
