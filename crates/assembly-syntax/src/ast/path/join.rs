use alloc::{boxed::Box, string::String, sync::Arc};

use super::*;
use crate::ast;

/// This trait is used to implement joining of a path or path component to a [Path] or [PathBuf].
///
/// This is required as the semantics of joining a path to a path, versus joining a string to a path
/// are not the same, but they are consistent for specific pairs of types.
///
/// This trait is public in order to use it as a constraint for [`Path::join`], but it is sealed to
/// only allow it to be implemented on [Path] and [PathBuf].
pub trait Join<T: ?Sized>: sealed::Joinable {
    /// Joins `other` to `self`, producing a new [PathBuf] containing the joined path.
    ///
    /// Implementations must choose one of two strategies for joining, depending on what `T`
    /// represents:
    ///
    /// 1. If `T` is a type that can represent a multi-component path, then you should prefer to
    ///    construct a [Path] or [PathBuf] from `T`, and delegate to `<Path as Join<Path>>::join`.
    ///    This approach is akin to converting `self` to a [PathBuf], and calling [`PathBuf::push`]
    ///    on it.
    /// 2. If `T` is a type that represents a symbol or single-component path, then you should
    ///    prefer to convert the `T` to a `&str`/`String`/`Ident` and delegate to the corresponding
    ///    implementation of `Join` for [Path]. This approach is akin to converting `self` to a
    ///    [PathBuf] and calliing [`PathBuf::push_component`] on it.
    fn join(&self, other: &T) -> PathBuf;
}

mod sealed {
    #[doc(hidden)]
    pub trait Joinable {}

    impl Joinable for crate::ast::Path {}
    impl Joinable for crate::ast::PathBuf {}
}

impl Join<Path> for Path {
    fn join(&self, other: &Path) -> PathBuf {
        if other.is_empty() {
            return self.to_path_buf();
        }

        if self.is_empty() {
            other.to_path_buf()
        } else if other.is_absolute() || other.is_in_kernel() || other.is_in_exec() {
            other.to_absolute().into_owned()
        } else {
            let mut buf = self.to_path_buf();
            buf.push(other);

            buf
        }
    }
}

impl Join<PathBuf> for Path {
    #[inline(always)]
    fn join(&self, other: &PathBuf) -> PathBuf {
        <Path as Join<Path>>::join(self, other.as_path())
    }
}

impl Join<str> for Path {
    fn join(&self, other: &str) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.push_component(other);
        buf
    }
}

impl Join<String> for Path {
    fn join(&self, other: &String) -> PathBuf {
        <Path as Join<str>>::join(self, other)
    }
}

impl Join<Box<str>> for Path {
    fn join(&self, other: &Box<str>) -> PathBuf {
        <Path as Join<str>>::join(self, other)
    }
}

impl Join<Arc<str>> for Path {
    fn join(&self, other: &Arc<str>) -> PathBuf {
        <Path as Join<str>>::join(self, other)
    }
}

impl Join<ast::Ident> for Path {
    fn join(&self, other: &ast::Ident) -> PathBuf {
        <Path as Join<str>>::join(self, other.as_str())
    }
}

impl Join<ast::ProcedureName> for Path {
    fn join(&self, other: &ast::ProcedureName) -> PathBuf {
        <Path as Join<str>>::join(self, other.as_str())
    }
}

impl Join<ast::QualifiedProcedureName> for Path {
    fn join(&self, other: &ast::QualifiedProcedureName) -> PathBuf {
        let mut buf = <Path as Join<Path>>::join(self, other.namespace());
        buf.push_component(other.name());
        buf
    }
}

impl Join<Path> for PathBuf {
    #[inline]
    fn join(&self, other: &Path) -> PathBuf {
        <Path as Join<Path>>::join(self.as_path(), other)
    }
}

impl Join<PathBuf> for PathBuf {
    #[inline(always)]
    fn join(&self, other: &PathBuf) -> PathBuf {
        <Path as Join<Path>>::join(self.as_path(), other.as_path())
    }
}

impl Join<str> for PathBuf {
    fn join(&self, other: &str) -> PathBuf {
        <Path as Join<str>>::join(self.as_path(), other)
    }
}

impl Join<String> for PathBuf {
    fn join(&self, other: &String) -> PathBuf {
        <Path as Join<str>>::join(self.as_path(), other)
    }
}

impl Join<Box<str>> for PathBuf {
    fn join(&self, other: &Box<str>) -> PathBuf {
        <Path as Join<str>>::join(self.as_path(), other)
    }
}

impl Join<Arc<str>> for PathBuf {
    fn join(&self, other: &Arc<str>) -> PathBuf {
        <Path as Join<str>>::join(self.as_path(), other)
    }
}

impl Join<ast::Ident> for PathBuf {
    fn join(&self, other: &ast::Ident) -> PathBuf {
        <Path as Join<ast::Ident>>::join(self.as_path(), other)
    }
}

impl Join<ast::ProcedureName> for PathBuf {
    fn join(&self, other: &ast::ProcedureName) -> PathBuf {
        <Path as Join<ast::ProcedureName>>::join(self.as_path(), other)
    }
}

impl Join<ast::QualifiedProcedureName> for PathBuf {
    fn join(&self, other: &ast::QualifiedProcedureName) -> PathBuf {
        <Path as Join<ast::QualifiedProcedureName>>::join(self.as_path(), other)
    }
}

#[cfg(test)]
mod tests {
    use miden_core::assert_matches;

    use super::*;

    #[test]
    fn test_join_path_to_path_plain() {
        let p1 = Path::new("foo");
        let p2 = Path::new("bar::baz");
        let joined = Join::join(p1, p2);
        assert_eq!(joined.as_path(), Path::new("foo::bar::baz"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_absolute_path_to_path_plain() {
        let p1 = Path::new("foo");
        let p2 = Path::new("::bar::baz");
        let joined = Join::join(p1, p2);
        assert_eq!(joined.as_path(), Path::new("::bar::baz"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_path_to_path_quoted() {
        let p1 = Path::new("foo");
        let p2 = Path::new("\"bar::baz\"::qux");
        let joined = Join::join(p1, p2);
        assert_eq!(joined.as_path(), Path::new("foo::\"bar::baz\"::qux"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar::baz\""))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("qux"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_path_to_absolute_path_quoted() {
        let p1 = Path::new("::foo");
        let p2 = Path::new("\"bar::baz\"::qux");
        let joined = Join::join(p1, p2);
        assert_eq!(joined.as_path(), Path::new("::foo::\"bar::baz\"::qux"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar::baz\""))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("qux"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_str_to_path_simple() {
        let p1 = Path::new("foo");
        let joined = Join::join(p1, "bar");
        assert_eq!(joined.as_path(), Path::new("foo::bar"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_str_to_path_multi_component_quoted() {
        let p1 = Path::new("foo");
        let joined = Join::join(p1, "\"bar::baz\"");
        assert_eq!(joined.as_path(), Path::new("foo::\"bar::baz\""));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar::baz\""))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_str_to_path_multi_component_unquoted() {
        let p1 = Path::new("foo");
        let joined = Join::join(p1, "bar::baz");
        assert_eq!(joined.as_path(), Path::new("foo::\"bar::baz\""));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar::baz\""))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn test_join_qualified_proc_name_to_path() {
        let p1 = Path::new("foo");
        let proc = ast::ProcedureName::new("qux").unwrap();
        let p2 = ast::QualifiedProcedureName::new("bar::baz", proc);
        let joined = Join::join(p1, &p2);
        assert_eq!(joined.as_path(), Path::new("foo::bar::baz::qux"));
        let mut components = joined.components();
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("qux"))));
        assert_matches!(components.next(), None);
    }
}
