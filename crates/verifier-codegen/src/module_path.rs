//! Validated relation namespaces for a complete generated module subtree.
#[derive(Clone, Debug)]
pub(crate) struct RelationModulePath {
    relative: String,
}

impl RelationModulePath {
    pub(crate) fn new(relative: impl Into<String>) -> Result<Self, String> {
        let relative = relative.into();
        if relative.split('/').any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || part.as_bytes()[0].is_ascii_digit()
        }) {
            return Err(format!("invalid relation module path: {relative}"));
        }
        Ok(Self { relative })
    }

    pub(crate) fn relative(&self) -> &str {
        &self.relative
    }

    pub(crate) fn qualify(&self, module: &str) -> String {
        format!("miden::core::sys::{}::{module}", self.relative.replace('/', "::"))
    }

    /// Rebind module imports only. Absolute references to the public PVM verifier in the proof
    /// request protocol deliberately keep their public identity across specialized subtrees.
    pub(crate) fn bind_pvm_imports(&self, source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        for line in source.split_inclusive('\n') {
            if let Some(module) = line.trim_end().strip_prefix("use miden::core::sys::pvm::") {
                out.push_str("use ");
                out.push_str(&self.qualify(module));
                if line.ends_with('\n') {
                    out.push('\n');
                }
            } else {
                out.push_str(line);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_binding_changes_imports_and_preserves_public_request_identity() {
        let path = RelationModulePath::new("pvm/relations/pvm_1").unwrap();
        assert_eq!(path.bind_pvm_imports("use miden::core::sys::pvm::layout\n    procref.::miden::core::sys::pvm::verify_proof\n"),
            "use miden::core::sys::pvm::relations::pvm_1::layout\n    procref.::miden::core::sys::pvm::verify_proof\n");
        for invalid in ["", "/pvm", "pvm/..", "pvm/a::b", "pvm/1"] {
            assert!(RelationModulePath::new(invalid).is_err());
        }
    }
}
