use alloc::sync::Arc;

use miden_debug_types::FileLineCol;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Debug information describing one source-level function in an active inline call chain.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugInlineCallInfo {
    name: Arc<str>,
    linkage_name: Option<Arc<str>>,
    declaration: FileLineCol,
    call_site: FileLineCol,
}

impl DebugInlineCallInfo {
    pub fn new(
        name: impl Into<Arc<str>>,
        declaration: FileLineCol,
        call_site: FileLineCol,
    ) -> Self {
        Self {
            name: name.into(),
            linkage_name: None,
            declaration,
            call_site,
        }
    }

    pub fn with_linkage_name(mut self, linkage_name: impl Into<Arc<str>>) -> Self {
        self.linkage_name = Some(linkage_name.into());
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn linkage_name(&self) -> Option<&str> {
        self.linkage_name.as_deref()
    }

    pub fn declaration(&self) -> &FileLineCol {
        &self.declaration
    }

    pub fn call_site(&self) -> &FileLineCol {
        &self.call_site
    }
}
