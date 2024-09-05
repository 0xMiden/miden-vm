#![no_std]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc};

use assembly::{mast::MastForest, utils::Deserializable, Library};

// STANDARD LIBRARY
// ================================================================================================

/// TODO: add docs
#[derive(Clone)]
pub struct StdLibrary(Library);

impl AsRef<Library> for StdLibrary {
    fn as_ref(&self) -> &Library {
        &self.0
    }
}

impl From<StdLibrary> for Library {
    fn from(value: StdLibrary) -> Self {
        value.0
    }
}

impl StdLibrary {
    /// Serialized representation of the Miden standard library.
    pub const SERIALIZED: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/std.masl"));

    /// Returns a reference to the [MastForest] underlying the Miden standard library.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }
}

impl Default for StdLibrary {
    fn default() -> Self {
        static STDLIB: once_cell::race::OnceBox<StdLibrary> = once_cell::race::OnceBox::new();
        STDLIB
            .get_or_init(|| {
                let contents =
                    Library::read_from_bytes(Self::SERIALIZED).expect("failed to read std masl!");
                Box::new(Self(contents))
            })
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use assembly::LibraryPath;

    use super::*;

    #[test]
    fn test_compile() {
        let path = "std::math::u64::overflowing_add".parse::<LibraryPath>().unwrap();
        let stdlib = StdLibrary::default();
        let exists = stdlib.0.module_infos().any(|module| {
            module
                .procedures()
                .any(|(_, proc)| module.path().clone().append(&proc.name).unwrap() == path)
        });

        assert!(exists);
    }
}
