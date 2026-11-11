/// This represents a descriptor for a pointer translated from the IR into a form suitable for
/// referencing data in Miden's linear memory.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NativePtr {
    /// This is the address of the element containing the first byte of data
    ///
    /// Each element is assumed to be a 32-bit value/chunk
    pub addr: u32,
    /// This is the byte offset into the 32-bit chunk referenced by `index`
    ///
    /// This offset is where the data referenced by the pointer actually starts.
    pub offset: u8,
    /// This is the assumed address space of the pointer value.
    ///
    /// This address space is unknown by default, but can be specified if known statically.
    /// The address space determines whether the pointer is valid in certain contexts. For
    /// example, attempting to load a pointer with address space 0 is invalid if not operating
    /// in the root context.
    ///
    /// Currently this has no effect, but is here as we expand support for multiple memories.
    pub addrspace: miden_assembly_syntax::ast::types::AddressSpace,
}
impl NativePtr {
    pub fn new(addr: u32, offset: u8) -> Self {
        Self {
            addr,
            offset,
            addrspace: Default::default(),
        }
    }

    /// Translates a raw pointer (assumed to be in a byte-addressable address space) to a native
    /// pointer value, in the default [hir::AddressSpace].
    pub fn from_ptr(addr: u32) -> Self {
        // The native word address for `addr` is derived by splitting the byte-addressable space
        // into 32-bit chunks, each chunk belonging to a single field element, i.e. each element
        // of the native address space represents 32 bits of byte-addressable memory.
        //
        // By dividing `addr` by 4, we get the element address where the data starts.
        let eaddr = addr / 4;
        // If our address is not element-aligned, we need to determine what byte offset contains
        // the first byte of the data.
        let offset = (addr % 4) as u8;
        Self {
            addr: eaddr,
            offset,
            addrspace: Default::default(),
        }
    }

    /// Returns true if this pointer is aligned to a word boundary
    pub const fn is_word_aligned(&self) -> bool {
        self.offset == 0 && self.addr.is_multiple_of(4)
    }

    /// Returns true if this pointer is aligned to a field element boundary
    pub const fn is_element_aligned(&self) -> bool {
        self.offset == 0
    }
}

#[cfg(test)]
mod tests;
