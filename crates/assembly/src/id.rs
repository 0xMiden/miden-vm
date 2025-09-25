use crate::ast::ProcedureIndex;

/// Uniquely identifies a procedure in a set of [crate::ast::Module]
///
/// A [GlobalProcedureIndex] is assigned to a procedure when it is added to the linker's module
/// graph. The index uniquely identifies that procedure in the graph, and provides a unique,
/// copyable, machine-word sized handle that can be trivially stored, passed around, and later used
/// to perform constant-complexity operations against that procedure.
///
/// <div class="warning">
/// As a result of this being just an index into a specific instance of a [super::ModuleGraph],
/// it does not provide any guarantees about uniqueness or stability when the same module is stored
/// in multiple graphs - each graph may assign it a unique index. You must ensure that you do not
/// store these indices and attempt to use them with just any module graph - it is only valid with
/// the one it was assigned from.
/// </div>
///
/// In addition to the linker's module graph, these indices are also used with an instance of a
/// `MastForestBuilder`. This is because the linker and `MastForestBuilder` instances
/// are paired, i.e. the linker stores the syntax trees and call graph analysis for a program, while
/// the `MastForestBuilder` caches the compiled [crate::Procedure]s for the same program, as
/// derived from the corresponding graph.
///
/// This is intended for use when we are doing global inter-procedural analysis on a (possibly
/// growable) set of modules. It is expected that the index of a module in the set, as well as the
/// index of a procedure in a module, are stable once allocated in the graph. The set of modules and
/// functions can grow, as long as growing the set only allocates unused identifiers.
///
/// NOTE: This struct is the same size as a u32
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobalProcedureIndex {
    /// The index of the containing module in the global set of modules
    pub module: ModuleIndex,
    /// The local index of the procedure in the module
    pub index: ProcedureIndex,
}

/// A strongly-typed index into a set of [crate::ast::Module]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ModuleIndex(u16);
impl ModuleIndex {
    pub fn new(index: usize) -> Self {
        Self(index.try_into().expect("invalid module index: too many modules"))
    }

    #[cfg(test)]
    pub const fn const_new(index: u16) -> Self {
        Self(index)
    }

    #[inline(always)]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl core::ops::Add<ProcedureIndex> for ModuleIndex {
    type Output = GlobalProcedureIndex;

    fn add(self, rhs: ProcedureIndex) -> Self::Output {
        GlobalProcedureIndex { module: self, index: rhs }
    }
}

impl core::fmt::Display for ModuleIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.as_usize())
    }
}
