mod name;
#[allow(clippy::module_inception)]
mod procedure;

pub(crate) use self::procedure::InvokedIter;
pub use self::{
    name::{ProcedureName, QualifiedProcedureName},
    procedure::Procedure,
};
