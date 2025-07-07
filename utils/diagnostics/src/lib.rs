#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod label;
mod related;
pub mod reporting;

pub use miette::{
    self, Diagnostic, IntoDiagnostic, LabeledSpan, NamedSource, Report, Result, Severity,
    SourceCode, WrapErr,
};
pub use tracing;

pub use self::{
    label::Label,
    related::{RelatedError, RelatedLabel},
};

#[macro_export]
macro_rules! report {
    ($($key:ident = $value:expr,)* $fmt:literal $($arg:tt)*) => {
        $crate::Report::from(
            $crate::diagnostic!($($key = $value,)* $fmt $($arg)*)
        )
    };
}

#[macro_export]
macro_rules! diagnostic {
    ($fmt:literal $($arg:tt)*) => {{
        $crate::miette::MietteDiagnostic::new(format!($fmt $($arg)*))
    }};
    ($($key:ident = $value:expr,)+ $fmt:literal $($arg:tt)*) => {{
        let mut diag = $crate::miette::MietteDiagnostic::new(format!($fmt $($arg)*));
        $(diag.$key = Some($value.into());)*
        diag
    }};
}
