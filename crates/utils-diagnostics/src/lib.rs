#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod diagnostic;
mod label;
mod related;
mod report;
pub mod reporting;
#[cfg(test)]
mod tests;

pub use tracing;

pub use self::{
    diagnostic::{Diagnostic, DiagnosticDetails, MessageDiagnostic, Severity},
    label::Label,
    related::{RelatedError, RelatedLabel},
    report::{IntoDiagnostic, Report, Result, WrapErr},
};

pub type LabeledSpan = Label;

#[doc(hidden)]
pub use alloc::format;

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
        $crate::MessageDiagnostic::new($crate::format!($fmt $($arg)*))
    }};
    ($($key:ident = $value:expr,)+ $fmt:literal $($arg:tt)*) => {{
        let mut diag = $crate::MessageDiagnostic::new($crate::format!($fmt $($arg)*));
        $(diag.$key = Some($value.into());)*
        diag
    }};
}
