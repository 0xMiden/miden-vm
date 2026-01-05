//! Rendering and error reporting implementation details.
use core::fmt;

pub use miette::{
    DebugReportHandler, JSONReportHandler, NarratableReportHandler, ReportHandler, set_hook,
};
#[cfg(feature = "std")]
pub use miette::{GraphicalReportHandler, GraphicalTheme};

// set_panic_hook is only available with fancy or fancy-no-backtrace features,
// not with fancy-no-syscall. Since we use fancy-no-syscall to avoid syscall
// dependencies, we provide a no-op stub for compatibility.
#[cfg(feature = "std")]
pub fn set_panic_hook() {
    // No-op when using fancy-no-syscall feature
    // The fancy-no-syscall feature doesn't include panic hook support
}

pub type ReportHandlerOpts = miette::MietteHandlerOpts;

#[cfg(feature = "std")]
pub type DefaultReportHandler = miette::GraphicalReportHandler;

#[cfg(not(feature = "std"))]
pub type DefaultReportHandler = miette::DebugReportHandler;

/// A type that can be used to render a [super::Diagnostic] via [core::fmt::Display]
pub struct PrintDiagnostic<D, R = DefaultReportHandler> {
    handler: R,
    diag: D,
}

impl<D: AsRef<dyn super::Diagnostic>> PrintDiagnostic<D> {
    pub fn new(diag: D) -> Self {
        Self { handler: Default::default(), diag }
    }
    #[cfg(feature = "std")]
    pub fn new_without_color(diag: D) -> Self {
        Self {
            handler: DefaultReportHandler::new_themed(GraphicalTheme::none()),
            diag,
        }
    }
    #[cfg(not(feature = "std"))]
    pub fn new_without_color(diag: D) -> Self {
        Self::new(diag)
    }
}

impl<D: AsRef<dyn super::Diagnostic>> PrintDiagnostic<D, NarratableReportHandler> {
    pub fn narrated(diag: D) -> Self {
        Self {
            handler: NarratableReportHandler::default(),
            diag,
        }
    }
}

impl<D: AsRef<dyn super::Diagnostic>> PrintDiagnostic<D, JSONReportHandler> {
    pub fn json(diag: D) -> Self {
        Self { handler: JSONReportHandler, diag }
    }
}

impl<D: AsRef<dyn super::Diagnostic>> fmt::Display for PrintDiagnostic<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
        self.handler.render_report(f, self.diag.as_ref())
    }
}

impl<D: AsRef<dyn super::Diagnostic>> fmt::Display for PrintDiagnostic<D, NarratableReportHandler> {
    fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
        self.handler.render_report(f, self.diag.as_ref())
    }
}

impl<D: AsRef<dyn super::Diagnostic>> fmt::Display for PrintDiagnostic<D, JSONReportHandler> {
    fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
        self.handler.render_report(f, self.diag.as_ref())
    }
}
