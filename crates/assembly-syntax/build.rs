extern crate lalrpop;

use rustc_version::{Channel, version_meta};

fn main() {
    lalrpop::process_root().unwrap();

    // In cases where we want to compile with support for the standard library Error type (which
    // is used by all of our diagnostics, etc.), but we are compiling without the `std` feature,
    // we require use of the `error_in_core` feature, which is currently unstable, and thus requires
    // a nightly compiler.
    //
    // Exposing this as a `nightly` feature doesn't make sense, as you are either compiling with a
    // nightly compiler or not, and if you aren't, then enabling nightly features will just cause
    // compilation to fail unexpectedly. Instead, we detect the use of a nightly compiler, and
    // conditionally enable nightly features automatically when the nightly compiler is in use.
    //
    // To accomplish that goal, we set a `nightly` configuration variable, which can then be
    // referenced in `#[cfg]` directives, e.g. `#[cfg(nightly)]` or `#[cfg(not(nightly))]`.
    println!("cargo::rustc-check-cfg=cfg(nightly)");
    if let Channel::Nightly = version_meta().unwrap().channel {
        println!("cargo::rustc-cfg=nightly")
    }
}
