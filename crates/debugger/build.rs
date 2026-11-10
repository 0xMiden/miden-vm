#[cfg(feature = "python")]
use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    #[cfg(feature = "python")]
    configure_python();
}

#[cfg(feature = "python")]
fn configure_python() {
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=PYO3_CONFIG_FILE");
    println!("cargo:rerun-if-env-changed=PYO3_NO_PYTHON");

    pyo3_build_config::use_pyo3_cfgs();
    pyo3_build_config::add_libpython_rpath_link_args();
    pyo3_build_config::add_python_framework_link_args();

    validate_python();
}

#[cfg(feature = "python")]
fn validate_python() {
    let config = pyo3_build_config::get();

    if config.implementation() != pyo3_build_config::PythonImplementation::CPython {
        panic!(
            "miden-debug Python scripting embeds CPython, but PyO3 selected {} {}. Set \
             PYO3_PYTHON to a CPython executable, or disable the `python` feature.",
            config.implementation(),
            config.version()
        );
    }

    if !config.shared() {
        panic!(
            "miden-debug Python scripting requires a shared libpython, but PyO3 selected a static \
             Python {} configuration. Set PYO3_PYTHON to an interpreter with a shared libpython, \
             or provide PYO3_CONFIG_FILE with shared=true.",
            config.version()
        );
    }

    if let Some(executable) = config.executable() {
        validate_python_executable(executable, &config.version().to_string());
    } else {
        println!(
            "cargo:warning=Python scripting is using PYO3_CONFIG_FILE/cross-compile metadata; no \
             host Python executable was available for an import smoke test"
        );
    }

    let framework_prefix = config.python_framework_prefix().filter(|path| !path.trim().is_empty());
    let lib_dir = config.lib_dir().filter(|path| !path.trim().is_empty());

    match (framework_prefix, lib_dir) {
        (Some(prefix), _) => validate_framework_prefix(prefix),
        (None, Some(lib_dir)) => validate_lib_dir(lib_dir),
        (None, None) => panic!(
            "miden-debug Python scripting requires a Python library directory or framework \
             prefix, but PyO3 did not report one. Set PYO3_PYTHON or PYO3_CONFIG_FILE to a \
             complete Python development installation."
        ),
    }
}

#[cfg(feature = "python")]
fn validate_python_executable(executable: &str, expected_version: &str) {
    let output = Command::new(executable)
        .arg("-c")
        .arg(
            "import ctypes, sys; version=f'{sys.version_info[0]}.{sys.version_info[1]}'; assert \
             version == __import__('os').environ['MIDEN_DEBUG_EXPECTED_PYTHON_VERSION']; \
             ctypes.pythonapi.Py_IsInitialized",
        )
        .env("MIDEN_DEBUG_EXPECTED_PYTHON_VERSION", expected_version)
        .output()
        .unwrap_or_else(|err| {
            panic!("failed to execute Python interpreter `{executable}` selected by PyO3: {err}")
        });

    if !output.status.success() {
        panic!(
            "Python interpreter `{}` selected by PyO3 failed the embed smoke \
             test.\nstdout:\n{}\nstderr:\n{}",
            executable,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[cfg(feature = "python")]
fn validate_framework_prefix(prefix: &str) {
    let prefix = Path::new(prefix);
    if !prefix.exists() {
        panic!(
            "PyO3 selected Python framework prefix `{}`, but it does not exist. Set PYO3_PYTHON \
             to a usable framework Python.",
            prefix.display()
        );
    }

    let framework = prefix.join("Python3.framework");
    if framework.exists() {
        return;
    }

    println!(
        "cargo:warning=PyO3 selected Python framework prefix `{}`, but Python3.framework was not \
         found directly under it; continuing because custom framework layouts are possible",
        prefix.display()
    );
}

#[cfg(feature = "python")]
fn validate_lib_dir(lib_dir: &str) {
    let lib_dir = PathBuf::from(lib_dir);
    if !lib_dir.exists() {
        panic!(
            "PyO3 selected Python library directory `{}`, but it does not exist. Set PYO3_PYTHON \
             to a Python installation with development libraries.",
            lib_dir.display()
        );
    }
}
