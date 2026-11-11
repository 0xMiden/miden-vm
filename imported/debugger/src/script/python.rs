use std::{
    cell::RefCell,
    collections::{BTreeMap, hash_map::DefaultHasher},
    ffi::CString,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};

use pyo3::{
    exceptions::{PyKeyError, PyRuntimeError, PySyntaxError},
    prelude::*,
    types::{PyDict, PyModule},
};

use super::{ScriptBreakpoint, ScriptDebugger, ScriptFrame, ScriptSourceLocation, ScriptValue};

type SharedDebugger = Rc<RefCell<ScriptDebugger>>;

#[cfg(test)]
pub(crate) use tests::python_test_lock;

/// Embedded Python scripting session.
///
/// The session owns the current debugger handle plus a persistent globals
/// dictionary. REPL integration can execute snippets against that dictionary so
/// variables, imports, and registered callbacks persist across `script`
/// commands.
pub struct PythonScriptSession {
    debugger: SharedDebugger,
    globals: Py<PyDict>,
    internal_dict: Py<PyDict>,
    modules: RefCell<Vec<Py<PyModule>>>,
    custom_commands: RefCell<BTreeMap<String, Py<PyAny>>>,
    breakpoint_callbacks: RefCell<BTreeMap<u8, Py<PyAny>>>,
}

impl PythonScriptSession {
    /// Create a Python scripting session over an existing script debugger.
    pub fn new(debugger: ScriptDebugger) -> PyResult<Self> {
        Python::attach(|py| {
            let debugger = Rc::new(RefCell::new(debugger));
            let module = create_miden_debugger_module(py, debugger.clone())?;
            let globals = PyDict::new(py);
            let internal_dict = PyDict::new(py);
            let builtins = py.import("builtins")?;
            globals.set_item("__builtins__", builtins)?;
            globals.set_item("miden_debugger", module.clone())?;
            globals.set_item("internal_dict", internal_dict.clone())?;
            globals.set_item("debugger", module.getattr("debugger")?)?;
            globals.set_item("target", module.getattr("target")?)?;
            globals.set_item("process", module.getattr("process")?)?;
            globals.set_item("thread", module.getattr("thread")?)?;
            globals.set_item("frame", module.getattr("frame")?)?;

            Ok(Self {
                debugger,
                globals: globals.unbind(),
                internal_dict: internal_dict.unbind(),
                modules: RefCell::default(),
                custom_commands: RefCell::default(),
                breakpoint_callbacks: RefCell::default(),
            })
        })
    }

    /// Return a Python wrapper around the current debugger.
    pub fn debugger(&self) -> PyDebugger {
        PyDebugger::new(self.debugger.clone())
    }

    /// Access the persistent Python globals dictionary for this session.
    pub fn with_globals<R>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&Bound<'_, PyDict>) -> PyResult<R>,
    ) -> PyResult<R> {
        f(self.globals.bind(py))
    }

    /// Execute one Python snippet in this session's persistent globals.
    ///
    /// Expressions print their `repr()` when they evaluate to a non-`None`
    /// value. Statements are executed with no synthetic output.
    pub fn execute_snippet(&self, code: &str) -> Result<String, String> {
        Python::attach(|py| {
            self.with_globals(py, |globals| {
                let code = CString::new(code)
                    .map_err(|_| PyRuntimeError::new_err("Python code contains a NUL byte"))?;

                match py.eval(code.as_c_str(), Some(globals), Some(globals)) {
                    Ok(value) if value.is_none() => Ok(String::new()),
                    Ok(value) => Ok(format!("{}\n", value.repr()?.to_str()?)),
                    Err(err) if err.is_instance_of::<PySyntaxError>(py) => {
                        py.run(code.as_c_str(), Some(globals), Some(globals))?;
                        Ok(String::new())
                    }
                    Err(err) => Err(err),
                }
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Enter Python's standard interactive console with this session's globals.
    pub fn interact(&self) -> Result<(), String> {
        Python::attach(|py| {
            self.with_globals(py, |globals| {
                let code = py.import("code")?;
                let kwargs = PyDict::new(py);
                kwargs.set_item("banner", "Miden Debugger Python console")?;
                kwargs.set_item("local", globals)?;
                code.call_method("interact", (), Some(&kwargs))?;
                Ok(())
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Import a Python file into this session.
    ///
    /// If the module defines `__miden_init_module(debugger, internal_dict)`, the
    /// initializer is called after the module has been executed.
    pub fn import_file(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = canonical_python_path(path.as_ref())?;
        let module_name = module_name_for_path(&path);
        let module_alias = module_alias_for_path(&path);
        let path_string = path.to_string_lossy().into_owned();

        Python::attach(|py| {
            self.with_globals(py, |_| {
                let importlib_util = py.import("importlib.util")?;
                let sys = py.import("sys")?;
                let spec = importlib_util
                    .call_method1("spec_from_file_location", (&module_name, &path_string))?;
                if spec.is_none() {
                    return Err(PyRuntimeError::new_err(format!(
                        "failed to create import spec for {}",
                        path.display()
                    )));
                }

                let module = importlib_util.call_method1("module_from_spec", (&spec,))?;
                sys.getattr("modules")?.set_item(&module_name, &module)?;
                sys.getattr("modules")?.set_item(&module_alias, &module)?;
                spec.getattr("loader")?.call_method1("exec_module", (&module,))?;

                if let Ok(init) = module.getattr("__miden_init_module") {
                    let miden_module = py.import("miden_debugger")?;
                    init.call1((miden_module.getattr("debugger")?, self.internal_dict.bind(py)))?;
                }

                self.modules.borrow_mut().push(module.cast_into::<PyModule>()?.unbind());
                Ok(())
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Register a Python-backed custom debugger command.
    pub fn add_custom_command(&self, name: &str, function_path: &str) -> Result<(), String> {
        validate_custom_command_name(name)?;
        Python::attach(|py| {
            self.with_globals(py, |globals| {
                let function = resolve_python_callable(py, globals, function_path)?;
                self.custom_commands.borrow_mut().insert(name.into(), function);
                Ok(())
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Return registered custom command names.
    pub fn custom_commands(&self) -> Vec<String> {
        self.custom_commands.borrow().keys().cloned().collect()
    }

    /// Delete a registered custom command.
    pub fn delete_custom_command(&self, name: &str) -> Result<(), String> {
        if self.custom_commands.borrow_mut().remove(name).is_some() {
            Ok(())
        } else {
            Err(format!("no Python command named `{name}`"))
        }
    }

    /// Execute a registered custom command.
    pub fn execute_custom_command(&self, name: &str, args: &str) -> Result<Option<String>, String> {
        Python::attach(|py| {
            self.with_globals(py, |_| {
                let Some(function) =
                    self.custom_commands.borrow().get(name).map(|function| function.clone_ref(py))
                else {
                    return Ok(None);
                };

                let result = Py::new(py, PyCommandResult::default())?;
                function.call1(
                    py,
                    (
                        PyDebugger::new(self.debugger.clone()),
                        args,
                        PyExecutionContext::new(self.debugger.clone()),
                        result.clone_ref(py),
                        self.internal_dict.bind(py),
                    ),
                )?;

                let result = result.borrow(py);
                if let Some(error) = result.error() {
                    return Err(PyRuntimeError::new_err(error));
                }
                Ok(Some(result.output()))
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Register a Python callback for a breakpoint id.
    pub fn add_breakpoint_callback(&self, id: u8, function_path: &str) -> Result<(), String> {
        let exists = self.debugger.borrow().breakpoints().iter().any(|bp| bp.id == id);
        if !exists {
            return Err(format!("no breakpoint with id {id}"));
        }

        Python::attach(|py| {
            self.with_globals(py, |globals| {
                let function = resolve_python_callable(py, globals, function_path)?;
                self.breakpoint_callbacks.borrow_mut().insert(id, function);
                Ok(())
            })
        })
        .map_err(|err| err.to_string())
    }

    /// Return breakpoint ids with registered Python callbacks.
    pub fn breakpoint_callbacks(&self) -> Vec<u8> {
        self.breakpoint_callbacks.borrow().keys().copied().collect()
    }

    /// Delete one breakpoint callback, or all callbacks when `id` is `None`.
    pub fn delete_breakpoint_callback(&self, id: Option<u8>) -> Result<(), String> {
        match id {
            Some(id) => {
                if self.breakpoint_callbacks.borrow_mut().remove(&id).is_some() {
                    Ok(())
                } else {
                    Err(format!("no Python callback registered for breakpoint {id}"))
                }
            }
            None => {
                self.breakpoint_callbacks.borrow_mut().clear();
                Ok(())
            }
        }
    }

    /// Evaluate callbacks for the current hit breakpoints.
    pub fn should_continue_after_breakpoint_callbacks(&self) -> Result<bool, String> {
        let hit_breakpoints = self.debugger.borrow().hit_breakpoints();
        if hit_breakpoints.is_empty() {
            return Ok(false);
        }

        Python::attach(|py| {
            self.with_globals(py, |_| {
                for breakpoint in hit_breakpoints {
                    let Some(callback) = self
                        .breakpoint_callbacks
                        .borrow()
                        .get(&breakpoint.id)
                        .map(|callback| callback.clone_ref(py))
                    else {
                        return Ok(false);
                    };

                    let result = callback.call1(
                        py,
                        (
                            PyFrame::new(self.debugger.clone()),
                            PyBreakpoint::new(self.debugger.clone(), breakpoint.id),
                            self.internal_dict.bind(py),
                        ),
                    )?;
                    if !result.is_none(py) && result.is_truthy(py)? {
                        return Ok(false);
                    }
                }

                Ok(true)
            })
        })
        .map_err(|err| err.to_string())
    }
}

impl Drop for PythonScriptSession {
    fn drop(&mut self) {
        let _ = Python::try_attach(|py| {
            if let Ok(sys) = py.import("sys")
                && let Ok(modules) = sys.getattr("modules")
            {
                let _ = modules.del_item("miden_debugger");
            }
            self.globals.bind(py).clear();
            self.internal_dict.bind(py).clear();
            self.modules.borrow_mut().clear();
            self.custom_commands.borrow_mut().clear();
            self.breakpoint_callbacks.borrow_mut().clear();
        });
    }
}

fn canonical_python_path(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|err| format!("failed to resolve Python script {}: {err}", path.display()))
}

fn module_name_for_path(path: &Path) -> String {
    let sanitized_stem = module_alias_for_path(path);
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    format!("miden_debugger_user_{}_{}", sanitized_stem, hasher.finish())
}

fn module_alias_for_path(path: &Path) -> String {
    let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("script");
    let alias = stem
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    if alias.is_empty() {
        "script".into()
    } else {
        alias
    }
}

fn validate_custom_command_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Python command name must not be empty".into());
    }
    if name.chars().any(char::is_whitespace) {
        return Err(format!("Python command name `{name}` must not contain whitespace"));
    }
    Ok(())
}

fn resolve_python_callable(
    py: Python<'_>,
    globals: &Bound<'_, PyDict>,
    function_path: &str,
) -> PyResult<Py<PyAny>> {
    let object = if let Some((module_name, attr_path)) = function_path.split_once('.') {
        let mut object: Bound<'_, PyAny> = py.import(module_name)?.into_any();
        for attr in attr_path.split('.') {
            object = object.getattr(attr)?;
        }
        object
    } else {
        globals.get_item(function_path)?.ok_or_else(|| {
            PyKeyError::new_err(format!("no Python object named `{function_path}`"))
        })?
    };

    if object.is_callable() {
        Ok(object.unbind())
    } else {
        Err(PyRuntimeError::new_err(format!("`{function_path}` is not callable")))
    }
}

fn create_miden_debugger_module(
    py: Python<'_>,
    debugger: SharedDebugger,
) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new(py, "miden_debugger")?;
    module.add_class::<PyDebugger>()?;
    module.add_class::<PyTarget>()?;
    module.add_class::<PyProcess>()?;
    module.add_class::<PyThread>()?;
    module.add_class::<PyFrame>()?;
    module.add_class::<PyBreakpoint>()?;
    module.add_class::<PyValue>()?;
    module.add_class::<PySourceLocation>()?;
    module.add_class::<PyExecutionContext>()?;
    module.add_class::<PyCommandResult>()?;

    module.add("debugger", PyDebugger::new(debugger.clone()))?;
    module.add("target", PyTarget::new(debugger.clone()))?;
    module.add("process", PyProcess::new(debugger.clone()))?;
    module.add("thread", PyThread::new(debugger.clone()))?;
    module.add("frame", PyFrame::new(debugger.clone()))?;

    py.import("sys")?.getattr("modules")?.set_item("miden_debugger", &module)?;

    Ok(module)
}

fn py_error(error: String) -> PyErr {
    PyRuntimeError::new_err(error)
}

fn find_breakpoint(debugger: &SharedDebugger, id: u8) -> PyResult<ScriptBreakpoint> {
    debugger
        .borrow()
        .breakpoints()
        .into_iter()
        .find(|bp| bp.id == id)
        .ok_or_else(|| PyKeyError::new_err(format!("no breakpoint with id {id}")))
}

#[pyclass(name = "Debugger", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyDebugger {
    debugger: SharedDebugger,
}

impl PyDebugger {
    fn new(debugger: SharedDebugger) -> Self {
        Self { debugger }
    }
}

#[pymethods]
impl PyDebugger {
    fn handle_command(&self, command: &str) -> PyResult<String> {
        self.debugger.borrow_mut().handle_command(command).map_err(py_error)
    }

    fn get_selected_target(&self) -> PyTarget {
        PyTarget::new(self.debugger.clone())
    }

    fn get_cycle(&self) -> usize {
        self.debugger.borrow().cycle()
    }

    fn get_breakpoints(&self) -> Vec<PyBreakpoint> {
        self.debugger
            .borrow()
            .breakpoints()
            .into_iter()
            .map(|bp| PyBreakpoint::new(self.debugger.clone(), bp.id))
            .collect()
    }

    fn set_breakpoint(&self, spec: &str) -> PyResult<PyBreakpoint> {
        let bp = self.debugger.borrow_mut().set_breakpoint(spec).map_err(py_error)?;
        Ok(PyBreakpoint::new(self.debugger.clone(), bp.id))
    }

    fn delete_breakpoint(&self, id: Option<u8>) -> PyResult<()> {
        self.debugger.borrow_mut().delete_breakpoint(id).map_err(py_error)
    }

    fn __repr__(&self) -> String {
        format!("Debugger(cycle={})", self.get_cycle())
    }
}

#[pyclass(name = "Target", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyTarget {
    debugger: SharedDebugger,
}

impl PyTarget {
    fn new(debugger: SharedDebugger) -> Self {
        Self { debugger }
    }
}

#[pymethods]
impl PyTarget {
    fn process(&self) -> PyProcess {
        PyProcess::new(self.debugger.clone())
    }

    fn source_path_prefixes(&self) -> Vec<String> {
        self.debugger.borrow().source_path_prefixes()
    }

    fn __repr__(&self) -> &'static str {
        "Target()"
    }
}

#[pyclass(name = "Process", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyProcess {
    debugger: SharedDebugger,
}

impl PyProcess {
    fn new(debugger: SharedDebugger) -> Self {
        Self { debugger }
    }
}

#[pymethods]
impl PyProcess {
    fn is_stopped(&self) -> bool {
        self.debugger.borrow().stopped()
    }

    fn is_terminated(&self) -> bool {
        self.debugger.borrow().terminated()
    }

    fn continue_(&self) -> PyResult<String> {
        self.debugger.borrow_mut().continue_().map_err(py_error)
    }

    fn step(&self, count: Option<usize>) -> PyResult<String> {
        self.debugger.borrow_mut().step(count.unwrap_or(1)).map_err(py_error)
    }

    fn next(&self) -> PyResult<String> {
        self.debugger.borrow_mut().next().map_err(py_error)
    }

    fn next_line(&self) -> PyResult<String> {
        self.debugger.borrow_mut().next_line().map_err(py_error)
    }

    fn finish(&self) -> PyResult<String> {
        self.debugger.borrow_mut().finish().map_err(py_error)
    }

    fn stack(&self) -> Vec<u64> {
        self.debugger.borrow().stack()
    }

    fn read_memory(&self, expression: &str) -> PyResult<String> {
        self.debugger.borrow_mut().read_memory(expression).map_err(py_error)
    }

    fn __repr__(&self) -> String {
        format!("Process(stopped={}, terminated={})", self.is_stopped(), self.is_terminated())
    }
}

#[pyclass(name = "Thread", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyThread {
    debugger: SharedDebugger,
}

impl PyThread {
    fn new(debugger: SharedDebugger) -> Self {
        Self { debugger }
    }
}

#[pymethods]
impl PyThread {
    fn frames(&self) -> Vec<PyFrame> {
        let count = self.debugger.borrow().frame_count();
        (0..count)
            .filter_map(|index| PyFrame::snapshot(self.debugger.clone(), index))
            .collect()
    }

    fn selected_frame(&self) -> PyFrame {
        let index = self.debugger.borrow().selected_frame_index();
        PyFrame::snapshot(self.debugger.clone(), index)
            .unwrap_or_else(|| PyFrame::new(self.debugger.clone()))
    }

    fn __repr__(&self) -> &'static str {
        "Thread()"
    }
}

#[pyclass(name = "ExecutionContext", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyExecutionContext {
    debugger: SharedDebugger,
}

impl PyExecutionContext {
    fn new(debugger: SharedDebugger) -> Self {
        Self { debugger }
    }
}

#[pymethods]
impl PyExecutionContext {
    fn target(&self) -> PyTarget {
        PyTarget::new(self.debugger.clone())
    }

    fn process(&self) -> PyProcess {
        PyProcess::new(self.debugger.clone())
    }

    fn thread(&self) -> PyThread {
        PyThread::new(self.debugger.clone())
    }

    fn frame(&self) -> PyFrame {
        PyFrame::new(self.debugger.clone())
    }

    fn cycle(&self) -> usize {
        self.debugger.borrow().cycle()
    }

    fn __repr__(&self) -> String {
        format!("ExecutionContext(cycle={})", self.cycle())
    }
}

#[pyclass(name = "CommandResult", unsendable, skip_from_py_object)]
#[derive(Default)]
pub struct PyCommandResult {
    output: RefCell<String>,
    error: RefCell<Option<String>>,
}

impl PyCommandResult {
    fn output(&self) -> String {
        self.output.borrow().clone()
    }

    fn error(&self) -> Option<String> {
        self.error.borrow().clone()
    }
}

#[pymethods]
impl PyCommandResult {
    fn write(&self, text: &str) {
        self.output.borrow_mut().push_str(text);
    }

    fn flush(&self) {}

    fn set_error(&self, message: &str) {
        *self.error.borrow_mut() = Some(message.into());
    }

    fn clear(&self) {
        self.output.borrow_mut().clear();
        self.error.borrow_mut().take();
    }

    fn succeeded(&self) -> bool {
        self.error.borrow().is_none()
    }

    fn __repr__(&self) -> String {
        match self.error() {
            Some(error) => format!("CommandResult(error={error:?})"),
            None => format!("CommandResult(output={:?})", self.output()),
        }
    }
}

#[pyclass(name = "Frame", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyFrame {
    debugger: SharedDebugger,
    /// Enumerated frames are stop-time snapshots; the global/callback frame remains live.
    snapshot: Option<(ScriptFrame, Vec<ScriptValue>)>,
}

impl PyFrame {
    fn new(debugger: SharedDebugger) -> Self {
        Self {
            debugger,
            snapshot: None,
        }
    }

    fn snapshot(debugger: SharedDebugger, index: usize) -> Option<Self> {
        let frame = debugger.borrow().frame_at(index, false)?;
        let all = debugger.borrow().frame_at(index, true)?.variables;
        Some(Self {
            debugger,
            snapshot: Some((frame, all)),
        })
    }
}

#[pymethods]
impl PyFrame {
    fn function_name(&self) -> Option<String> {
        self.snapshot.as_ref().map_or_else(
            || self.debugger.borrow().frame().function_name,
            |(frame, _)| frame.function_name.clone(),
        )
    }

    fn source_location(&self) -> Option<PySourceLocation> {
        self.snapshot
            .as_ref()
            .map_or_else(
                || self.debugger.borrow().frame().source_location,
                |(frame, _)| frame.source_location.clone(),
            )
            .map(PySourceLocation::from)
    }

    fn variables(&self, py: Python<'_>, all: Option<bool>) -> PyResult<Py<PyDict>> {
        let show_all = all.unwrap_or(false);
        let values = self.snapshot.as_ref().map_or_else(
            || self.debugger.borrow().frame_with_variables(show_all).variables,
            |(frame, all)| {
                if show_all {
                    all.clone()
                } else {
                    frame.variables.clone()
                }
            },
        );
        let variables = PyDict::new(py);
        for value in values {
            variables.set_item(value.name.clone(), PyValue::from(value))?;
        }
        Ok(variables.unbind())
    }

    fn __repr__(&self) -> String {
        match self.function_name() {
            Some(function) => format!("Frame(function_name={function:?})"),
            None => "Frame(function_name=None)".into(),
        }
    }
}

#[pyclass(name = "Breakpoint", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyBreakpoint {
    debugger: SharedDebugger,
    id: u8,
}

impl PyBreakpoint {
    fn new(debugger: SharedDebugger, id: u8) -> Self {
        Self { debugger, id }
    }

    fn snapshot(&self) -> PyResult<ScriptBreakpoint> {
        find_breakpoint(&self.debugger, self.id)
    }
}

#[pymethods]
impl PyBreakpoint {
    #[getter]
    fn id(&self) -> u8 {
        self.id
    }

    #[getter]
    fn spec(&self) -> PyResult<String> {
        Ok(self.snapshot()?.spec)
    }

    #[getter]
    fn internal(&self) -> PyResult<bool> {
        Ok(self.snapshot()?.internal)
    }

    #[getter]
    fn one_shot(&self) -> PyResult<bool> {
        Ok(self.snapshot()?.one_shot)
    }

    fn delete(&self) -> PyResult<()> {
        self.debugger.borrow_mut().delete_breakpoint(Some(self.id)).map_err(py_error)
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Breakpoint(id={}, spec={:?})", self.id, self.spec()?))
    }
}

#[pyclass(name = "Value", unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct PyValue {
    name: String,
    value: Option<u64>,
    display_value: Option<String>,
    location: String,
    source: Option<PySourceLocation>,
}

impl From<ScriptValue> for PyValue {
    fn from(value: ScriptValue) -> Self {
        Self {
            name: value.name,
            value: value.value,
            display_value: value.display_value,
            location: value.location,
            source: value.source.map(PySourceLocation::from),
        }
    }
}

#[pymethods]
impl PyValue {
    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    #[getter]
    fn value(&self) -> Option<u64> {
        self.value
    }

    #[getter]
    fn display_value(&self) -> Option<String> {
        self.display_value.clone()
    }

    #[getter]
    fn location(&self) -> String {
        self.location.clone()
    }

    #[getter]
    fn source(&self) -> Option<PySourceLocation> {
        self.source.clone()
    }

    fn __repr__(&self) -> String {
        match self.value {
            Some(value) => format!("Value(name={:?}, value={value})", self.name),
            None => format!("Value(name={:?}, value=None)", self.name),
        }
    }
}

#[pyclass(name = "SourceLocation", unsendable, skip_from_py_object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PySourceLocation {
    path: String,
    line: u32,
    column: u32,
}

impl From<ScriptSourceLocation> for PySourceLocation {
    fn from(location: ScriptSourceLocation) -> Self {
        Self {
            path: location.path,
            line: location.line,
            column: location.column,
        }
    }
}

#[pymethods]
impl PySourceLocation {
    #[getter]
    fn path(&self) -> String {
        self.path.clone()
    }

    #[getter]
    fn line(&self) -> u32 {
        self.line
    }

    #[getter]
    fn column(&self) -> u32 {
        self.column
    }

    fn __repr__(&self) -> String {
        format!(
            "SourceLocation(path={:?}, line={}, column={})",
            self.path, self.line, self.column
        )
    }
}

#[cfg(test)]
mod tests;
