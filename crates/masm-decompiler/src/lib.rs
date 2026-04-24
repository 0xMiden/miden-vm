pub mod callgraph;
pub mod frontend;
pub mod ir;
pub mod lift;
pub mod signature;
pub mod simplify;
pub mod symbol;
pub mod types;

// Re-export key types for convenient access
pub use frontend::Program;
pub use symbol::path::SymbolPath;
