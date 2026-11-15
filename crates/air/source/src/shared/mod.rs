pub mod eidos;
pub mod geometry;

/// Recoverable auxiliary-witness failures from an authored VM or precompile source.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    #[error(transparent)]
    Lookup(#[from] miden_stark::lookup::native::LookupError),
    #[error(transparent)]
    Eidos(#[from] eidos::EidosWitnessError),
}
