//! Process-wide fixed VM preprocessing cache.
use alloc::boxed::Box;
use core::any::{Any, TypeId};

use miden_air::vm::MidenMultiAir;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{Preprocessed, StarkConfig, air::Statement};

type PreprocessedSetup<SC> = Preprocessed<Felt, <SC as StarkConfig<Felt, QuadFelt>>::Lmcs>;
type PreprocessedCache = std::collections::HashMap<(TypeId, u8), Box<dyn Any + Send + Sync>>;
static PREPROCESSED_SETUPS: std::sync::OnceLock<std::sync::Mutex<PreprocessedCache>> =
    std::sync::OnceLock::new();

/// Returns the (possibly cached) preprocessed setup for `config`.
///
/// The verifier only needs the fixed setup commitment. The prover needs the
/// full setup tree so it can open preprocessed rows during PCS queries. The
/// setup depends only on the concrete config type and LDE blowup, so it is
/// cached per `(TypeId, log_blowup)` across proves.
#[cfg(feature = "std")]
pub(crate) fn cached_preprocessed_setup<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> Option<std::sync::Arc<PreprocessedSetup<SC>>>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    PreprocessedSetup<SC>: Send + Sync + 'static,
{
    let key = (TypeId::of::<SC>(), config.pcs().log_blowup());
    let mut cache = PREPROCESSED_SETUPS
        .get_or_init(Default::default)
        .lock()
        .expect("preprocessed setup cache poisoned");

    if let Some(value) = cache.get(&key) {
        return value
            .downcast_ref::<Option<std::sync::Arc<PreprocessedSetup<SC>>>>()
            .expect("preprocessed setup cache type mismatch")
            .clone();
    }

    let value = Preprocessed::build(statement, config).map(std::sync::Arc::new);
    cache.insert(key, Box::new(value.clone()));
    value
}
