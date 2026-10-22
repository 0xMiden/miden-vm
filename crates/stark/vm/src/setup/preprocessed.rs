//! Process-wide fixed VM preprocessing cache.
use alloc::boxed::Box;
use core::any::{Any, TypeId};

use miden_air::vm::MidenMultiAir;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{Preprocessed, StarkConfig, air::Statement};

type PreprocessedSetup<SC> = Preprocessed<Felt, <SC as StarkConfig<Felt, QuadFelt>>::Lmcs>;
type SetupCell<SC> = std::sync::OnceLock<Option<std::sync::Arc<PreprocessedSetup<SC>>>>;
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
    // Hold the map lock only while finding the cell. Each setup initializes once, without
    // blocking cache hits or construction for other configurations and blowup factors.
    let cell = {
        let mut cache = PREPROCESSED_SETUPS
            .get_or_init(Default::default)
            .lock()
            .expect("preprocessed setup cache poisoned");
        cache
            .entry(key)
            .or_insert_with(|| Box::new(std::sync::Arc::new(SetupCell::<SC>::new())))
            .downcast_ref::<std::sync::Arc<SetupCell<SC>>>()
            .expect("preprocessed setup cache type mismatch")
            .clone()
    };

    cell.get_or_init(|| Preprocessed::build(statement, config).map(std::sync::Arc::new))
        .clone()
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::sync::Arc;

    use miden_air::vm::{NUM_PUBLIC_VALUES, config as air_config};
    use miden_stark::pcs::PcsParams;

    use super::*;
    use crate::setup::config::eidos_config;

    #[test]
    fn concurrent_calls_share_setup_but_distinct_blowups_do_not() {
        let statement = Statement::new(
            MidenMultiAir::new(),
            vec![(0, vec![Felt::ZERO; NUM_PUBLIC_VALUES])],
            vec![],
        )
        .unwrap();
        let params = air_config::pcs_params();
        let config = eidos_config(params, air_config::RELATION_DIGEST);
        let cached = std::thread::scope(|scope| {
            let handles = core::array::from_fn::<_, 4, _>(|_| {
                scope.spawn(|| cached_preprocessed_setup(&statement, &config).unwrap())
            });
            let setups = handles.map(|handle| handle.join().unwrap());
            assert!(setups.iter().all(|setup| Arc::ptr_eq(setup, &setups[0])));
            setups[0].clone()
        });
        assert_eq!(
            <[u64; 4]>::from(cached.commitment()),
            air_config::EIDOS_PREPROCESSED_COMMITMENT
        );

        let larger_params = PcsParams::new(
            params.log_blowup() + 1,
            params.log_folding_arity(),
            params.log_final_degree(),
            params.folding_pow_bits(),
            params.deep_pow_bits(),
            params.num_queries(),
            params.query_pow_bits(),
        )
        .unwrap();
        let larger_config = eidos_config(larger_params, air_config::RELATION_DIGEST);
        let larger = cached_preprocessed_setup(&statement, &larger_config).unwrap();
        assert!(!Arc::ptr_eq(&cached, &larger));
        assert_ne!(cached.commitment(), larger.commitment());
    }
}
