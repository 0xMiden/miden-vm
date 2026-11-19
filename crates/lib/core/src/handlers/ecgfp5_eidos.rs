//! Host events for EcGFp5/Eidos sealing.
//!
//! `seal` and `seal_preprocessed` request private key-agreement advice from the host.
//! [`Ecgfp5SealHandler`] generates this advice from a cryptographic RNG and registered keys.
//! Hosts can also implement the event contract directly.
//!
//! Each event carries `[event_id, public_key_commitment(4), ...]` on the operand stack.
//! [`PublicKey::advise`] builds advice for `seal`; [`PreparedPublicKey::advise`] builds it for
//! `seal_preprocessed`. Use a key matching the commitment and a fresh random ephemeral secret
//! for each new encryption. Put the returned elements on the advice stack in consumption order
//! and the returned Merkle nodes in the Merkle store. Hosts with preloaded advice must still
//! handle the event without adding another response.
//!
//! To reproduce ciphertext during transaction re-execution, record each advice response with its
//! event ID and key commitment, then replay the responses for matching requests in order.
//! Record repeated calls to the same recipient separately, and keep all records private.
//! Building a trace from an existing [`miden_processor::ExecutionWitness`] does not call the host.

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

use miden_core::{Word, events::EventName};
use miden_crypto::ecdh::ecgfp5::{PreparedPublicKey, PublicKey, SecretKey};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventId},
};
use miden_utils_sync::RwLock;
use rand::CryptoRng;

/// Requests private key-agreement inputs for `crypto::ies::ecgfp5_eidos::seal`.
pub const ECGFP5_EIDOS_SEAL_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::ies::ecgfp5_eidos::seal");

/// Requests private key-agreement inputs for `crypto::ies::ecgfp5_eidos::seal_preprocessed`.
pub const ECGFP5_EIDOS_SEAL_PREPROCESSED_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::ies::ecgfp5_eidos::seal_preprocessed");

/// Supplies a fresh ephemeral secret and key-agreement witnesses for each sealing call.
///
/// Configure a cryptographic RNG and recipient keys, then register [`Self::handlers`] on the host.
/// Requests for unregistered key commitments fail. For transaction re-execution, see the
/// [host event contract](crate::handlers::ecgfp5_eidos).
///
/// ```
/// # use miden_core_lib::{CoreLibrary, handlers::ecgfp5_eidos::Ecgfp5SealHandler};
/// # use miden_crypto::ecdh::ecgfp5::PublicKey;
/// # use miden_processor::{DefaultHost, ExecutionError};
/// # fn configure<R: rand::CryptoRng + Send + Sync + 'static>(
/// #     rng: R, recipient: PublicKey,
/// # ) -> Result<DefaultHost, ExecutionError> {
/// let mut host = DefaultHost::default().with_library(&CoreLibrary::default())?;
/// let sealing = Ecgfp5SealHandler::new(rng).with_public_key(recipient);
/// for (event, handler) in sealing.handlers() {
///     host.register_handler(event, handler)?;
/// }
/// # Ok(host)
/// # }
/// ```
pub struct Ecgfp5SealHandler<R> {
    rng: RwLock<R>,
    public_keys: BTreeMap<Word, PublicKey>,
    prepared_public_keys: BTreeMap<Word, Arc<PreparedPublicKey>>,
}

impl<R> Ecgfp5SealHandler<R> {
    /// Creates a handler with no recipient keys. The RNG must be seeded with private entropy.
    pub fn new(rng: R) -> Self {
        Self {
            rng: RwLock::new(rng),
            public_keys: BTreeMap::new(),
            prepared_public_keys: BTreeMap::new(),
        }
    }

    /// Registers a recipient for `seal`, indexed by [`PublicKey::to_commitment`].
    pub fn with_public_key(mut self, key: PublicKey) -> Self {
        self.public_keys.insert(key.to_commitment(), key);
        self
    }

    /// Registers a recipient for `seal_preprocessed`, sharing its immutable tables.
    /// Requests use the commitment returned by [`PreparedPublicKey::to_commitment`].
    pub fn with_preprocessed_public_key(mut self, key: Arc<PreparedPublicKey>) -> Self {
        self.prepared_public_keys.insert(key.to_commitment(), key);
        self
    }
}

impl<R: CryptoRng + Send + Sync + 'static> Ecgfp5SealHandler<R> {
    /// Returns both event registrations sharing this handler and its RNG.
    pub fn handlers(self) -> Vec<(EventName, Arc<dyn EventHandler>)> {
        let handler: Arc<dyn EventHandler> = Arc::new(self);
        vec![
            (ECGFP5_EIDOS_SEAL_EVENT_NAME, Arc::clone(&handler)),
            (ECGFP5_EIDOS_SEAL_PREPROCESSED_EVENT_NAME, handler),
        ]
    }
}

impl<R: CryptoRng + Send + Sync + 'static> EventHandler for Ecgfp5SealHandler<R> {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event = EventId::from_felt(process.get_stack_item(0));
        let commitment = process.get_stack_word(1);
        let advice = if event == ECGFP5_EIDOS_SEAL_EVENT_NAME.to_event_id() {
            let key = self
                .public_keys
                .get(&commitment)
                .ok_or(Ecgfp5SealError::UnknownPublicKey { commitment })?;
            let ephemeral = SecretKey::with_rng(&mut *self.rng.write());
            key.advise(&ephemeral)
        } else if event == ECGFP5_EIDOS_SEAL_PREPROCESSED_EVENT_NAME.to_event_id() {
            let key = self
                .prepared_public_keys
                .get(&commitment)
                .ok_or(Ecgfp5SealError::UnknownPreprocessedPublicKey { commitment })?;
            let ephemeral = SecretKey::with_rng(&mut *self.rng.write());
            key.advise(&ephemeral)
        } else {
            return Err(Ecgfp5SealError::UnexpectedEvent.into());
        };

        Ok(vec![
            AdviceMutation::extend_merkle_store(advice.merkle_nodes().iter().cloned()),
            AdviceMutation::extend_advice_stack_with(advice.elements()),
        ])
    }
}

#[derive(Debug, thiserror::Error)]
enum Ecgfp5SealError {
    #[error("no EcGFp5 public key registered for commitment {commitment}")]
    UnknownPublicKey { commitment: Word },
    #[error("no preprocessed EcGFp5 public key registered for commitment {commitment}")]
    UnknownPreprocessedPublicKey { commitment: Word },
    #[error("unexpected EcGFp5/Eidos sealing event")]
    UnexpectedEvent,
}
