//! Bootstrap transition boundary: validation, required-event gating, and atomic state.
use crate::adapters::credential_store::{CredentialStore, CredentialStoreError, PlatformCredentialStore};
use crate::adapters::os_pipe::{BootstrapEnvelope, EnvelopeError, NonceLedger, OsPipe, OsPipeError, PlatformOsPipe};
use crate::events::{emit_required, EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry, SafeNextAction, SecurityCode, SecurityEvent, SecurityEventSink};
use crate::identity::{Fingerprint, IdentityId, PublicKey, TransitionOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrashPoint {
    BeforeEvent,
    AfterEvent,
    AfterStage,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapError {
    Pipe(OsPipeError),
    Envelope(EnvelopeError),
    Credential(CredentialStoreError),
    EventUnavailable,
    IdentityMismatch,
    AlreadyUsed,
    Crash(CrashPoint),
    InvalidKey,
    EndpointRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapRecord {
    pub(crate) state: IdentityId,
    pub(crate) daemon: IdentityId,
    pub(crate) bootstrap: uuid::Uuid,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) endpoint: String,
    pub(crate) event_time: EventTime,
}

/// In-memory implementation of the bootstrap persistence contract.
///
/// `staged` is durable-intent state and `active` is the committed state. The
/// only promotion operation consumes staged state into active state, so restart
/// recovery can complete a crash after staging without creating a second record.
#[derive(Default)]
pub(crate) struct BootstrapState {
    active: Option<BootstrapRecord>,
    staged: Option<BootstrapRecord>,
    ledger: NonceLedger,
}

impl BootstrapState {
    pub(crate) fn active(&self) -> Option<&BootstrapRecord> { self.active.as_ref() }
    pub(crate) fn staged(&self) -> Option<&BootstrapRecord> { self.staged.as_ref() }

    /// Recover the sole staged record. If active state already exists, an
    /// uncommitted duplicate is discarded rather than replacing active identity.
    pub(crate) fn recover(&mut self) {
        if self.active.is_none() {
            self.active = self.staged.take();
        } else {
            self.staged = None;
        }
    }

    /// Production entrypoint. It constructs the native credential adapter here;
    /// callers cannot silently replace platform custody on this path.
    pub(crate) fn bootstrap_encoded<P: OsPipe, S: SecurityEventSink>(
        &mut self,
        pipe: &P,
        encoded_envelope: &[u8],
        sink: Option<&mut S>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        let credential = PlatformCredentialStore::new();
        self.bootstrap_encoded_inner(
            pipe, encoded_envelope, &credential, sink, None, event_time, endpoint_bytes,
        )
    }

    /// Production convenience entrypoint for the raw inherited descriptor/handle.
    pub(crate) fn bootstrap_inherited_handle<S: SecurityEventSink>(
        &mut self,
        handle: u64,
        encoded_envelope: &[u8],
        sink: Option<&mut S>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        let pipe = PlatformOsPipe::new(handle);
        self.bootstrap_encoded(&pipe, encoded_envelope, sink, event_time, endpoint_bytes)
    }

    #[cfg(test)]
    pub(crate) fn bootstrap_encoded_with_store_for_test<P: OsPipe, C: CredentialStore, S: SecurityEventSink>(
        &mut self,
        pipe: &P,
        encoded_envelope: &[u8],
        credential: &C,
        sink: Option<&mut S>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        self.bootstrap_encoded_inner(
            pipe, encoded_envelope, credential, sink, None, event_time, endpoint_bytes,
        )
    }

    #[cfg(test)]
    pub(crate) fn bootstrap_encoded_for_test<P: OsPipe, C: CredentialStore, S: SecurityEventSink>(
        &mut self,
        pipe: &P,
        encoded_envelope: &[u8],
        credential: &C,
        sink: Option<&mut S>,
        crash: Option<CrashPoint>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        self.bootstrap_encoded_inner(
            pipe, encoded_envelope, credential, sink, crash, event_time, endpoint_bytes,
        )
    }

    fn bootstrap_encoded_inner<P: OsPipe, C: CredentialStore, S: SecurityEventSink>(
        &mut self,
        pipe: &P,
        encoded_envelope: &[u8],
        credential: &C,
        sink: Option<&mut S>,
        crash: Option<CrashPoint>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        let mut inherited = pipe.acquire().map_err(BootstrapError::Pipe)?;
        let result = (|| {
            let envelope = BootstrapEnvelope::parse(encoded_envelope)
                .map_err(BootstrapError::Envelope)?;
            let endpoint = BootstrapEnvelope::parse_endpoint(endpoint_bytes)
                .map_err(BootstrapError::Envelope)?;
            self.apply(&envelope, credential, sink, crash, event_time, endpoint)
        })();
        if result.is_err() { inherited.close_on_error(); } else { inherited.close(); }
        result
    }

    /// Apply one already parsed envelope after the endpoint and event time have
    /// crossed their typed boundaries. This is called only by [`bootstrap_encoded`].
    fn apply<C: CredentialStore, S: SecurityEventSink>(
        &mut self,
        envelope: &BootstrapEnvelope,
        credential: &C,
        mut sink: Option<&mut S>,
        crash: Option<CrashPoint>,
        event_time: EventTime,
        endpoint: &str,
    ) -> Result<TransitionOutcome, BootstrapError> {
        let public_key = PublicKey::from_uncompressed(envelope.public_key)
            .map_err(|_| BootstrapError::InvalidKey)?;
        let fingerprint = Fingerprint::from_public_key(&public_key);

        if let Some(active) = &self.active {
            if active.bootstrap == envelope.bootstrap
                && active.state == IdentityId::new(envelope.state_directory)
                && active.daemon == IdentityId::new(envelope.daemon)
                && active.fingerprint == fingerprint
            {
                return Ok(TransitionOutcome::AlreadyCommitted);
            }
            return Err(BootstrapError::IdentityMismatch);
        }
        if let Some(staged) = &self.staged {
            if staged.bootstrap == envelope.bootstrap
                && staged.state == IdentityId::new(envelope.state_directory)
                && staged.daemon == IdentityId::new(envelope.daemon)
                && staged.fingerprint == fingerprint
            {
                return Ok(TransitionOutcome::AlreadyCommitted);
            }
            return Err(BootstrapError::IdentityMismatch);
        }

        let endpoint_class = classify_endpoint(endpoint);
        if endpoint_class == EndpointClass::Loopback {
            return Err(BootstrapError::EndpointRejected);
        }
        self.ledger.consume(envelope.nonce).map_err(|_| BootstrapError::AlreadyUsed)?;
        let binding = crate::adapters::credential_store::CredentialBinding::for_identities(
            envelope.state_directory,
            envelope.daemon,
        );
        if let Err(error) = credential.lookup(binding) {
            self.ledger.release(&envelope.nonce);
            return Err(BootstrapError::Credential(error));
        }
        if matches!(crash, Some(CrashPoint::BeforeEvent)) {
            self.ledger.release(&envelope.nonce);
            return Err(BootstrapError::Crash(CrashPoint::BeforeEvent));
        }

        // These are pre-commit facts. They deliberately use Accepted rather
        // than Committed because no registration has been promoted yet.
        let bootstrap_event = SecurityEvent::new(
            envelope.bootstrap,
            EventBoundary::Bootstrap,
            SecurityCode::EnrollmentAccepted,
            EventOutcome::Accepted,
            SafeNextAction::Continue,
            None,
            None,
            endpoint_class,
            event_time,
            envelope.state_directory,
            vec![MetadataEntry { key: "operation".into(), value: "bootstrap".into() }],
        ).map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
        emit_required(sink.as_deref_mut(), bootstrap_event)
            .map_err(|_| { self.ledger.release(&envelope.nonce); BootstrapError::EventUnavailable })?;
        let identity_event = SecurityEvent::new(
            uuid::Uuid::from_u128(envelope.bootstrap.as_u128() ^ 1),
            EventBoundary::Bootstrap,
            SecurityCode::AuthorizationAccepted,
            EventOutcome::Accepted,
            SafeNextAction::Continue,
            Some(envelope.daemon),
            None,
            endpoint_class,
            event_time,
            envelope.state_directory,
            vec![MetadataEntry { key: "phase".into(), value: "identity".into() }],
        ).map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
        emit_required(sink.as_deref_mut(), identity_event)
            .map_err(|_| { self.ledger.release(&envelope.nonce); BootstrapError::EventUnavailable })?;
        if matches!(crash, Some(CrashPoint::AfterEvent)) {
            self.ledger.release(&envelope.nonce);
            return Err(BootstrapError::Crash(CrashPoint::AfterEvent));
        }

        let record = BootstrapRecord {
            state: IdentityId::new(envelope.state_directory),
            daemon: IdentityId::new(envelope.daemon),
            bootstrap: envelope.bootstrap,
            fingerprint,
            endpoint: endpoint.to_owned(),
            event_time,
        };
        self.staged = Some(record);
        if matches!(crash, Some(CrashPoint::AfterStage)) {
            return Err(BootstrapError::Crash(CrashPoint::AfterStage));
        }
        self.active = self.staged.take();
        if matches!(crash, Some(CrashPoint::AfterCommit)) {
            return Err(BootstrapError::Crash(CrashPoint::AfterCommit));
        }
        Ok(TransitionOutcome::Committed)
    }
}

fn classify_endpoint(endpoint: &str) -> EndpointClass {
    if endpoint.starts_with("native://") { EndpointClass::Native }
    else if endpoint.starts_with("chrome-extension://") { EndpointClass::Extension }
    else if endpoint.starts_with("127.0.0.1:") || endpoint.starts_with("[::1]:") {
        EndpointClass::Loopback
    } else { EndpointClass::Unknown }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::os_pipe::InheritedPipe;

    #[test]
    fn inherited_handles_are_close_on_exec_and_close_idempotently() {
        let mut handle = InheritedPipe::from_handle(9);
        assert!(handle.is_present());
        assert!(!handle.close_on_exec());
        handle.close_on_error();
        handle.close();
        assert!(handle.is_closed());
        assert!(!handle.is_present());
    }
}
