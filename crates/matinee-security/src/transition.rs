//! Serialized security transitions: bootstrap, enrollment, rotation, and revocation.
//!
//! One [`SecurityTransitions`] value owns every mutable fact a lifecycle change
//! touches: the principal registry, pending enrollments, live channels, extension
//! grants, pending extension decisions, the recorded outcome of every idempotency
//! key, and the committed object version. Every transition runs under that one lock,
//! validates completely, requires its security event to be available, and only then
//! commits. A refused transition, an unavailable sink, and a poisoned lock all leave
//! the whole state exactly as it was.
use core::fmt;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::adapters::credential_store::{CredentialStore, CredentialStoreError, PlatformCredentialStore};
use crate::adapters::os_pipe::{BootstrapEnvelope, EnvelopeError, NonceLedger, OsPipe, OsPipeError, PlatformOsPipe};
use crate::authorization::endpoint_class;
use crate::enrollment::{
    ChromeCapability, EnrollmentBinding, EnrollmentBundle, EnrollmentChannel, EnrollmentClock,
    EnrollmentConsumeError, EnrollmentConsumptionService, EnrollmentCreation, EnrollmentProof,
};
use crate::events::{emit_required, EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry, SafeNextAction, SecurityCode, SecurityEvent, SecurityEventSink};
use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{
    Capability, ConnectionId, CredentialReference, EnrollmentLifecycle, ExtensionGrant, Fingerprint,
    GrantLifecycle, IdempotencyKey, IdentityId, Principal, PrincipalKind, PrincipalLifecycle,
    PublicKey, RevocationTransition, RotationTransition, TransitionId, TransitionInput,
    TransitionOutcome,
};
use crate::{AuthorizedInput, ChannelSession, ObjectOwner, PayloadKind, SecurityCommand, SessionInput};

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
    pub(crate) fn bootstrap_encoded<P: OsPipe + ?Sized, S: SecurityEventSink + ?Sized>(
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
    pub(crate) fn bootstrap_inherited_handle<S: SecurityEventSink + ?Sized>(
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
    pub(crate) fn bootstrap_encoded_with_store_for_test<P: OsPipe + ?Sized, C: CredentialStore + ?Sized, S: SecurityEventSink + ?Sized>(
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
    pub(crate) fn bootstrap_encoded_for_test<P: OsPipe + ?Sized, C: CredentialStore + ?Sized, S: SecurityEventSink + ?Sized>(
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

    fn bootstrap_encoded_inner<P: OsPipe + ?Sized, C: CredentialStore + ?Sized, S: SecurityEventSink + ?Sized>(
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
    fn apply<C: CredentialStore + ?Sized, S: SecurityEventSink + ?Sized>(
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

/// A refused transition: one closed outcome and one bounded failure.
///
/// `Rejected` is a decided refusal: this process knows nothing was committed and the
/// same idempotency key may be retried once its cause is repaired. `Unknown` is an
/// undecidable one: the durable record, the deadline, or the lock could not be read,
/// so the module reports no protected success and mutates nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionRejection {
    outcome: TransitionOutcome,
    failure: SecurityFailure,
}

impl TransitionRejection {
    fn rejected(code: FailureCode, principal: Option<IdentityId>) -> Self {
        Self {
            outcome: TransitionOutcome::Rejected,
            failure: SecurityFailure::with_safe_ids(code, principal.map(IdentityId::get), None),
        }
    }

    fn undecided(code: FailureCode, principal: Option<IdentityId>) -> Self {
        Self {
            outcome: TransitionOutcome::Unknown,
            failure: SecurityFailure::with_safe_ids(code, principal.map(IdentityId::get), None),
        }
    }

    pub(crate) fn outcome(&self) -> TransitionOutcome {
        self.outcome
    }

    pub(crate) fn failure(&self) -> SecurityFailure {
        self.failure
    }

    pub(crate) fn code(&self) -> FailureCode {
        self.failure.code()
    }
}

/// The auditable, redacted shape of one committed transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TransitionRecord {
    Bootstrap,
    EnrollmentCreated(TransitionId),
    EnrollmentConsumed {
        enrollment: TransitionId,
        principal: IdentityId,
        fingerprint: Fingerprint,
    },
    Rotated(RotationTransition),
    Revoked(RevocationTransition),
}

/// The state of one pending extension decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecisionState {
    Pending,
    Completed,
    Invalidated,
}

/// The inherited pipe, envelope, and endpoint one bootstrap command applies.
pub(crate) struct BootstrapMaterial<'a> {
    pipe: &'a dyn OsPipe,
    envelope: &'a [u8],
    endpoint: &'a [u8],
    #[cfg(test)]
    credential: Option<&'a dyn CredentialStore>,
}

impl<'a> BootstrapMaterial<'a> {
    /// Production construction. Custody is not selectable here, so no caller can route
    /// a bootstrap commit past the platform credential store.
    pub(crate) fn platform(pipe: &'a dyn OsPipe, envelope: &'a [u8], endpoint: &'a [u8]) -> Self {
        Self {
            pipe,
            envelope,
            endpoint,
            #[cfg(test)]
            credential: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_store_for_test(
        pipe: &'a dyn OsPipe,
        envelope: &'a [u8],
        endpoint: &'a [u8],
        credential: &'a dyn CredentialStore,
    ) -> Self {
        Self {
            pipe,
            envelope,
            endpoint,
            credential: Some(credential),
        }
    }
}

/// The replacement credential one rotation installs.
///
/// A rotation replaces one whole credential: the key, the fingerprint that names it,
/// and the locator that stores it. The fingerprint is derived here rather than
/// supplied, so a caller cannot register a new key under an old name.
pub(crate) struct ReplacementCredential {
    public_key: PublicKey,
    credential: CredentialReference,
    custody: Option<ChromeCapability>,
}

impl ReplacementCredential {
    pub(crate) fn new(public_key: PublicKey, credential: CredentialReference) -> Self {
        Self {
            public_key,
            credential,
            custody: None,
        }
    }

    /// The browser custody the rotated extension key lives in. A principal the
    /// enrollment host registered cannot rotate without it, so the same transition
    /// that installs the replacement also quarantines the retired key.
    pub(crate) fn with_extension_custody(mut self, capability: ChromeCapability) -> Self {
        self.custody = Some(capability);
        self
    }

    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_public_key(&self.public_key)
    }
}

/// One pairing proof, the browser facts it was offered under, and the registration it
/// produces.
///
/// Proof verification belongs to the enrollment host. This names what the transition
/// registers once that verification succeeds: the principal identity, its capability
/// ceiling, and the non-secret locator its long-term key is stored under.
pub(crate) struct PairingMaterial<'a> {
    pub(crate) identity: IdentityId,
    pub(crate) proof: &'a EnrollmentProof,
    pub(crate) clock: &'a EnrollmentClock,
    pub(crate) binding: &'a EnrollmentBinding<'a>,
    pub(crate) capability: &'a ChromeCapability,
    pub(crate) channel: &'a mut EnrollmentChannel,
    pub(crate) ceiling: Vec<Capability>,
    pub(crate) credential: CredentialReference,
}

/// What each command in the closed set needs from its host to be applied.
///
/// The command names the lifecycle change; this carries the material that change
/// consumes. A command and a material that do not name one transition fail closed.
pub(crate) enum TransitionMaterial<'a> {
    Bootstrap(BootstrapMaterial<'a>),
    Enrollment(EnrollmentCreation),
    Pairing(PairingMaterial<'a>),
    Replacement(ReplacementCredential),
    Revocation(&'a str),
}

struct EnrollmentRegistration {
    bundle: EnrollmentBundle,
    owner: IdentityId,
    epoch: u64,
}

struct PendingDecision {
    extension: IdentityId,
    epoch: u64,
    state: DecisionState,
}

struct AppliedTransition {
    command: SecurityCommand,
    record: TransitionRecord,
}

#[derive(Default)]
struct TransitionState {
    bootstrap: BootstrapState,
    principals: HashMap<IdentityId, Principal>,
    enrollments: HashMap<TransitionId, EnrollmentRegistration>,
    channels: HashMap<ConnectionId, ChannelSession>,
    grants: Vec<ExtensionGrant>,
    decisions: HashMap<TransitionId, PendingDecision>,
    applied: HashMap<IdempotencyKey, AppliedTransition>,
    host: EnrollmentConsumptionService,
    object_version: u64,
}

/// The one process-lifetime security state every transition serializes against.
#[derive(Default)]
pub(crate) struct SecurityTransitions {
    state: Mutex<TransitionState>,
}

impl fmt::Debug for SecurityTransitions {
    /// Bounded counters only: no key, locator, fingerprint, payload, or endpoint.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(state) = self.state.lock() else {
            return formatter.write_str("SecurityTransitions(POISONED)");
        };
        formatter
            .debug_struct("SecurityTransitions")
            .field("principals", &state.principals.len())
            .field("enrollments", &state.enrollments.len())
            .field("channels", &state.channels.len())
            .field("grants", &state.grants.len())
            .field("decisions", &state.decisions.len())
            .field("applied", &state.applied.len())
            .field("object_version", &state.object_version)
            .finish_non_exhaustive()
    }
}

impl SecurityTransitions {
    fn lock(&self) -> Result<MutexGuard<'_, TransitionState>, TransitionRejection> {
        self.state
            .lock()
            .map_err(|_| TransitionRejection::undecided(FailureCode::TransitionUnknown, None))
    }

    fn lock_for_frame(&self) -> Result<MutexGuard<'_, TransitionState>, SecurityFailure> {
        self.state
            .lock()
            .map_err(|_| SecurityFailure::new(FailureCode::TransitionUnknown))
    }

    /// Apply one closed lifecycle command against the durable transition record the
    /// owning state actor reported.
    ///
    /// The order is fixed for every command: the command and the record must name one
    /// transition, a recorded idempotency key answers from its record, an uncertain
    /// record fails closed, the command validates completely, its required event must
    /// be available, and only then does anything commit.
    pub(crate) fn apply<S: SecurityEventSink + ?Sized>(
        &self,
        command: &SecurityCommand,
        input: &TransitionInput,
        material: TransitionMaterial<'_>,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let mut state = self.lock()?;
        if *input.operation() != command.operation()
            || input.idempotency() != command.idempotency()
        {
            return Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                None,
            ));
        }
        // A retry answers from the recorded decision and commits nothing a second
        // time. A different command under a recorded key is a conflicting reuse.
        if let Some(applied) = state.applied.get(&command.idempotency()) {
            return if &applied.command == command {
                Ok(TransitionOutcome::AlreadyCommitted)
            } else {
                Err(TransitionRejection::undecided(
                    FailureCode::TransitionUnknown,
                    None,
                ))
            };
        }
        if input.outcome() == TransitionOutcome::AlreadyCommitted {
            // The record claims a commit this process holds no decision for, so
            // whether the protected state moved cannot be established here.
            return Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                None,
            ));
        }
        if !input.may_persist() {
            return Err(if input.is_fail_closed() {
                TransitionRejection::undecided(FailureCode::TransitionUnknown, None)
            } else {
                TransitionRejection::rejected(FailureCode::TransitionUnknown, None)
            });
        }
        match (command, material) {
            (
                SecurityCommand::Bootstrap {
                    state_directory, ..
                },
                TransitionMaterial::Bootstrap(bootstrap),
            ) => state.bootstrap(command, input, *state_directory, bootstrap, sink, time),
            (
                SecurityCommand::CreateEnrollment {
                    enrollment, daemon, ..
                },
                TransitionMaterial::Enrollment(creation),
            ) => state.create_enrollment(command, input, *enrollment, *daemon, creation, sink, time),
            (
                SecurityCommand::ConsumeEnrollment { enrollment, .. },
                TransitionMaterial::Pairing(pairing),
            ) => state.consume_enrollment(command, input, *enrollment, pairing, sink, time),
            (
                SecurityCommand::Rotate {
                    principal,
                    new_fingerprint,
                    ..
                },
                TransitionMaterial::Replacement(replacement),
            ) => state.rotate(
                command,
                input,
                *principal,
                new_fingerprint,
                replacement,
                sink,
                time,
            ),
            (
                SecurityCommand::Revoke { principal, .. },
                TransitionMaterial::Revocation(reason),
            ) => state.revoke(command, input, *principal, reason, sink, time),
            _ => Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                None,
            )),
        }
    }

    /// Register one principal snapshot a host built.
    ///
    /// This registry is the only snapshot source a handshake configuration may read,
    /// so every committed rotation and revocation is visible to every later handshake,
    /// frame, grant, and decision.
    pub(crate) fn register_principal(
        &self,
        principal: Principal,
    ) -> Result<(), TransitionRejection> {
        let mut state = self.lock()?;
        let id = principal.id();
        if principal.lifecycle() != PrincipalLifecycle::Active {
            return Err(TransitionRejection::rejected(
                FailureCode::AuthenticationFailed,
                Some(id),
            ));
        }
        match state.principals.get(&id) {
            Some(existing) if existing == &principal => Ok(()),
            Some(_) => Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(id),
            )),
            None => {
                state.principals.insert(id, principal);
                Ok(())
            }
        }
    }

    /// The registered snapshot of one principal, as every decision reads it.
    pub(crate) fn registered_principal(&self, principal: IdentityId) -> Option<Principal> {
        self.state.lock().ok()?.principals.get(&principal).cloned()
    }

    /// Register one extension grant. A grant from a retired epoch is refused, so a
    /// stale approval cannot re-enter the registry after a transition commits.
    pub(crate) fn register_grant(&self, grant: ExtensionGrant) -> Result<(), TransitionRejection> {
        let mut state = self.lock()?;
        let extension = grant.extension();
        let principal = state.principals.get(&extension).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthorizationDenied, Some(extension))
        })?;
        if principal.lifecycle() == PrincipalLifecycle::Revoked {
            return Err(TransitionRejection::rejected(
                FailureCode::Revoked,
                Some(extension),
            ));
        }
        if principal.lifecycle() != PrincipalLifecycle::Active || grant.owner() != principal.owner()
        {
            return Err(TransitionRejection::rejected(
                FailureCode::AuthorizationDenied,
                Some(extension),
            ));
        }
        if grant.epoch() != principal.epoch() {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(extension),
            ));
        }
        state.grants.push(grant);
        Ok(())
    }

    /// The lifecycle of every grant registered for one extension.
    pub(crate) fn grant_lifecycles(&self, extension: IdentityId) -> Vec<GrantLifecycle> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state
            .grants
            .iter()
            .filter(|grant| grant.extension() == extension)
            .map(ExtensionGrant::lifecycle)
            .collect()
    }

    /// Register one authenticated channel.
    ///
    /// A handshake that completed against a retired epoch, a revoked principal, or an
    /// identity this registry does not hold never becomes a live channel, so a
    /// concurrent handshake cannot outlive the transition it raced.
    pub(crate) fn register_channel(
        &self,
        session: ChannelSession,
    ) -> Result<ConnectionId, TransitionRejection> {
        let mut state = self.lock()?;
        let connection = session.connection_id();
        let id = session.principal();
        let principal = state.principals.get(&id).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthenticationFailed, Some(id))
        })?;
        match principal.lifecycle() {
            PrincipalLifecycle::Active => {}
            PrincipalLifecycle::Revoked => {
                return Err(TransitionRejection::rejected(
                    FailureCode::Revoked,
                    Some(id),
                ));
            }
            _ => {
                return Err(TransitionRejection::rejected(
                    FailureCode::AuthenticationFailed,
                    Some(id),
                ));
            }
        }
        if session.epoch() != principal.epoch() {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(id),
            ));
        }
        if !session.is_open() || state.channels.contains_key(&connection) {
            return Err(TransitionRejection::rejected(
                FailureCode::ReplayDetected,
                Some(id),
            ));
        }
        state.channels.insert(connection, session);
        Ok(connection)
    }

    /// Close one connection.
    ///
    /// A disconnect is not a transition: it closes a channel and touches no principal,
    /// grant, decision, recorded outcome, or object version.
    pub(crate) fn close_channel(&self, connection: ConnectionId) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        match state.channels.get_mut(&connection) {
            Some(session) if session.is_open() => {
                session.close();
                true
            }
            _ => false,
        }
    }

    pub(crate) fn channel_is_open(&self, connection: ConnectionId) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.channels.get(&connection).map(ChannelSession::is_open))
            .unwrap_or(false)
    }

    pub(crate) fn open_channels(&self) -> usize {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        state
            .channels
            .values()
            .filter(|session| session.is_open())
            .count()
    }

    /// Open one pending extension decision at the epoch its principal holds now.
    pub(crate) fn open_decision(
        &self,
        decision: TransitionId,
        extension: IdentityId,
    ) -> Result<(), TransitionRejection> {
        let mut state = self.lock()?;
        let principal = state.principals.get(&extension).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthorizationDenied, Some(extension))
        })?;
        if principal.lifecycle() != PrincipalLifecycle::Active {
            return Err(TransitionRejection::rejected(
                FailureCode::Revoked,
                Some(extension),
            ));
        }
        if state.decisions.contains_key(&decision) {
            return Err(TransitionRejection::rejected(
                FailureCode::ReplayDetected,
                Some(extension),
            ));
        }
        let epoch = principal.epoch();
        state.decisions.insert(
            decision,
            PendingDecision {
                extension,
                epoch,
                state: DecisionState::Pending,
            },
        );
        Ok(())
    }

    pub(crate) fn decision_state(&self, decision: TransitionId) -> Option<DecisionState> {
        Some(self.state.lock().ok()?.decisions.get(&decision)?.state)
    }

    /// Complete one pending extension decision.
    ///
    /// A decision invalidated by a rotation or a revocation, one whose principal is no
    /// longer active, and one from a retired epoch all fail closed. The decision event
    /// must be available before the decision is marked complete.
    pub(crate) fn complete_decision<S: SecurityEventSink + ?Sized>(
        &self,
        decision: TransitionId,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let mut state = self.lock()?;
        let pending = state.decisions.get(&decision).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthorizationDenied, None)
        })?;
        let extension = pending.extension;
        match pending.state {
            DecisionState::Pending => {}
            DecisionState::Completed => {
                return Err(TransitionRejection::rejected(
                    FailureCode::ReplayDetected,
                    Some(extension),
                ));
            }
            DecisionState::Invalidated => {
                return Err(TransitionRejection::rejected(
                    FailureCode::StaleEpoch,
                    Some(extension),
                ));
            }
        }
        let epoch = pending.epoch;
        let principal = state.principals.get(&extension).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthorizationDenied, Some(extension))
        })?;
        if principal.lifecycle() != PrincipalLifecycle::Active {
            return Err(TransitionRejection::rejected(
                FailureCode::Revoked,
                Some(extension),
            ));
        }
        if principal.epoch() != epoch {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(extension),
            ));
        }
        require_event(
            sink,
            decision.get(),
            EventBoundary::Authorization,
            SecurityCode::AuthorizationAccepted,
            EventOutcome::Accepted,
            SafeNextAction::Continue,
            principal,
            principal.credential().state_directory(),
            time,
            vec![MetadataEntry {
                key: "operation".into(),
                value: "decision".into(),
            }],
        )?;
        if let Some(pending) = state.decisions.get_mut(&decision) {
            pending.state = DecisionState::Completed;
        }
        Ok(TransitionOutcome::Committed)
    }

    /// Authenticate and authorize one frame on a registered channel.
    ///
    /// The live registry decides, never the snapshot the handshake captured: a
    /// principal that rotated, one that was revoked, and a channel from a retired
    /// epoch are refused before the frame is opened. The extension grant is read from
    /// the registry too, so no caller can present one the registry does not hold.
    pub(crate) fn receive(
        &self,
        connection: ConnectionId,
        frame: &[u8],
        requested: Capability,
        kind: PayloadKind,
        owner: ObjectOwner,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<AuthorizedInput, SecurityFailure> {
        let mut state = self.lock_for_frame()?;
        let TransitionState {
            principals,
            channels,
            grants,
            ..
        } = &mut *state;
        let session = channels
            .get_mut(&connection)
            .ok_or_else(|| SecurityFailure::new(FailureCode::AuthenticationFailed))?;
        let principal = principals.get(&session.principal()).ok_or_else(|| {
            SecurityFailure::with_safe_ids(
                FailureCode::AuthenticationFailed,
                Some(session.principal().get()),
                Some(connection.get()),
            )
        })?;
        let safe_ids = (Some(principal.id().get()), Some(connection.get()));
        match principal.lifecycle() {
            PrincipalLifecycle::Active => {}
            PrincipalLifecycle::Revoked => {
                session.close();
                return Err(SecurityFailure::with_safe_ids(
                    FailureCode::Revoked,
                    safe_ids.0,
                    safe_ids.1,
                ));
            }
            _ => {
                session.close();
                return Err(SecurityFailure::with_safe_ids(
                    FailureCode::AuthenticationFailed,
                    safe_ids.0,
                    safe_ids.1,
                ));
            }
        }
        if session.epoch() != principal.epoch() {
            session.close();
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::StaleEpoch,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        let grant = grants.iter().find(|grant| {
            grant.extension() == principal.id()
                && grant.lifecycle() == GrantLifecycle::Active
                && grant.epoch() == principal.epoch()
        });
        let operation = SessionInput::new(requested, kind, owner, grant);
        session.receive(frame, &operation, sink)
    }

    /// Commit one object mutation the receive path authorized.
    ///
    /// The authorized input carries the epoch it was minted at, so an input that
    /// crossed a committed rotation or revocation mutates nothing. The registry is
    /// consulted before the connection, so a stale credential is reported as the stale
    /// epoch it is rather than as the closed channel that followed from it.
    pub(crate) fn commit_mutation(
        &self,
        input: &AuthorizedInput,
    ) -> Result<u64, SecurityFailure> {
        let mut state = self.lock_for_frame()?;
        let safe_ids = (
            Some(input.principal().get()),
            Some(input.connection().get()),
        );
        let principal = state.principals.get(&input.principal()).ok_or_else(|| {
            SecurityFailure::with_safe_ids(
                FailureCode::AuthenticationFailed,
                safe_ids.0,
                safe_ids.1,
            )
        })?;
        if principal.lifecycle() == PrincipalLifecycle::Revoked {
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::Revoked,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        if principal.lifecycle() != PrincipalLifecycle::Active
            || principal.epoch() != input.epoch()
        {
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::StaleEpoch,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        // Work already committed survives a disconnect, but a new mutation needs the
        // channel it was authorized on to still be live.
        let open = state
            .channels
            .get(&input.connection())
            .is_some_and(ChannelSession::is_open);
        if !open {
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::AuthenticationFailed,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        state.object_version = state.object_version.saturating_add(1);
        Ok(state.object_version)
    }

    /// The number of object mutations this process has committed.
    pub(crate) fn object_version(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.object_version)
            .unwrap_or_default()
    }

    /// The auditable record of one applied idempotency key.
    pub(crate) fn recorded(&self, key: IdempotencyKey) -> Option<TransitionRecord> {
        Some(self.state.lock().ok()?.applied.get(&key)?.record.clone())
    }

    /// The lifecycle of one pending enrollment this process registered.
    pub(crate) fn enrollment_lifecycle(
        &self,
        enrollment: TransitionId,
    ) -> Option<EnrollmentLifecycle> {
        Some(
            self.state
                .lock()
                .ok()?
                .enrollments
                .get(&enrollment)?
                .bundle
                .lifecycle(),
        )
    }

    /// The long-term fingerprint the enrollment host holds for one principal.
    pub(crate) fn custody_fingerprint(&self, principal: IdentityId) -> Option<Fingerprint> {
        self.state.lock().ok()?.host.registered_fingerprint(principal)
    }

    /// Whether the enrollment host quarantined one retired fingerprint.
    pub(crate) fn is_quarantined(&self, fingerprint: &Fingerprint) -> bool {
        self.state
            .lock()
            .map(|state| state.host.is_quarantined(fingerprint))
            .unwrap_or(true)
    }

    /// Seal one bundle's one-time key over an authenticated native channel. The
    /// pending registration keeps the only copy of that key, and it leaves exactly
    /// once.
    #[cfg(test)]
    pub(crate) fn seal_one_time_key(
        &self,
        enrollment: TransitionId,
        channel: &mut EnrollmentChannel,
    ) -> Result<crate::enrollment::EncryptedKeyOutput, TransitionRejection> {
        let mut state = self.lock()?;
        let registration = state.enrollments.get_mut(&enrollment).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthenticationFailed, None)
        })?;
        channel
            .seal_one_time_key(&mut registration.bundle)
            .map_err(|_| TransitionRejection::rejected(FailureCode::CredentialStoreMismatch, None))
    }

    /// The exact transcript a pairing peer signs for one pending enrollment.
    #[cfg(test)]
    pub(crate) fn proof_message(
        &self,
        enrollment: TransitionId,
        long_term: &PublicKey,
    ) -> Option<Vec<u8>> {
        let state = self.state.lock().ok()?;
        let registration = state.enrollments.get(&enrollment)?;
        Some(crate::enrollment::enrollment_proof_message(
            &registration.bundle,
            long_term,
        ))
    }
}

impl TransitionState {
    fn bootstrap<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        state_directory: IdentityId,
        material: BootstrapMaterial<'_>,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        if input.state_directory() != state_directory {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                None,
            ));
        }
        if input.prior_epoch() != 0 {
            return Err(TransitionRejection::rejected(FailureCode::StaleEpoch, None));
        }
        // The certified bootstrap path owns its own required events, envelope parsing,
        // nonce ledger, and staged-to-active promotion.
        let outcome = self
            .run_bootstrap(material, sink, time)
            .map_err(bootstrap_rejection)?;
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                command: command.clone(),
                record: TransitionRecord::Bootstrap,
            },
        );
        Ok(outcome)
    }

    /// Production custody: the platform credential store is the only one reachable here.
    #[cfg(not(test))]
    fn run_bootstrap<S: SecurityEventSink + ?Sized>(
        &mut self,
        material: BootstrapMaterial<'_>,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, BootstrapError> {
        self.bootstrap.bootstrap_encoded(
            material.pipe,
            material.envelope,
            sink,
            time,
            material.endpoint,
        )
    }

    #[cfg(test)]
    fn run_bootstrap<S: SecurityEventSink + ?Sized>(
        &mut self,
        material: BootstrapMaterial<'_>,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, BootstrapError> {
        match material.credential {
            Some(store) => self.bootstrap.bootstrap_encoded_with_store_for_test(
                material.pipe,
                material.envelope,
                store,
                sink,
                time,
                material.endpoint,
            ),
            None => self.bootstrap.bootstrap_encoded(
                material.pipe,
                material.envelope,
                sink,
                time,
                material.endpoint,
            ),
        }
    }

    fn create_enrollment<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        enrollment: TransitionId,
        daemon: IdentityId,
        creation: EnrollmentCreation,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let owner = self.active_principal(daemon)?.clone();
        if input.prior_epoch() != owner.epoch() {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(daemon),
            ));
        }
        if input.state_directory() != owner.credential().state_directory() {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(daemon),
            ));
        }
        if creation.enrollment != enrollment || creation.daemon != daemon {
            return Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                Some(daemon),
            ));
        }
        if self.enrollments.contains_key(&enrollment) {
            return Err(TransitionRejection::rejected(
                FailureCode::ReplayDetected,
                Some(daemon),
            ));
        }
        // An uncertain or elapsed deadline is never the basis of a new enrollment, and
        // the check precedes one-time key generation.
        if !creation.expiry.is_security_valid() {
            return Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                Some(daemon),
            ));
        }
        // Creating the bundle validates every bound and generates the one-time key
        // without touching registered state.
        let bundle = EnrollmentBundle::create(creation).map_err(|_| {
            TransitionRejection::rejected(FailureCode::MalformedInput, Some(daemon))
        })?;
        require_event(
            sink,
            enrollment.get(),
            EventBoundary::Enrollment,
            SecurityCode::EnrollmentAccepted,
            EventOutcome::Accepted,
            SafeNextAction::Continue,
            &owner,
            input.state_directory(),
            time,
            vec![MetadataEntry {
                key: "operation".into(),
                value: "enrollment-create".into(),
            }],
        )?;
        let epoch = owner.epoch();
        self.enrollments.insert(
            enrollment,
            EnrollmentRegistration {
                bundle,
                owner: daemon,
                epoch,
            },
        );
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                command: command.clone(),
                record: TransitionRecord::EnrollmentCreated(enrollment),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    fn consume_enrollment<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        enrollment: TransitionId,
        pairing: PairingMaterial<'_>,
        sink: Option<&mut S>,
        // The enrollment host times its own required event from the supplied clock, so
        // this transition contributes no second timestamp.
        _time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let registration = self.enrollments.get(&enrollment).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::ReplayDetected, Some(pairing.identity))
        })?;
        let (owner_id, registered_epoch) = (registration.owner, registration.epoch);
        let owner = self.active_principal(owner_id)?.clone();
        if input.prior_epoch() != registered_epoch || owner.epoch() != registered_epoch {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(owner_id),
            ));
        }
        if input.state_directory() != owner.credential().state_directory() {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(owner_id),
            ));
        }
        if self.principals.contains_key(&pairing.identity) {
            return Err(TransitionRejection::rejected(
                FailureCode::ReplayDetected,
                Some(pairing.identity),
            ));
        }
        if pairing.proof.identity != pairing.identity {
            return Err(TransitionRejection::rejected(
                FailureCode::AuthenticationFailed,
                Some(pairing.identity),
            ));
        }
        if pairing.credential.daemon() != owner_id
            || pairing.credential.state_directory() != owner.credential().state_directory()
        {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(pairing.identity),
            ));
        }
        // The principal this consumption registers is built before the proof is
        // consumed, so a binding the registry would refuse cannot leave a consumed
        // enrollment behind.
        let fingerprint = Fingerprint::from_public_key(&pairing.proof.long_term_public_key);
        let mut candidate = Principal::new(
            pairing.identity,
            PrincipalKind::BrowserExtension,
            pairing.proof.long_term_public_key.clone(),
            fingerprint.clone(),
            owner_id,
            pairing.ceiling,
            pairing.credential,
        )
        .map_err(|_| {
            TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(pairing.identity),
            )
        })?;
        candidate.activate().map_err(|_| {
            TransitionRejection::rejected(
                FailureCode::AuthenticationFailed,
                Some(pairing.identity),
            )
        })?;
        let Self {
            host, enrollments, ..
        } = self;
        let registration = enrollments.get_mut(&enrollment).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::ReplayDetected, Some(pairing.identity))
        })?;
        // The enrollment host owns proof verification, the budgets, and the required
        // enrollment event; it commits the one-use consumption or nothing.
        let proven = host
            .consume_proof(
                &mut registration.bundle,
                pairing.proof,
                pairing.identity,
                pairing.clock,
                pairing.binding,
                pairing.capability,
                pairing.channel,
                sink,
            )
            .map_err(|error| consume_rejection(error, pairing.identity))?;
        if proven != fingerprint {
            return Err(TransitionRejection::undecided(
                FailureCode::CredentialStoreMismatch,
                Some(pairing.identity),
            ));
        }
        let identity = pairing.identity;
        self.principals.insert(identity, candidate);
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                command: command.clone(),
                record: TransitionRecord::EnrollmentConsumed {
                    enrollment,
                    principal: identity,
                    fingerprint,
                },
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    fn rotate<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        principal: IdentityId,
        new_fingerprint: &Fingerprint,
        replacement: ReplacementCredential,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let current = self.active_principal(principal)?.clone();
        if input.prior_epoch() != current.epoch() {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(principal),
            ));
        }
        if input.state_directory() != current.credential().state_directory() {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(principal),
            ));
        }
        // One whole replacement: the fingerprint names the key being installed, the
        // key is not the retired one, and the locator stays inside the owning daemon
        // and state directory.
        let fingerprint = replacement.fingerprint();
        if &fingerprint != new_fingerprint
            || replacement.public_key == *current.public_key()
            || replacement.credential.daemon() != current.owner()
            || replacement.credential.state_directory()
                != current.credential().state_directory()
        {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(principal),
            ));
        }
        // A principal the enrollment host stores a key for rotates together with that
        // custody, so no retired extension key survives unquarantined.
        let custody = match (
            self.host.registered_fingerprint(principal),
            replacement.custody.as_ref(),
        ) {
            (Some(_), None) => {
                return Err(TransitionRejection::rejected(
                    FailureCode::CredentialStoreMismatch,
                    Some(principal),
                ));
            }
            (Some(_), Some(capability)) => Some(capability),
            (None, _) => None,
        };
        let next_epoch = current
            .epoch()
            .checked_add(1)
            .ok_or_else(|| TransitionRejection::rejected(FailureCode::ResourceLimit, Some(principal)))?;
        // The auditable carrier validates the epoch boundary and the fingerprint
        // change before anything is written.
        let carrier = RotationTransition::new(
            command.idempotency(),
            principal,
            current.fingerprint().clone(),
            fingerprint.clone(),
            current.epoch(),
            next_epoch,
            next_epoch,
            TransitionOutcome::Committed,
        )
        .map_err(|_| {
            TransitionRejection::rejected(FailureCode::CredentialStoreMismatch, Some(principal))
        })?;
        // The replacement is registered on the snapshot before its epoch moves. The
        // snapshot is written back only once it is whole.
        let mut rotated = current.clone();
        rotated
            .begin_rotation()
            .and_then(|()| {
                rotated.complete_rotation(
                    replacement.public_key.clone(),
                    fingerprint.clone(),
                    replacement.credential.clone(),
                )
            })
            .map_err(|_| {
                TransitionRejection::rejected(
                    FailureCode::CredentialStoreMismatch,
                    Some(principal),
                )
            })?;
        require_event(
            sink,
            input.transition().get(),
            EventBoundary::Rotation,
            SecurityCode::Rotation,
            EventOutcome::Accepted,
            SafeNextAction::Reconnect,
            &current,
            input.state_directory(),
            time,
            vec![
                MetadataEntry {
                    key: "operation".into(),
                    value: "rotation".into(),
                },
                MetadataEntry {
                    key: "epoch".into(),
                    value: next_epoch.to_string(),
                },
            ],
        )?;
        if let Some(capability) = custody {
            self.host
                .update_custody(principal, &replacement.public_key, capability)
                .map_err(|error| consume_rejection(error, principal))?;
        }
        self.principals.insert(principal, rotated);
        self.close_channels_for(principal);
        self.invalidate_grants_for(principal);
        self.invalidate_decisions_for(principal);
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                command: command.clone(),
                record: TransitionRecord::Rotated(carrier),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    fn revoke<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        principal: IdentityId,
        reason: &str,
        sink: Option<&mut S>,
        time: EventTime,
    ) -> Result<TransitionOutcome, TransitionRejection> {
        let current = self.active_principal(principal)?.clone();
        if input.prior_epoch() != current.epoch() {
            return Err(TransitionRejection::rejected(
                FailureCode::StaleEpoch,
                Some(principal),
            ));
        }
        if input.state_directory() != current.credential().state_directory() {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(principal),
            ));
        }
        let channels = self.open_channels_for(principal);
        let grants = self.active_grants_for(principal);
        let carrier = RevocationTransition::new(
            command.idempotency(),
            principal,
            reason,
            current.epoch(),
            channels,
            grants,
            TransitionOutcome::Committed,
        )
        .map_err(|_| {
            TransitionRejection::rejected(FailureCode::MalformedInput, Some(principal))
        })?;
        require_event(
            sink,
            input.transition().get(),
            EventBoundary::Revocation,
            SecurityCode::Revocation,
            EventOutcome::Accepted,
            SafeNextAction::RePair,
            &current,
            input.state_directory(),
            time,
            vec![
                MetadataEntry {
                    key: "operation".into(),
                    value: "revocation".into(),
                },
                MetadataEntry {
                    key: "reason_class".into(),
                    value: reason.to_owned(),
                },
            ],
        )?;
        if self.host.registered_fingerprint(principal).is_some() {
            self.host
                .revoke(principal)
                .map_err(|error| consume_rejection(error, principal))?;
        }
        let mut revoked = current.clone();
        revoked.revoke();
        self.principals.insert(principal, revoked);
        self.close_channels_for(principal);
        self.invalidate_grants_for(principal);
        self.invalidate_decisions_for(principal);
        self.revoke_enrollments_of(principal);
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                command: command.clone(),
                record: TransitionRecord::Revoked(carrier),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    /// The registered principal a transition targets, refused unless it is active.
    fn active_principal(
        &self,
        principal: IdentityId,
    ) -> Result<&Principal, TransitionRejection> {
        let registered = self.principals.get(&principal).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::AuthenticationFailed, Some(principal))
        })?;
        match registered.lifecycle() {
            PrincipalLifecycle::Active => Ok(registered),
            // Revocation is terminal: no later transition reopens it.
            PrincipalLifecycle::Revoked => Err(TransitionRejection::rejected(
                FailureCode::Revoked,
                Some(principal),
            )),
            _ => Err(TransitionRejection::rejected(
                FailureCode::AuthenticationFailed,
                Some(principal),
            )),
        }
    }

    fn open_channels_for(&self, principal: IdentityId) -> u32 {
        self.channels
            .values()
            .filter(|session| session.principal() == principal && session.is_open())
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    fn active_grants_for(&self, principal: IdentityId) -> u32 {
        self.grants
            .iter()
            .filter(|grant| {
                grant.extension() == principal && grant.lifecycle() == GrantLifecycle::Active
            })
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    fn close_channels_for(&mut self, principal: IdentityId) {
        for session in self.channels.values_mut() {
            if session.principal() == principal {
                session.close();
            }
        }
    }

    /// Every grant is bound to the epoch it was approved at, so a committed rotation
    /// or revocation invalidates all of them.
    fn invalidate_grants_for(&mut self, principal: IdentityId) {
        for grant in &mut self.grants {
            if grant.extension() == principal {
                grant.revoke();
            }
        }
    }

    fn invalidate_decisions_for(&mut self, principal: IdentityId) {
        for decision in self.decisions.values_mut() {
            if decision.extension == principal && decision.state == DecisionState::Pending {
                decision.state = DecisionState::Invalidated;
            }
        }
    }

    fn revoke_enrollments_of(&mut self, owner: IdentityId) {
        for registration in self.enrollments.values_mut() {
            if registration.owner == owner {
                registration.bundle.revoke();
            }
        }
    }
}

/// Build one redacted transition event and require it before the commit it justifies.
#[allow(clippy::too_many_arguments)]
fn require_event<S: SecurityEventSink + ?Sized>(
    sink: Option<&mut S>,
    event_id: uuid::Uuid,
    boundary: EventBoundary,
    code: SecurityCode,
    outcome: EventOutcome,
    next_action: SafeNextAction,
    principal: &Principal,
    state_directory: IdentityId,
    time: EventTime,
    metadata: Vec<MetadataEntry>,
) -> Result<(), TransitionRejection> {
    let unavailable = || {
        TransitionRejection::rejected(FailureCode::EventSinkUnavailable, Some(principal.id()))
    };
    let event = SecurityEvent::new(
        event_id,
        boundary,
        code,
        outcome,
        next_action,
        Some(principal.id().get()),
        None,
        endpoint_class(principal.kind()),
        time,
        state_directory.get(),
        metadata,
    )
    .map_err(|_| unavailable())?;
    emit_required(sink, event).map_err(|_| unavailable())?;
    Ok(())
}

fn bootstrap_rejection(error: BootstrapError) -> TransitionRejection {
    match error {
        BootstrapError::Pipe(_) | BootstrapError::Envelope(_) | BootstrapError::InvalidKey => {
            TransitionRejection::rejected(FailureCode::MalformedInput, None)
        }
        BootstrapError::Credential(CredentialStoreError::Unavailable) => {
            TransitionRejection::rejected(FailureCode::CredentialStoreUnavailable, None)
        }
        BootstrapError::Credential(_) | BootstrapError::IdentityMismatch => {
            TransitionRejection::rejected(FailureCode::CredentialStoreMismatch, None)
        }
        BootstrapError::AlreadyUsed => {
            TransitionRejection::rejected(FailureCode::ReplayDetected, None)
        }
        BootstrapError::EventUnavailable => {
            TransitionRejection::rejected(FailureCode::EventSinkUnavailable, None)
        }
        BootstrapError::EndpointRejected => {
            TransitionRejection::rejected(FailureCode::EndpointRejected, None)
        }
        // A crash leaves the durable outcome undetermined until recovery runs.
        BootstrapError::Crash(_) => {
            TransitionRejection::undecided(FailureCode::TransitionUnknown, None)
        }
    }
}

fn consume_rejection(error: EnrollmentConsumeError, principal: IdentityId) -> TransitionRejection {
    match error {
        // An uncertain deadline decides nothing, so consumption cannot be called
        // rejected either.
        EnrollmentConsumeError::UncertainExpiry | EnrollmentConsumeError::EventUnavailable => {
            TransitionRejection::undecided(FailureCode::TransitionUnknown, Some(principal))
        }
        EnrollmentConsumeError::Expired | EnrollmentConsumeError::AlreadyConsumed => {
            TransitionRejection::rejected(FailureCode::ReplayDetected, Some(principal))
        }
        EnrollmentConsumeError::WrongIdentity
        | EnrollmentConsumeError::InvalidProof
        | EnrollmentConsumeError::InvalidPublicKey
        | EnrollmentConsumeError::ChannelClosed => {
            TransitionRejection::rejected(FailureCode::AuthenticationFailed, Some(principal))
        }
        EnrollmentConsumeError::RateLimited => {
            TransitionRejection::rejected(FailureCode::RateLimited, Some(principal))
        }
        EnrollmentConsumeError::CredentialMismatch
        | EnrollmentConsumeError::CapabilityRejected => {
            TransitionRejection::rejected(FailureCode::CredentialStoreMismatch, Some(principal))
        }
    }
}

#[cfg(test)]
mod tests {
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
