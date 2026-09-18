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

use crate::adapters::credential_store::{
    CredentialStore, CredentialStoreError, PlatformCredentialStore,
};
use crate::adapters::os_pipe::{
    BootstrapEnvelope, EnvelopeError, NonceLedger, OsPipe, OsPipeError, PlatformOsPipe,
};
use crate::authorization::endpoint_class;
use crate::enrollment::{
    ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentBundle,
    EnrollmentChannel, EnrollmentClock, EnrollmentConsumeError, EnrollmentConsumptionService,
    EnrollmentCreation, EnrollmentProof,
};
use crate::events::{
    EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry, SafeNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink, emit_required,
};
use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{
    Capability, CapabilityAction, ConnectionId, CredentialReference, EnrollmentLifecycle,
    ExpiryStatus, ExtensionGrant, Fingerprint, GrantLifecycle, IdempotencyKey, IdentityId,
    Principal, PrincipalKind, PrincipalLifecycle, PublicKey, RevocationTransition,
    RotationTransition, TransitionId, TransitionInput, TransitionOperation, TransitionOutcome,
};
use crate::{
    AuthorizedInput, ChannelSession, ObjectOwner, PayloadKind, SecurityCommand, SessionInput,
};

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
    pub(crate) fn active(&self) -> Option<&BootstrapRecord> {
        self.active.as_ref()
    }
    pub(crate) fn staged(&self) -> Option<&BootstrapRecord> {
        self.staged.as_ref()
    }

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
            pipe,
            encoded_envelope,
            &credential,
            sink,
            None,
            event_time,
            endpoint_bytes,
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
    pub(crate) fn bootstrap_encoded_with_store_for_test<
        P: OsPipe + ?Sized,
        C: CredentialStore + ?Sized,
        S: SecurityEventSink + ?Sized,
    >(
        &mut self,
        pipe: &P,
        encoded_envelope: &[u8],
        credential: &C,
        sink: Option<&mut S>,
        event_time: EventTime,
        endpoint_bytes: &[u8],
    ) -> Result<TransitionOutcome, BootstrapError> {
        self.bootstrap_encoded_inner(
            pipe,
            encoded_envelope,
            credential,
            sink,
            None,
            event_time,
            endpoint_bytes,
        )
    }

    #[cfg(test)]
    pub(crate) fn bootstrap_encoded_for_test<
        P: OsPipe + ?Sized,
        C: CredentialStore + ?Sized,
        S: SecurityEventSink + ?Sized,
    >(
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
            pipe,
            encoded_envelope,
            credential,
            sink,
            crash,
            event_time,
            endpoint_bytes,
        )
    }

    fn bootstrap_encoded_inner<
        P: OsPipe + ?Sized,
        C: CredentialStore + ?Sized,
        S: SecurityEventSink + ?Sized,
    >(
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
            let envelope =
                BootstrapEnvelope::parse(encoded_envelope).map_err(BootstrapError::Envelope)?;
            let endpoint = BootstrapEnvelope::parse_endpoint(endpoint_bytes)
                .map_err(BootstrapError::Envelope)?;
            self.apply(&envelope, credential, sink, crash, event_time, endpoint)
        })();
        if result.is_err() {
            inherited.close_on_error();
        } else {
            inherited.close();
        }
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
        self.ledger
            .consume(envelope.nonce)
            .map_err(|_| BootstrapError::AlreadyUsed)?;
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
            vec![MetadataEntry {
                key: "operation".into(),
                value: "bootstrap".into(),
            }],
        )
        .map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
        emit_required(sink.as_deref_mut(), bootstrap_event).map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
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
            vec![MetadataEntry {
                key: "phase".into(),
                value: "identity".into(),
            }],
        )
        .map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
        emit_required(sink.as_deref_mut(), identity_event).map_err(|_| {
            self.ledger.release(&envelope.nonce);
            BootstrapError::EventUnavailable
        })?;
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
    if endpoint.starts_with("native://") {
        EndpointClass::Native
    } else if endpoint.starts_with("chrome-extension://") {
        EndpointClass::Extension
    } else if endpoint.starts_with("127.0.0.1:") || endpoint.starts_with("[::1]:") {
        EndpointClass::Loopback
    } else {
        EndpointClass::Unknown
    }
}

/// A refused transition: one closed outcome and one bounded failure.
///
/// `Rejected` is a decided refusal: this process knows nothing was committed and the
/// same idempotency key may be retried once its cause is repaired. `Unknown` is an
/// undecidable one: the durable record, the deadline, or the lock could not be read,
/// so the module reports no protected success and mutates nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionRejection {
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

    pub fn outcome(&self) -> TransitionOutcome {
        self.outcome
    }

    pub fn failure(&self) -> SecurityFailure {
        self.failure
    }

    pub fn code(&self) -> FailureCode {
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
fn transition_digest(
    command: &SecurityCommand,
    input: &TransitionInput,
    material: &TransitionMaterial<'_>,
) -> [u8; 32] {
    let mut digest = CanonicalDigest::new();
    digest.bytes("domain", b"matinee.transition.replay.v1");
    match command {
        SecurityCommand::Bootstrap {
            state_directory,
            idempotency,
        } => {
            digest.byte("command", 0);
            digest.uuid("state-directory", state_directory.get());
            digest.uuid("idempotency", idempotency.get());
        }
        SecurityCommand::CreateEnrollment {
            enrollment,
            daemon,
            idempotency,
        } => {
            digest.byte("command", 1);
            digest.uuid("enrollment", enrollment.get());
            digest.uuid("daemon", daemon.get());
            digest.uuid("idempotency", idempotency.get());
        }
        SecurityCommand::ConsumeEnrollment {
            enrollment,
            idempotency,
        } => {
            digest.byte("command", 2);
            digest.uuid("enrollment", enrollment.get());
            digest.uuid("idempotency", idempotency.get());
        }
        SecurityCommand::Rotate {
            principal,
            new_fingerprint,
            idempotency,
        } => {
            digest.byte("command", 3);
            digest.uuid("principal", principal.get());
            digest.bytes("new-fingerprint", new_fingerprint.as_str().as_bytes());
            digest.uuid("idempotency", idempotency.get());
        }
        SecurityCommand::Revoke {
            principal,
            idempotency,
        } => {
            digest.byte("command", 4);
            digest.uuid("principal", principal.get());
            digest.uuid("idempotency", idempotency.get());
        }
    }
    digest.uuid("input-state-directory", input.state_directory().get());
    digest.uuid("input-transition", input.transition().get());
    digest.byte("input-operation", operation_code(input.operation()));
    digest.uuid("input-idempotency", input.idempotency().get());
    digest.u64("input-prior-epoch", input.prior_epoch());
    digest.byte("input-outcome", outcome_code(input.outcome()));
    match material {
        TransitionMaterial::Bootstrap(value) => {
            digest.byte("material", 0);
            digest.bytes("envelope", value.envelope);
            digest.bytes("endpoint", value.endpoint);
        }
        TransitionMaterial::Enrollment(value) => {
            digest.byte("material", 1);
            digest.uuid("enrollment", value.enrollment.get());
            digest.bytes("origin", value.origin.as_bytes());
            digest.bytes("store", value.store_metadata.as_bytes());
            digest.bytes("update", value.update_metadata.as_bytes());
            digest.bytes("install", value.install_metadata.as_bytes());
            digest.uuid("daemon", value.daemon.get());
            digest.bytes("daemon-endpoint", value.daemon_endpoint.as_bytes());
            digest.byte("expiry-status", expiry_code(value.expiry.status()));
            digest.u64("expiry-deadline", value.expiry.deadline_ms());
        }
        TransitionMaterial::Pairing(value) => {
            digest.byte("material", 2);
            digest.uuid("identity", value.identity.get());
            digest.uuid("proof-identity", value.proof.identity.get());
            digest.bytes("proof-signature", &value.proof.signature);
            digest.bytes(
                "proof-public-key",
                value.proof.long_term_public_key.as_bytes(),
            );
            digest.u64("clock-occurrence", value.clock.occurrence_ms());
            digest.byte(
                "clock-expiry-status",
                expiry_code(value.clock.expiry().status()),
            );
            digest.u64("clock-expiry-deadline", value.clock.expiry().deadline_ms());
            digest.bytes("binding-origin", value.binding.origin.as_bytes());
            digest.bytes("binding-endpoint", value.binding.endpoint.as_bytes());
            digest.bytes("binding-store", value.binding.store_metadata.as_bytes());
            digest.bytes("binding-update", value.binding.update_metadata.as_bytes());
            digest.bytes("binding-install", value.binding.install_metadata.as_bytes());
            let development = match value.binding.development_allowance {
                DevelopmentIdentityAllowance::None => 0,
                DevelopmentIdentityAllowance::Explicit {
                    warning_acknowledged: false,
                } => 1,
                DevelopmentIdentityAllowance::Explicit {
                    warning_acknowledged: true,
                } => 2,
            };
            digest.byte("binding-development", development);
            add_chrome_capability(&mut digest, value.capability);
            digest.uuid("channel-connection", value.channel.connection().get());
            digest.u64("channel-epoch", value.channel.epoch());
            digest.u64("ceiling-count", value.ceiling.len() as u64);
            for capability in &value.ceiling {
                add_capability(&mut digest, capability);
            }
            add_credential(&mut digest, &value.credential);
        }
        TransitionMaterial::Replacement(value) => {
            digest.byte("material", 3);
            digest.bytes("replacement-key", value.public_key.as_bytes());
            add_credential(&mut digest, &value.credential);
            digest.bool("replacement-custody", value.custody.is_some());
            if let Some(capability) = &value.custody {
                add_chrome_capability(&mut digest, capability);
            }
        }
        TransitionMaterial::Revocation(reason) => {
            digest.byte("material", 4);
            digest.bytes("reason", reason.as_bytes());
        }
    }
    digest.finish()
}

fn add_chrome_capability(digest: &mut CanonicalDigest, capability: &ChromeCapability) {
    let (origin, store, update, install, storage_local, non_exportable) =
        capability.canonical_fields();
    digest.bytes("capability-origin", origin.as_bytes());
    digest.bytes("capability-store", store.as_bytes());
    digest.bytes("capability-update", update.as_bytes());
    digest.bytes("capability-install", install.as_bytes());
    digest.bool("capability-storage-local", storage_local);
    digest.bool("capability-non-exportable", non_exportable);
}

fn add_capability(digest: &mut CanonicalDigest, capability: &Capability) {
    let action = match capability.action() {
        CapabilityAction::Read => 0,
        CapabilityAction::Write => 1,
        CapabilityAction::Execute => 2,
        CapabilityAction::Administer => 3,
        CapabilityAction::ManagePrincipals => 4,
        CapabilityAction::Rotate => 5,
        CapabilityAction::Revoke => 6,
    };
    digest.byte("capability-action", action);
    digest.bytes("capability-scope", capability.resource_scope().as_bytes());
}

fn add_credential(digest: &mut CanonicalDigest, credential: &CredentialReference) {
    digest.bytes("credential-provider", credential.provider().as_bytes());
    digest.bytes("credential-locator", credential.key_locator().as_bytes());
    digest.uuid("credential-daemon", credential.daemon().get());
    digest.uuid(
        "credential-state-directory",
        credential.state_directory().get(),
    );
}

const fn operation_code(operation: &TransitionOperation) -> u8 {
    match operation {
        TransitionOperation::Bootstrap => 0,
        TransitionOperation::EnrollmentCreate => 1,
        TransitionOperation::EnrollmentConsume => 2,
        TransitionOperation::Rotation => 3,
        TransitionOperation::Revocation => 4,
    }
}

const fn outcome_code(outcome: TransitionOutcome) -> u8 {
    match outcome {
        TransitionOutcome::Committed => 0,
        TransitionOutcome::AlreadyCommitted => 1,
        TransitionOutcome::Rejected => 2,
        TransitionOutcome::Unknown => 3,
    }
}

const fn expiry_code(status: ExpiryStatus) -> u8 {
    match status {
        ExpiryStatus::Valid => 0,
        ExpiryStatus::Expired => 1,
        ExpiryStatus::Uncertain => 2,
    }
}

struct CanonicalDigest(ring::digest::Context);

impl CanonicalDigest {
    fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        self.0.update(&(name.len() as u32).to_be_bytes());
        self.0.update(name.as_bytes());
        self.0.update(&(value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn byte(&mut self, name: &str, value: u8) {
        self.bytes(name, &[value]);
    }

    fn bool(&mut self, name: &str, value: bool) {
        self.byte(name, u8::from(value));
    }

    fn u64(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    fn uuid(&mut self, name: &str, value: uuid::Uuid) {
        self.bytes(name, value.as_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.0
            .finish()
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes")
    }
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
    digest: [u8; 32],
    record: TransitionRecord,
}

struct RetiredCredential {
    public_key: PublicKey,
    fingerprint: Fingerprint,
    credential: CredentialReference,
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
    retired_credentials: HashMap<IdentityId, Vec<RetiredCredential>>,
    host: EnrollmentConsumptionService,
    object_version: u64,
}

#[cfg(test)]
pub(crate) struct ApplyGate {
    acquired: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
impl ApplyGate {
    pub(crate) fn wait_until_acquired(&self) {
        self.acquired.wait();
    }

    pub(crate) fn release(&self) {
        self.release.wait();
    }
}

/// The one process-lifetime security state every transition serializes against.
#[derive(Default)]
pub struct SecurityTransitions {
    state: Mutex<TransitionState>,
    #[cfg(test)]
    next_apply_gate: Mutex<Option<std::sync::Arc<ApplyGate>>>,
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
    #[cfg(test)]
    pub(crate) fn gate_next_apply(&self) -> std::sync::Arc<ApplyGate> {
        let gate = std::sync::Arc::new(ApplyGate {
            acquired: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        *self.next_apply_gate.lock().expect("apply gate lock") = Some(gate.clone());
        gate
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
        let digest = transition_digest(command, input, &material);
        let mut state = self.lock()?;
        #[cfg(test)]
        if let Some(gate) = self.next_apply_gate.lock().expect("apply gate lock").take() {
            gate.acquired.wait();
            gate.release.wait();
        }
        if *input.operation() != command.operation() || input.idempotency() != command.idempotency()
        {
            return Err(TransitionRejection::undecided(
                FailureCode::TransitionUnknown,
                None,
            ));
        }
        if let Some(applied) = state.applied.get(&command.idempotency()) {
            return if applied.digest == digest {
                Ok(TransitionOutcome::AlreadyCommitted)
            } else {
                Err(TransitionRejection::undecided(
                    FailureCode::TransitionUnknown,
                    None,
                ))
            };
        }
        if input.outcome() == TransitionOutcome::AlreadyCommitted {
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
            ) => state.bootstrap(
                command,
                input,
                digest,
                *state_directory,
                bootstrap,
                sink,
                time,
            ),
            (
                SecurityCommand::CreateEnrollment {
                    enrollment, daemon, ..
                },
                TransitionMaterial::Enrollment(creation),
            ) => state.create_enrollment(
                command,
                input,
                digest,
                *enrollment,
                *daemon,
                creation,
                sink,
                time,
            ),
            (
                SecurityCommand::ConsumeEnrollment { enrollment, .. },
                TransitionMaterial::Pairing(pairing),
            ) => state.consume_enrollment(command, input, digest, *enrollment, pairing, sink, time),
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
                digest,
                *principal,
                new_fingerprint,
                replacement,
                sink,
                time,
            ),
            (SecurityCommand::Revoke { principal, .. }, TransitionMaterial::Revocation(reason)) => {
                state.revoke(command, input, digest, *principal, reason, sink, time)
            }
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
    pub fn register_principal(&self, principal: Principal) -> Result<(), TransitionRejection> {
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
    pub fn register_channel(
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
    pub fn close_channel(&self, connection: ConnectionId) -> bool {
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

    pub fn channel_is_open(&self, connection: ConnectionId) -> bool {
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
        let pending = state
            .decisions
            .get(&decision)
            .ok_or_else(|| TransitionRejection::rejected(FailureCode::AuthorizationDenied, None))?;
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
    pub fn receive(
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
    /// Authorize and seal one daemon projection on a registered live channel.
    pub fn send_projection(
        &self,
        connection: ConnectionId,
        projection: &crate::SessionProjection<'_>,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<Vec<u8>, SecurityFailure> {
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
        if principal.lifecycle() == PrincipalLifecycle::Revoked {
            session.close();
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::Revoked,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        if principal.lifecycle() != PrincipalLifecycle::Active {
            session.close();
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::AuthenticationFailed,
                safe_ids.0,
                safe_ids.1,
            ));
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
        let operation = projection.operation();
        let coordinated = crate::SessionProjection::new(
            projection.class(),
            operation.requested().clone(),
            operation.owner(),
            grant,
            projection.payload(),
        );
        session.send_projection(&coordinated, sink)
    }

    /// Commit one object mutation the receive path authorized.
    ///
    /// The authorized input carries the epoch it was minted at, so an input that
    /// crossed a committed rotation or revocation mutates nothing. The registry is
    /// consulted before the connection, so a stale credential is reported as the stale
    /// epoch it is rather than as the closed channel that followed from it.
    pub fn commit_mutation(
        &self,
        input: &AuthorizedInput,
        expected: &SessionInput<'_>,
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
        if principal.lifecycle() != PrincipalLifecycle::Active || principal.epoch() != input.epoch()
        {
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::StaleEpoch,
                safe_ids.0,
                safe_ids.1,
            ));
        }
        if input.granted() != expected.requested()
            || input.kind() != expected.kind()
            || input.owner() != expected.owner()
            || input.granted().action() != &CapabilityAction::Write
            || input.kind() != PayloadKind::Command
            || input.owner() != ObjectOwner::Owned(principal.owner())
        {
            return Err(SecurityFailure::with_safe_ids(
                FailureCode::AuthorizationDenied,
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
        self.state
            .lock()
            .ok()?
            .host
            .registered_fingerprint(principal)
    }

    #[cfg(test)]
    pub(crate) fn custody_is_revoked(&self, principal: IdentityId) -> Option<bool> {
        self.state.lock().ok()?.host.is_revoked(principal)
    }

    /// Whether the enrollment host quarantined one retired fingerprint.
    pub(crate) fn is_quarantined(&self, fingerprint: &Fingerprint) -> bool {
        self.state
            .lock()
            .map(|state| state.host.is_quarantined(fingerprint))
            .unwrap_or(true)
    }
    #[cfg(test)]
    pub(crate) fn fail_next_custody_validation(&self) {
        let mut state = self.state.lock().expect("transition state lock");
        state.host.fail_next_custody_validation();
    }
    #[cfg(test)]
    pub(crate) fn fail_next_custody_revocation(&self) {
        let mut state = self.state.lock().expect("transition state lock");
        state.host.fail_next_custody_revocation();
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
        digest: [u8; 32],
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
                digest,
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
        digest: [u8; 32],
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
                digest,
                record: TransitionRecord::EnrollmentCreated(enrollment),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    fn consume_enrollment<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        digest: [u8; 32],
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
            TransitionRejection::rejected(FailureCode::AuthenticationFailed, Some(pairing.identity))
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
                digest,
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
        digest: [u8; 32],
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
        // No key, fingerprint, or locator that became retired may ever become active
        // again. The current locator must move too, otherwise it would become both
        // active and retired in this commit.
        let fingerprint = replacement.fingerprint();
        let reactivates_retired = self
            .retired_credentials
            .get(&principal)
            .is_some_and(|retired| {
                retired.iter().any(|retired| {
                    retired.public_key == replacement.public_key
                        || retired.fingerprint == fingerprint
                        || retired.credential == replacement.credential
                })
            });
        if &fingerprint != new_fingerprint
            || replacement.public_key == *current.public_key()
            || replacement.credential == *current.credential()
            || reactivates_retired
            || replacement.credential.daemon() != current.owner()
            || replacement.credential.state_directory() != current.credential().state_directory()
        {
            return Err(TransitionRejection::rejected(
                FailureCode::CredentialStoreMismatch,
                Some(principal),
            ));
        }
        // Every fallible custody check completes before the accepted event. The
        // resulting plan is an owned, validated commit that cannot fail afterwards.
        let custody_update = match (
            self.host.registered_fingerprint(principal),
            replacement.custody.as_ref(),
        ) {
            (Some(_), None) => {
                return Err(TransitionRejection::rejected(
                    FailureCode::CredentialStoreMismatch,
                    Some(principal),
                ));
            }
            (Some(_), Some(capability)) => Some(
                self.host
                    .prepare_custody_update(principal, &replacement.public_key, capability)
                    .map_err(|error| consume_rejection(error, principal))?,
            ),
            (None, _) => None,
        };
        let next_epoch = current.epoch().checked_add(1).ok_or_else(|| {
            TransitionRejection::rejected(FailureCode::ResourceLimit, Some(principal))
        })?;
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
                TransitionRejection::rejected(FailureCode::CredentialStoreMismatch, Some(principal))
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
        if let Some(update) = custody_update {
            self.host.commit_custody_update(update);
        }
        self.retired_credentials
            .entry(principal)
            .or_default()
            .push(RetiredCredential {
                public_key: current.public_key().clone(),
                fingerprint: current.fingerprint().clone(),
                credential: current.credential().clone(),
            });
        self.principals.insert(principal, rotated);
        self.close_channels_for(principal);
        self.invalidate_grants_for(principal);
        self.invalidate_decisions_for(principal);
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                digest,
                record: TransitionRecord::Rotated(carrier),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    fn revoke<S: SecurityEventSink + ?Sized>(
        &mut self,
        command: &SecurityCommand,
        input: &TransitionInput,
        digest: [u8; 32],
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
        .map_err(|_| TransitionRejection::rejected(FailureCode::MalformedInput, Some(principal)))?;
        // The outer transition-state guard owns the host for the entire stage/event/commit
        // sequence, so this validated plan cannot become stale before its infallible commit.
        let custody_revocation = self
            .host
            .prepare_custody_revocation(principal)
            .map_err(|error| consume_rejection(error, principal))?;
        let mut revoked = current.clone();
        revoked.revoke();
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
        if let Some(revocation) = custody_revocation {
            self.host.commit_custody_revocation(revocation);
        }
        self.principals.insert(principal, revoked);
        self.close_channels_for(principal);
        self.invalidate_grants_for(principal);
        self.invalidate_decisions_for(principal);
        self.revoke_enrollments_of(principal);
        self.applied.insert(
            command.idempotency(),
            AppliedTransition {
                digest,
                record: TransitionRecord::Revoked(carrier),
            },
        );
        Ok(TransitionOutcome::Committed)
    }

    /// The registered principal a transition targets, refused unless it is active.
    fn active_principal(&self, principal: IdentityId) -> Result<&Principal, TransitionRejection> {
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
    let unavailable =
        || TransitionRejection::rejected(FailureCode::EventSinkUnavailable, Some(principal.id()));
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
        EnrollmentConsumeError::CredentialMismatch | EnrollmentConsumeError::CapabilityRejected => {
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
