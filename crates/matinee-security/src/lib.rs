//! Private security implementation with a deliberately narrow crate boundary.
//!
//! Protocol framing, transcript handling, cryptographic operations, authorization
//! policy, origin validation, adapter access, and transition state remain behind
//! private modules. Consumers interact only through the typed session boundary, the
//! closed lifecycle command interface, and the enrollment lifecycle re-exported
//! here: the one-time private key, required-event sink, host attempt budgets, and
//! quarantine set are reachable through none of them.

// Foundational modules. Every declaration resolves to real content: a module is
// declared once it carries its own definitions, so channel framing, authorization
// policy, enrollment, and transition application are declared with the work that
// defines them.
mod adapters;
mod authorization;
mod channel;
mod enrollment;
mod events;
mod failures;
mod identity;
mod transition;
pub use crate::channel::{
    AdmittedEndpoint, ChannelSigner, ChannelSigningError, ClientHandshake, ClientHandshakeConfig,
    LoopbackHost, SECURE_CHANNEL_CONTEXT, ServerHandshake, ServerHandshakeConfig,
    StateBearingRequest, StateBearingRoute,
};
pub use crate::events::{
    EndpointClass, EventBoundary, EventOutcome, MetadataEntry, SafeNextAction as EventNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink, SecurityEventSinkResult,
};
pub use crate::failures::{FailureBoundary, FailureCode, SafeNextAction, SecurityFailure};
pub use crate::transition::{SecurityTransitions, TransitionRejection};

#[cfg(test)]
#[path = "../tests/support/channel.rs"]
mod test_support_channel;
#[cfg(test)]
#[path = "../tests/support/fakes.rs"]
mod test_support_fakes;
#[cfg(test)]
#[path = "../tests/support/transitions.rs"]
mod test_support_transitions;

use core::fmt;

use crate::events::EventTime;
use crate::identity::{IdempotencyKey, TransitionOperation};

/// The enrollment lifecycle a host process drives: create a bounded one-time
/// enrollment, seal its one-time key to one authenticated channel, consume the
/// pairing proof once, then reconnect, update encrypted custody, or revoke the
/// registered principal. Transcript assembly, budgets, quarantine, and event
/// emission stay behind this boundary.
pub use crate::enrollment::{
    ChromeCapability, ChromeReconnectOutcome, DevelopmentIdentityAllowance, EncryptedKeyOutput,
    EnrollmentBinding, EnrollmentBundle, EnrollmentChannel, EnrollmentClock,
    EnrollmentConsumeError, EnrollmentConsumptionService, EnrollmentCreateError,
    EnrollmentCreation, EnrollmentCustodyError, EnrollmentExpiry, EnrollmentProof,
    ExtensionVersion, ExtensionVersionError, SupportedExtensionVersions, enrollment_proof_message,
};
/// The registered identities and grants a session boundary is expressed in. A host builds
/// the principal snapshot a daemon channel authenticates against and the extension grant one
/// operation presents; the ceiling, epoch, and state directory travel inside them.
pub use crate::identity::{
    Capability, CapabilityAction, ConnectionId, CredentialReference, ExpiryResult, ExtensionGrant,
    Fingerprint, GrantLifecycle, IdentityId, Principal, PrincipalKind, PrincipalLifecycle,
    PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES,
};

/// v1 plaintext includes one payload-kind byte. The largest application payload is
/// therefore one byte below the 1,048,535-byte plaintext limit.
const MAX_PAYLOAD_BYTES: usize = 1_048_534;
/// A bounded artifact chunk carries at most this many content bytes.
const MAX_CHUNK_BYTES: usize = 1_000_000;

/// The closed set of payload shapes the session carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    Command,
    Response,
    Event,
    StreamChunk,
}

impl PayloadKind {
    /// The declared bound for this shape. A chunk is bounded below the frame maximum
    /// so one stream chunk cannot consume the whole frame budget.
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Command | Self::Response | Self::Event => MAX_PAYLOAD_BYTES,
            Self::StreamChunk => MAX_CHUNK_BYTES,
        }
    }

    pub(crate) const fn wire_code(self) -> u8 {
        match self {
            Self::Command => 1,
            Self::Response => 2,
            Self::Event => 3,
            Self::StreamChunk => 4,
        }
    }

    pub(crate) fn from_wire(code: u8) -> Result<Self, SecurityFailure> {
        match code {
            1 => Ok(Self::Command),
            2 => Ok(Self::Response),
            3 => Ok(Self::Event),
            4 => Ok(Self::StreamChunk),
            _ => Err(SecurityFailure::new(FailureCode::MalformedInput)),
        }
    }
}

/// Who owns the object one operation names, as the daemon resolved it.
///
/// `Unknown` covers an object that does not exist, one whose existence is not disclosable,
/// and one a filter removed. Authorization maps all three to the same `object.not_found`
/// outcome, so a caller cannot tell them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectOwner {
    Owned(IdentityId),
    Unknown,
}

/// The object facts one operation supplies.
///
/// The session owns the connection, the principal, the authentication epoch, the
/// negotiated contract, and the state directory for its whole life, so this value names
/// only what varies per operation: the capability requested, the payload shape, the owner
/// the object lookup resolved, and the extension grant presented. A caller can therefore
/// neither widen a ceiling nor retarget a decision by constructing one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInput<'a> {
    requested: Capability,
    kind: PayloadKind,
    owner: ObjectOwner,
    grant: Option<&'a ExtensionGrant>,
}

impl<'a> SessionInput<'a> {
    pub fn new(
        requested: Capability,
        kind: PayloadKind,
        owner: ObjectOwner,
        grant: Option<&'a ExtensionGrant>,
    ) -> Self {
        Self {
            requested,
            kind,
            owner,
            grant,
        }
    }

    pub fn requested(&self) -> &Capability {
        &self.requested
    }
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
    pub fn owner(&self) -> ObjectOwner {
        self.owner
    }
    pub fn grant(&self) -> Option<&'a ExtensionGrant> {
        self.grant
    }
}

/// The closed set of daemon projections authorization filters before serialization.
///
/// Every shape a daemon discloses is named here, so none reaches a frame on a path that
/// skipped the decision: a response, a status summary, an event, an artifact, and one
/// bounded stream chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionClass {
    Response,
    Status,
    Event,
    Artifact,
    StreamChunk,
}

impl ProjectionClass {
    /// The wire shape this projection is carried in.
    pub const fn payload_kind(self) -> PayloadKind {
        match self {
            Self::Response | Self::Status | Self::Artifact => PayloadKind::Response,
            Self::Event => PayloadKind::Event,
            Self::StreamChunk => PayloadKind::StreamChunk,
        }
    }

    /// The declared bound for this projection's wire shape.
    pub const fn max_bytes(self) -> usize {
        self.payload_kind().max_bytes()
    }
}

/// One daemon projection offered for authorization before the session serializes it.
///
/// The payload is borrowed: nothing is copied or framed until the decision accepts it.
/// The wire shape is derived from the projection class, so the two cannot disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionProjection<'a> {
    class: ProjectionClass,
    operation: SessionInput<'a>,
    payload: &'a [u8],
}

impl<'a> SessionProjection<'a> {
    pub fn new(
        class: ProjectionClass,
        requested: Capability,
        owner: ObjectOwner,
        grant: Option<&'a ExtensionGrant>,
        payload: &'a [u8],
    ) -> Self {
        Self {
            class,
            operation: SessionInput::new(requested, class.payload_kind(), owner, grant),
            payload,
        }
    }

    pub fn class(&self) -> ProjectionClass {
        self.class
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    fn operation(&self) -> &SessionInput<'a> {
        &self.operation
    }
}

/// One payload that passed frame authentication and the authorization decision, together
/// with the capability it was authorized under.
///
/// Only a daemon session mints one, so the type cannot present unchecked plaintext to a
/// consumer. Its `Debug` projection reports the shape and the byte count, never the
/// payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedInput {
    connection: ConnectionId,
    principal: IdentityId,
    epoch: u64,
    granted: Capability,
    owner: ObjectOwner,
    kind: PayloadKind,
    /// The authenticated v1 plaintext: one shape byte, then the payload.
    body: Vec<u8>,
}

impl AuthorizedInput {
    /// The authorized payload, borrowed. The session owns the only copy.
    pub fn payload(&self) -> &[u8] {
        // The session matched the leading shape byte before minting this value.
        &self.body[1..]
    }

    pub fn connection(&self) -> ConnectionId {
        self.connection
    }
    pub fn principal(&self) -> IdentityId {
        self.principal
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn granted(&self) -> &Capability {
        &self.granted
    }
    pub fn owner(&self) -> ObjectOwner {
        self.owner
    }
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
}

impl fmt::Debug for AuthorizedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedInput")
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload().len())
            .finish_non_exhaustive()
    }
}

/// One payload a daemon already authorized and filtered, as a client session received it.
///
/// A client is not the policy decision point: it holds no principal and authorizes
/// nothing, so this value names no capability. Its `Debug` projection reports the shape and
/// the byte count, never the payload.
#[derive(Clone, Eq, PartialEq)]
pub struct FilteredPayload {
    kind: PayloadKind,
    /// The authenticated v1 plaintext: one shape byte, then the payload.
    body: Vec<u8>,
}

impl FilteredPayload {
    pub fn payload(&self) -> &[u8] {
        // The session matched the leading shape byte before minting this value.
        &self.body[1..]
    }

    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
}

impl fmt::Debug for FilteredPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilteredPayload")
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload().len())
            .finish_non_exhaustive()
    }
}

/// One request payload a client session hands to the session for sealing.
///
/// A client asks; it does not disclose, so nothing here is authorized. The session chooses
/// every framing value itself, so this value names only the shape and the bytes. Its
/// `Debug` projection reports the shape and the byte count, never the payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedOutput {
    kind: PayloadKind,
    payload: Vec<u8>,
}

impl AuthorizedOutput {
    /// Accept a request payload, rejecting anything past the declared bound before the
    /// session allocates a frame for it.
    pub fn filtered(kind: PayloadKind, payload: Vec<u8>) -> Result<Self, SecurityFailure> {
        if payload.len() > kind.max_bytes() {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        Ok(Self { kind, payload })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
}

impl fmt::Debug for AuthorizedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedOutput")
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// The peer a session authenticated.
///
/// The arm is fixed when the handshake completes: a daemon session holds the principal it
/// authenticated for life and a client session never holds one. There is no unbound state
/// and no rebinding call, so a session cannot acquire, swap, or clear an authorization
/// identity after establishment.
enum SessionPeer {
    Principal(authorization::AuthorizationContext),
    Daemon {
        daemon: IdentityId,
        principal: IdentityId,
    },
}

impl fmt::Debug for SessionPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Principal(context) => formatter
                .debug_struct("Principal")
                .field("principal", &context.principal().id())
                .field("kind", &context.principal().kind())
                .finish_non_exhaustive(),
            Self::Daemon { daemon, principal } => formatter
                .debug_struct("Daemon")
                .field("daemon", daemon)
                .field("principal", principal)
                .finish_non_exhaustive(),
        }
    }
}

/// Stateful payload boundary created only by a mutually authenticated handshake.
/// Raw transcript construction, traffic keys, framing values, and counters remain private.
///
/// Public methods are client-side only. A completed daemon session is
/// coordinator-owned state used for server operations and must move into
/// [`SecurityTransitions`] before it can receive, disclose, or commit protected
/// work; rotation and revocation invalidate those operations under the same lock.
#[derive(Debug)]
pub struct ChannelSession {
    connection: ConnectionId,
    epoch: u64,
    contract: u16,
    endpoint: String,
    open: bool,
    peer: SessionPeer,
    channel: channel::ChannelState,
}

impl ChannelSession {
    pub(crate) fn client(
        connection: ConnectionId,
        principal: IdentityId,
        daemon: IdentityId,
        epoch: u64,
        contract: u16,
        endpoint: String,
        keys: channel::TrafficKeys,
    ) -> Result<Self, SecurityFailure> {
        Ok(Self {
            connection,
            epoch,
            contract,
            endpoint,
            open: true,
            peer: SessionPeer::Daemon { daemon, principal },
            channel: channel::ChannelState::new(channel::Role::Client, keys)?,
        })
    }

    pub(crate) fn daemon(
        connection: ConnectionId,
        context: authorization::AuthorizationContext,
        endpoint: String,
        keys: channel::TrafficKeys,
    ) -> Result<Self, SecurityFailure> {
        Ok(Self {
            connection,
            epoch: context.epoch(),
            contract: context.contract(),
            endpoint,
            open: true,
            peer: SessionPeer::Principal(context),
            channel: channel::ChannelState::new(channel::Role::Daemon, keys)?,
        })
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn close(&mut self) {
        self.open = false;
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.connection
    }

    /// The principal this channel authenticated: on a daemon session the registered
    /// principal it authorized against, on a client session the identity it presented.
    pub fn principal(&self) -> IdentityId {
        match &self.peer {
            SessionPeer::Principal(context) => context.principal().id(),
            SessionPeer::Daemon { principal, .. } => *principal,
        }
    }

    /// The whole authenticated principal snapshot a daemon session captured, exactly as
    /// the registry held it when the handshake bound the traffic keys.
    ///
    /// A client session authenticates no principal of its own, so it has none: it can
    /// never be bound to a registered snapshot and never becomes a live daemon channel.
    pub(crate) fn authenticated_principal_snapshot(&self) -> Option<&Principal> {
        match &self.peer {
            SessionPeer::Principal(context) => Some(context.principal()),
            SessionPeer::Daemon { .. } => None,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn contract(&self) -> u16 {
        self.contract
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The authorization facts of a daemon session. A client session holds no principal, so
    /// every authorizing path fails closed here rather than proceeding unauthorized.
    fn authorization(&self) -> Result<&authorization::AuthorizationContext, SecurityFailure> {
        match &self.peer {
            SessionPeer::Principal(context) => Ok(context),
            SessionPeer::Daemon { .. } => {
                Err(SecurityFailure::new(FailureCode::AuthorizationDenied))
            }
        }
    }

    /// A daemon must authorize what it accepts and what it discloses, so it cannot take an
    /// unauthorized path. Only a client session may.
    fn unauthorized_path(&self) -> Result<(), SecurityFailure> {
        match &self.peer {
            SessionPeer::Daemon { .. } => Ok(()),
            SessionPeer::Principal(_) => {
                Err(SecurityFailure::new(FailureCode::AuthorizationDenied))
            }
        }
    }

    /// Daemon side. Authenticate one frame, authorize the operation it names against the
    /// principal this channel established with, and only then mint typed plaintext.
    ///
    /// The order is fixed: frame, counter, and AEAD first, then the typed shape, then the
    /// required decision event, and only after that the receive counter and the typed
    /// value. A malformed shape and an unavailable decision sink both leave the counter
    /// where it was. A decision that denies the operation consumes the frame and leaves the
    /// channel usable, because a denial is an answer and not a protocol fault.
    pub(crate) fn receive(
        &mut self,
        frame: &[u8],
        operation: &SessionInput<'_>,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<AuthorizedInput, SecurityFailure> {
        if !self.open {
            let failure = SecurityFailure::new(FailureCode::AuthenticationFailed);
            return Err(self.fail(sink, failure));
        }
        if let Err(failure) = self.authorization() {
            return Err(self.fail(sink, failure));
        }
        let (plaintext, counter) =
            match self
                .channel
                .open(frame, self.connection, self.epoch, self.contract)
            {
                Ok(opened) => opened,
                Err(failure) => return Err(self.fail(sink, failure)),
            };
        let payload_bytes = match typed_payload_bytes(&plaintext, operation.kind()) {
            Ok(bytes) => bytes,
            Err(failure) => return Err(self.fail(sink, failure)),
        };
        if let Err(failure) = self.decide(operation, payload_bytes, sink) {
            if failure.code() == FailureCode::EventSinkUnavailable {
                self.close();
                return Err(failure);
            }
            self.channel.commit_receive(counter);
            return Err(failure);
        }
        let input = AuthorizedInput {
            connection: self.connection,
            principal: self.principal(),
            epoch: self.epoch,
            granted: operation.requested().clone(),
            owner: operation.owner(),
            kind: operation.kind(),
            body: plaintext,
        };
        self.channel.commit_receive(counter);
        Ok(input)
    }

    /// Daemon side. Authorize one projection and only then serialize it.
    ///
    /// This is the only path a response, status summary, event, artifact, or bounded stream
    /// chunk reaches a frame through, so no object identifier or payload byte is serialized
    /// before the decision accepts it. A denial serializes nothing and leaves the channel
    /// usable; an unavailable decision sink closes it.
    pub(crate) fn send_projection(
        &mut self,
        projection: &SessionProjection<'_>,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<Vec<u8>, SecurityFailure> {
        if !self.open {
            let failure = SecurityFailure::new(FailureCode::AuthenticationFailed);
            return Err(self.fail(sink, failure));
        }
        if let Err(failure) = self.authorization() {
            return Err(self.fail(sink, failure));
        }
        if let Err(failure) = self.decide(projection.operation(), projection.payload().len(), sink)
        {
            if failure.code() == FailureCode::EventSinkUnavailable {
                self.close();
            }
            return Err(failure);
        }
        match self.channel.seal(
            self.connection,
            self.epoch,
            self.contract,
            projection.class().payload_kind(),
            projection.payload(),
        ) {
            Ok(frame) => Ok(frame),
            Err(failure) => Err(self.fail(sink, failure)),
        }
    }

    /// Client side. Seal one request payload. Callers cannot choose headers, nonces, or
    /// counters. A daemon session cannot use this path: it must authorize what it sends.
    pub fn send(
        &mut self,
        output: &AuthorizedOutput,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<Vec<u8>, SecurityFailure> {
        if !self.open {
            let failure = SecurityFailure::new(FailureCode::AuthenticationFailed);
            return Err(self.fail(sink, failure));
        }
        if let Err(failure) = self.unauthorized_path() {
            return Err(self.fail(sink, failure));
        }
        match self.channel.seal(
            self.connection,
            self.epoch,
            self.contract,
            output.kind(),
            output.payload(),
        ) {
            Ok(frame) => Ok(frame),
            Err(failure) => Err(self.fail(sink, failure)),
        }
    }

    /// Client side. Authenticate one frame the daemon already authorized and filtered. A
    /// daemon session cannot use this path: it must authorize what it accepts.
    pub fn receive_filtered(
        &mut self,
        frame: &[u8],
        kind: PayloadKind,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<FilteredPayload, SecurityFailure> {
        if !self.open {
            let failure = SecurityFailure::new(FailureCode::AuthenticationFailed);
            return Err(self.fail(sink, failure));
        }
        if let Err(failure) = self.unauthorized_path() {
            return Err(self.fail(sink, failure));
        }
        let (plaintext, counter) =
            match self
                .channel
                .open(frame, self.connection, self.epoch, self.contract)
            {
                Ok(opened) => opened,
                Err(failure) => return Err(self.fail(sink, failure)),
            };
        if let Err(failure) = typed_payload_bytes(&plaintext, kind) {
            return Err(self.fail(sink, failure));
        }
        self.channel.commit_receive(counter);
        Ok(FilteredPayload {
            kind,
            body: plaintext,
        })
    }

    /// Run the authorization decision for one operation on this daemon session.
    fn decide(
        &self,
        operation: &SessionInput<'_>,
        payload_bytes: usize,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<(), SecurityFailure> {
        let context = self.authorization()?;
        authorization::authorize(
            authorization::AuthorizationRequest::new(
                context,
                self.connection,
                operation,
                EventTime(self.epoch),
            ),
            payload_bytes,
            Some(sink),
        )
    }

    fn fail(
        &mut self,
        sink: &mut dyn SecurityEventSink,
        failure: SecurityFailure,
    ) -> SecurityFailure {
        let projected = channel::emit_session_failure(
            sink,
            failure,
            self.principal(),
            self.connection,
            self.epoch,
        );
        self.close();
        projected
    }

    #[cfg(test)]
    pub(crate) fn set_counters(&mut self, send: u64, receive: u64) {
        self.channel.set_counters(send, receive);
    }

    #[cfg(test)]
    pub(crate) fn receive_counter(&self) -> u64 {
        self.channel.receive_counter()
    }

    /// Seal a payload past the declared per-shape bound, emulating a peer that does not
    /// honour the contract. Only the receiving session's bound check can reject it.
    #[cfg(test)]
    pub(crate) fn seal_unbounded(
        &mut self,
        kind: PayloadKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, SecurityFailure> {
        self.channel
            .seal(self.connection, self.epoch, self.contract, kind, payload)
    }

    #[cfg(test)]
    pub(crate) fn send_counter(&self) -> u64 {
        self.channel.send_counter()
    }
}

/// Validate the one shape byte v1 plaintext carries and report the payload length behind
/// it. A shape the operation did not declare, or a payload past its declared bound, is a
/// malformed frame rather than a policy decision, so it never reaches the decision gate.
fn typed_payload_bytes(plaintext: &[u8], expected: PayloadKind) -> Result<usize, SecurityFailure> {
    let (&code, payload) = plaintext
        .split_first()
        .ok_or(SecurityFailure::new(FailureCode::MalformedInput))?;
    if PayloadKind::from_wire(code)? != expected {
        return Err(SecurityFailure::new(FailureCode::MalformedInput));
    }
    if payload.len() > expected.max_bytes() {
        return Err(SecurityFailure::new(FailureCode::ResourceLimit));
    }
    Ok(payload.len())
}

/// The closed set of lifecycle changes the security boundary applies.
///
/// A command names identities, transitions, and idempotency keys only: it carries no
/// lifecycle field, no epoch field, and no secret, so a caller can neither mutate a
/// lifecycle directly nor advance an epoch by constructing a command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityCommand {
    /// Establish the first daemon identity for one state directory.
    Bootstrap {
        state_directory: IdentityId,
        idempotency: IdempotencyKey,
    },
    /// Open one bounded, one-time enrollment for an extension principal.
    CreateEnrollment {
        enrollment: TransitionId,
        daemon: IdentityId,
        idempotency: IdempotencyKey,
    },
    /// Consume that enrollment exactly once.
    ConsumeEnrollment {
        enrollment: TransitionId,
        idempotency: IdempotencyKey,
    },
    /// Rotate a principal onto a new key, named by its fingerprint.
    Rotate {
        principal: IdentityId,
        new_fingerprint: Fingerprint,
        idempotency: IdempotencyKey,
    },
    /// Revoke a principal terminally.
    Revoke {
        principal: IdentityId,
        idempotency: IdempotencyKey,
    },
}

impl SecurityCommand {
    /// The transition operation this command records. The mapping is exhaustive: a
    /// new command variant fails to compile until it names its operation.
    pub(crate) fn operation(&self) -> TransitionOperation {
        match self {
            Self::Bootstrap { .. } => TransitionOperation::Bootstrap,
            Self::CreateEnrollment { .. } => TransitionOperation::EnrollmentCreate,
            Self::ConsumeEnrollment { .. } => TransitionOperation::EnrollmentConsume,
            Self::Rotate { .. } => TransitionOperation::Rotation,
            Self::Revoke { .. } => TransitionOperation::Revocation,
        }
    }

    /// The key that makes a retry of this command the same command.
    pub(crate) fn idempotency(&self) -> IdempotencyKey {
        match self {
            Self::Bootstrap { idempotency, .. }
            | Self::CreateEnrollment { idempotency, .. }
            | Self::ConsumeEnrollment { idempotency, .. }
            | Self::Rotate { idempotency, .. }
            | Self::Revoke { idempotency, .. } => *idempotency,
        }
    }
}

#[cfg(test)]
mod foundation_contract {
    include!("../tests/foundation_contract.rs");
    foundation_contract_tests!();
}
#[cfg(test)]
mod events_contract {
    include!("../tests/events_contract.rs");
    events_contract_tests!();
}
#[cfg(test)]
mod bootstrap_contract {
    include!("../tests/bootstrap_contract.rs");
    bootstrap_contract_tests!();
}
#[cfg(test)]
mod bootstrap_recovery_contract {
    include!("../tests/bootstrap_recovery.rs");
    bootstrap_recovery_tests!();
}
#[cfg(test)]
mod enrollment_contract {
    include!("../tests/enrollment_contract.rs");
    enrollment_contract_tests!();
    mod failures {
        include!("../tests/enrollment_failures.rs");
        enrollment_failure_tests!();
    }
    mod custody {
        include!("../tests/enrollment_custody.rs");
        enrollment_custody_tests!();
    }
}
#[cfg(test)]
mod malformed_corpus_contract {
    include!("../tests/malformed_corpus.rs");
    malformed_corpus_tests!();
}
#[cfg(test)]
mod secure_channel_handshake_contract {
    include!("../tests/secure_channel_handshake.rs");
    secure_channel_handshake_tests!();
}
#[cfg(test)]
mod secure_channel_frames_contract {
    include!("../tests/secure_channel_frames.rs");
    secure_channel_frames_tests!();
}
#[cfg(test)]
mod secure_channel_faults_contract {
    include!("../tests/secure_channel_faults.rs");
    secure_channel_faults_tests!();
}
#[cfg(test)]
mod authorization_contract {
    include!("../tests/authorization_contract.rs");
    authorization_contract_tests!();
}
#[cfg(test)]
mod authorization_privacy {
    include!("../tests/authorization_privacy.rs");
    authorization_privacy_tests!();
}
#[cfg(test)]
mod rotation_revocation_contract {
    include!("../tests/rotation_revocation.rs");
    rotation_revocation_tests!();
}
#[cfg(test)]
mod rotation_revocation_races_contract {
    include!("../tests/rotation_revocation_races.rs");
    rotation_revocation_races_tests!();
}
#[cfg(test)]
mod quickstart_evidence {
    include!("../tests/quickstart_evidence.rs");
    quickstart_evidence_tests!();
}
#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    use crate::test_support_channel::{
        RecordingSink, establish_pair, owned_operation, owned_projection,
    };

    fn key(value: u128) -> IdempotencyKey {
        IdempotencyKey::new(Uuid::from_u128(value))
    }

    fn commands() -> [SecurityCommand; 5] {
        let identity = IdentityId::new(Uuid::from_u128(1));
        let transition = TransitionId::new(Uuid::from_u128(2));
        [
            SecurityCommand::Bootstrap {
                state_directory: identity,
                idempotency: key(10),
            },
            SecurityCommand::CreateEnrollment {
                enrollment: transition,
                daemon: identity,
                idempotency: key(11),
            },
            SecurityCommand::ConsumeEnrollment {
                enrollment: transition,
                idempotency: key(12),
            },
            SecurityCommand::Rotate {
                principal: identity,
                new_fingerprint: Fingerprint::new("d".repeat(64)).expect("64 lowercase hex digits"),
                idempotency: key(13),
            },
            SecurityCommand::Revoke {
                principal: identity,
                idempotency: key(14),
            },
        ]
    }

    #[test]
    fn payload_bounds_follow_the_declared_shape() {
        assert_eq!(PayloadKind::Command.max_bytes(), MAX_PAYLOAD_BYTES);
        assert_eq!(PayloadKind::Response.max_bytes(), MAX_PAYLOAD_BYTES);
        assert_eq!(PayloadKind::Event.max_bytes(), MAX_PAYLOAD_BYTES);
        assert_eq!(PayloadKind::StreamChunk.max_bytes(), MAX_CHUNK_BYTES);
        for class in [
            ProjectionClass::Response,
            ProjectionClass::Status,
            ProjectionClass::Artifact,
        ] {
            assert_eq!(class.payload_kind(), PayloadKind::Response);
            assert_eq!(class.max_bytes(), MAX_PAYLOAD_BYTES);
        }
        assert_eq!(ProjectionClass::Event.payload_kind(), PayloadKind::Event);
        assert_eq!(
            ProjectionClass::StreamChunk.payload_kind(),
            PayloadKind::StreamChunk
        );
        assert_eq!(ProjectionClass::StreamChunk.max_bytes(), MAX_CHUNK_BYTES);

        let (_, mut daemon) = establish_pair(0);
        let mut sink = RecordingSink::default();
        let oversize = vec![0u8; MAX_CHUNK_BYTES + 1];
        assert_eq!(
            daemon
                .send_projection(
                    &owned_projection(ProjectionClass::StreamChunk, &oversize),
                    &mut sink
                )
                .expect_err("oversize chunk")
                .code(),
            FailureCode::ResourceLimit
        );
        assert_eq!(
            AuthorizedOutput::filtered(PayloadKind::StreamChunk, oversize)
                .expect_err("oversize chunk")
                .code(),
            FailureCode::ResourceLimit
        );
    }

    #[test]
    fn authorized_values_never_format_their_payload() {
        let (mut client, mut daemon) = establish_pair(0);
        let mut sink = RecordingSink::default();
        let output = AuthorizedOutput::filtered(PayloadKind::Event, b"secret-plaintext".to_vec())
            .expect("bounded payload");
        let frame = client.send(&output, &mut sink).expect("sealed request");
        let input = daemon
            .receive(&frame, &owned_operation(PayloadKind::Event), &mut sink)
            .expect("authorized request");
        let response = daemon
            .send_projection(
                &owned_projection(ProjectionClass::Event, b"secret-plaintext"),
                &mut sink,
            )
            .expect("authorized projection");
        let filtered = client
            .receive_filtered(&response, PayloadKind::Event, &mut sink)
            .expect("filtered projection");
        for rendered in [
            format!("{input:?}"),
            format!("{output:?}"),
            format!("{filtered:?}"),
        ] {
            assert!(!rendered.contains("secret-plaintext"));
            assert!(rendered.contains("payload_bytes: 16"));
        }
        assert_eq!(input.payload(), b"secret-plaintext");
        assert_eq!(output.payload(), b"secret-plaintext");
        assert_eq!(filtered.payload(), b"secret-plaintext");
        assert_eq!(input.granted().resource_scope(), "matinee/status");
        assert_eq!(input.kind(), PayloadKind::Event);
        assert_eq!(filtered.kind(), PayloadKind::Event);
    }

    #[test]
    fn a_session_debug_projection_names_its_peer_without_its_principal_record() {
        let (client, daemon) = establish_pair(0);
        let rendered = format!("{daemon:?}");
        assert!(rendered.contains("Principal"));
        assert!(rendered.contains("McpClient"));
        assert!(!rendered.contains("ceiling"));
        assert!(!rendered.contains("fingerprint"));
        assert!(!rendered.contains("credential"));
        assert!(format!("{client:?}").contains("Daemon"));
    }

    #[test]
    fn session_reports_its_negotiated_binding() {
        let (session, _) = crate::test_support_channel::establish_pair(3);
        assert_eq!(session.contract(), 3);
        assert_eq!(session.endpoint(), "127.0.0.1:7777");
        assert_eq!(session.epoch(), 3);
        assert!(session.is_open());
    }

    #[test]
    fn every_command_names_its_transition_operation() {
        let expected = [
            TransitionOperation::Bootstrap,
            TransitionOperation::EnrollmentCreate,
            TransitionOperation::EnrollmentConsume,
            TransitionOperation::Rotation,
            TransitionOperation::Revocation,
        ];
        for (command, operation) in commands().iter().zip(expected) {
            assert_eq!(command.operation(), operation);
        }
    }

    #[test]
    fn each_command_carries_its_own_idempotency_key() {
        let commands = commands();
        for (index, command) in commands.iter().enumerate() {
            assert_eq!(command.idempotency(), key(10 + index as u128));
            assert!(
                commands[..index]
                    .iter()
                    .all(|prior| prior.idempotency() != command.idempotency())
            );
        }
    }
}
