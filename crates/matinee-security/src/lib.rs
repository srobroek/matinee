//! Private security implementation with a deliberately narrow crate boundary.
//!
//! Protocol framing, transcript handling, cryptographic operations, authorization
//! policy, origin validation, adapter access, and transition state remain behind
//! private modules. Consumers interact only through the typed session boundary and
//! the closed lifecycle command interface defined here.

// Foundational modules. Every declaration resolves to real content: a module is
// declared once it carries its own definitions, so channel framing, authorization
// policy, enrollment, and transition application are declared with the work that
// defines them.
mod adapters;
mod authorization;
mod enrollment;
mod events;
mod failures;
mod identity;

#[cfg(test)]
#[path = "../tests/support/fakes.rs"]
mod test_support_fakes;

use core::fmt;

use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{
    Capability, Connection, ConnectionId, ConnectionLifecycle, Fingerprint, IdempotencyKey,
    IdentityId, TransitionId, TransitionOperation,
};

/// v1 carries no secure-channel fragmentation, so one payload occupies one frame:
/// 1 MiB minus the 25-byte header and the 16-byte tag.
const MAX_PAYLOAD_BYTES: usize = 1_048_535;
/// A bounded artifact chunk carries at most this many content bytes.
const MAX_CHUNK_BYTES: usize = 1_000_000;
/// The endpoint binding is a bounded loopback locator, never a free-form label.
const MAX_ENDPOINT_BYTES: usize = 256;

/// The closed set of payload shapes the session carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PayloadKind {
    Command,
    Response,
    Event,
    StreamChunk,
}

impl PayloadKind {
    /// The declared bound for this shape. A chunk is bounded below the frame maximum
    /// so one stream chunk cannot consume the whole frame budget.
    pub(crate) const fn max_bytes(self) -> usize {
        match self {
            Self::Command | Self::Response | Self::Event => MAX_PAYLOAD_BYTES,
            Self::StreamChunk => MAX_CHUNK_BYTES,
        }
    }
}

/// The typed context a caller supplies with one received frame.
///
/// It names the connection, the principal, the epoch the caller believes is current,
/// and the capability the caller requests. It carries no frame bytes, no plaintext,
/// and no key material, so a caller cannot smuggle either past the session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInput {
    connection: ConnectionId,
    principal: IdentityId,
    epoch: u64,
    requested: Capability,
    kind: PayloadKind,
}

impl SessionInput {
    pub(crate) fn new(
        connection: ConnectionId,
        principal: IdentityId,
        epoch: u64,
        requested: Capability,
        kind: PayloadKind,
    ) -> Self {
        Self {
            connection,
            principal,
            epoch,
            requested,
            kind,
        }
    }

    pub(crate) fn connection(&self) -> ConnectionId {
        self.connection
    }
    pub(crate) fn principal(&self) -> IdentityId {
        self.principal
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn requested(&self) -> &Capability {
        &self.requested
    }
    pub(crate) fn kind(&self) -> PayloadKind {
        self.kind
    }
}

/// One payload that passed every session check, together with the capability it was
/// authorized under.
///
/// Only this crate mints one, so the type cannot be used to present unchecked
/// plaintext to a consumer. Its `Debug` projection reports the shape and the byte
/// count, never the payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedInput {
    connection: ConnectionId,
    principal: IdentityId,
    epoch: u64,
    granted: Capability,
    kind: PayloadKind,
    payload: Vec<u8>,
}

impl AuthorizedInput {
    /// Mint an authorized input after the caller has checked the payload bound.
    pub(crate) fn from_prevalidated(context: &SessionInput, payload: Vec<u8>) -> Self {
        debug_assert!(payload.len() <= context.kind().max_bytes());
        Self {
            connection: context.connection(),
            principal: context.principal(),
            epoch: context.epoch(),
            granted: context.requested().clone(),
            kind: context.kind(),
            payload,
        }
    }

    /// Mint an authorized input for a context whose checks have already run.
    pub(crate) fn authorized(
        context: &SessionInput,
        payload: Vec<u8>,
    ) -> Result<Self, SecurityFailure> {
        if payload.len() > context.kind().max_bytes() {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        Ok(Self::from_prevalidated(context, payload))
    }

    /// The authorized payload, borrowed. The session owns the only copy.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn connection(&self) -> ConnectionId {
        self.connection
    }
    pub(crate) fn principal(&self) -> IdentityId {
        self.principal
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn granted(&self) -> &Capability {
        &self.granted
    }
    pub(crate) fn kind(&self) -> PayloadKind {
        self.kind
    }
}

impl fmt::Debug for AuthorizedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedInput")
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// One already filtered payload a caller hands to the session for sealing.
///
/// The session chooses every framing value itself, so this value names only the
/// shape and the bytes. Its `Debug` projection reports the shape and the byte count,
/// never the payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedOutput {
    kind: PayloadKind,
    payload: Vec<u8>,
}

impl AuthorizedOutput {
    /// Accept a filtered payload, rejecting anything past the declared bound before
    /// the session allocates a frame for it.
    pub(crate) fn filtered(kind: PayloadKind, payload: Vec<u8>) -> Result<Self, SecurityFailure> {
        if payload.len() > kind.max_bytes() {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        Ok(Self { kind, payload })
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub(crate) fn kind(&self) -> PayloadKind {
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

/// The stateful boundary over one authenticated connection.
///
/// The session owns the connection, its directional counters, the negotiated
/// contract, and the transcript-bound endpoint. A caller can observe only whether
/// the session is open and can close it; every counter, key handle, and nonce stays
/// inside this crate, and raw framing, plaintext, transcript assembly, and
/// authorization policy are never reachable from outside it.
#[derive(Debug)]
pub struct ChannelSession {
    connection: Connection,
    contract: u16,
    endpoint: String,
}

impl ChannelSession {
    /// Establish a session over a connection whose handshake already completed.
    ///
    /// A connection that is not authenticated, a contract outside the negotiated
    /// range, or an endpoint outside its bound fails closed with a bounded failure.
    pub(crate) fn establish(
        connection: Connection,
        contract: u16,
        endpoint: impl Into<String>,
    ) -> Result<Self, SecurityFailure> {
        if connection.lifecycle() != ConnectionLifecycle::Authenticated {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        if contract == 0 {
            return Err(SecurityFailure::new(FailureCode::CompatibilityUnsupported));
        }
        let endpoint = endpoint.into();
        if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err(SecurityFailure::new(FailureCode::EndpointRejected));
        }
        Ok(Self {
            connection,
            contract,
            endpoint,
        })
    }

    /// Whether the session still carries payloads.
    pub fn is_open(&self) -> bool {
        self.connection.lifecycle() == ConnectionLifecycle::Authenticated
    }

    /// Close the session. A closed session accepts no later payload.
    pub fn close(&mut self) {
        self.connection.close();
    }

    pub(crate) fn connection_id(&self) -> ConnectionId {
        self.connection.id()
    }
    pub(crate) fn principal(&self) -> IdentityId {
        self.connection.principal()
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.connection.epoch()
    }
    pub(crate) fn contract(&self) -> u16 {
        self.contract
    }
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Check that a caller's context belongs to this session at the current epoch.
    ///
    /// A closed session, another connection, a different principal, or a stale epoch
    /// each fails closed before any payload is considered.
    pub(crate) fn binds(&self, context: &SessionInput) -> Result<(), SecurityFailure> {
        if !self.is_open() {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        if context.connection() != self.connection_id() || context.principal() != self.principal() {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        if context.epoch() != self.epoch() {
            return Err(SecurityFailure::new(FailureCode::StaleEpoch));
        }
        Ok(())
    }

    /// The next counter for an outbound frame. Exhaustion refuses rather than wraps.
    pub(crate) fn next_send_counter(&mut self) -> Result<u64, SecurityFailure> {
        self.connection
            .next_send()
            .ok_or(SecurityFailure::new(FailureCode::CounterMismatch))
    }

    /// The next counter expected on an inbound frame.
    pub(crate) fn next_receive_counter(&mut self) -> Result<u64, SecurityFailure> {
        self.connection
            .next_receive()
            .ok_or(SecurityFailure::new(FailureCode::CounterMismatch))
    }
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
mod malformed_corpus_contract {
    include!("../tests/malformed_corpus.rs");
    malformed_corpus_tests!();
}
#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::identity::CapabilityAction;

    fn connection(epoch: u64) -> Connection {
        let mut connection = Connection::new(
            ConnectionId::new(Uuid::from_u128(1)),
            IdentityId::new(Uuid::from_u128(2)),
            1,
            epoch,
            [0u8; 12],
            [1u8; 12],
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        );
        connection.authenticate().expect("fresh connection");
        connection
    }

    fn session(epoch: u64) -> ChannelSession {
        ChannelSession::establish(connection(epoch), 1, "127.0.0.1:7777").expect("bound session")
    }

    fn context(epoch: u64, kind: PayloadKind) -> SessionInput {
        SessionInput::new(
            ConnectionId::new(Uuid::from_u128(1)),
            IdentityId::new(Uuid::from_u128(2)),
            epoch,
            Capability::new(CapabilityAction::Read, "matinee/status").expect("bounded scope"),
            kind,
        )
    }

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
    fn establishment_requires_an_authenticated_connection_and_a_bound_endpoint() {
        let handshaking = Connection::new(
            ConnectionId::new(Uuid::from_u128(1)),
            IdentityId::new(Uuid::from_u128(2)),
            1,
            0,
            [0u8; 12],
            [1u8; 12],
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        );
        assert_eq!(
            ChannelSession::establish(handshaking, 1, "127.0.0.1:7777")
                .expect_err("handshaking connection")
                .code(),
            FailureCode::AuthenticationFailed
        );
        assert_eq!(
            ChannelSession::establish(connection(0), 0, "127.0.0.1:7777")
                .expect_err("unnegotiated contract")
                .code(),
            FailureCode::CompatibilityUnsupported
        );
        assert_eq!(
            ChannelSession::establish(connection(0), 1, "")
                .expect_err("unbound endpoint")
                .code(),
            FailureCode::EndpointRejected
        );
        assert_eq!(
            ChannelSession::establish(connection(0), 1, "e".repeat(MAX_ENDPOINT_BYTES + 1))
                .expect_err("oversize endpoint")
                .code(),
            FailureCode::EndpointRejected
        );
    }

    #[test]
    fn binding_rejects_a_stale_epoch_a_foreign_context_and_a_closed_session() {
        let mut open = session(7);
        assert!(open.binds(&context(7, PayloadKind::Command)).is_ok());
        assert_eq!(
            open.binds(&context(6, PayloadKind::Command))
                .expect_err("stale epoch")
                .code(),
            FailureCode::StaleEpoch
        );

        let foreign = SessionInput::new(
            ConnectionId::new(Uuid::from_u128(99)),
            IdentityId::new(Uuid::from_u128(2)),
            7,
            Capability::new(CapabilityAction::Read, "matinee/status").expect("bounded scope"),
            PayloadKind::Command,
        );
        assert_eq!(
            open.binds(&foreign).expect_err("foreign connection").code(),
            FailureCode::MalformedInput
        );

        open.close();
        assert!(!open.is_open());
        assert_eq!(
            open.binds(&context(7, PayloadKind::Command))
                .expect_err("closed session")
                .code(),
            FailureCode::AuthenticationFailed
        );
    }

    #[test]
    fn counters_start_at_zero_per_direction_and_refuse_after_close() {
        let mut session = session(0);
        assert_eq!(session.next_send_counter().expect("first send"), 0);
        assert_eq!(session.next_send_counter().expect("second send"), 1);
        assert_eq!(session.next_receive_counter().expect("first receive"), 0);
        session.close();
        assert_eq!(
            session
                .next_send_counter()
                .expect_err("closed session")
                .code(),
            FailureCode::CounterMismatch
        );
    }

    #[test]
    fn payload_bounds_follow_the_declared_shape() {
        let command = context(0, PayloadKind::Command);
        assert_eq!(
            AuthorizedInput::authorized(&command, vec![0u8; MAX_PAYLOAD_BYTES])
                .expect("payload at the frame bound")
                .payload()
                .len(),
            MAX_PAYLOAD_BYTES
        );
        assert_eq!(
            AuthorizedInput::authorized(&command, vec![0u8; MAX_PAYLOAD_BYTES + 1])
                .expect_err("oversize payload")
                .code(),
            FailureCode::ResourceLimit
        );

        let chunk = context(0, PayloadKind::StreamChunk);
        assert!(AuthorizedInput::authorized(&chunk, vec![0u8; MAX_CHUNK_BYTES]).is_ok());
        assert_eq!(
            AuthorizedInput::authorized(&chunk, vec![0u8; MAX_CHUNK_BYTES + 1])
                .expect_err("oversize chunk")
                .code(),
            FailureCode::ResourceLimit
        );
        assert_eq!(
            AuthorizedOutput::filtered(PayloadKind::StreamChunk, vec![0u8; MAX_CHUNK_BYTES + 1])
                .expect_err("oversize chunk")
                .code(),
            FailureCode::ResourceLimit
        );
    }

    #[test]
    fn authorized_values_never_format_their_payload() {
        let context = context(0, PayloadKind::Event);
        let input = AuthorizedInput::authorized(&context, b"secret-plaintext".to_vec())
            .expect("bounded payload");
        let output = AuthorizedOutput::filtered(PayloadKind::Event, b"secret-plaintext".to_vec())
            .expect("bounded payload");
        for rendered in [format!("{input:?}"), format!("{output:?}")] {
            assert!(!rendered.contains("secret-plaintext"));
            assert!(rendered.contains("payload_bytes: 16"));
        }
        assert_eq!(input.payload(), b"secret-plaintext");
        assert_eq!(output.payload(), b"secret-plaintext");
        assert_eq!(input.granted().resource_scope(), "matinee/status");
        assert_eq!(input.kind(), PayloadKind::Event);
    }

    #[test]
    fn session_reports_its_negotiated_binding() {
        let session = session(3);
        assert_eq!(session.contract(), 1);
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
            assert!(commands[..index]
                .iter()
                .all(|prior| prior.idempotency() != command.idempotency()));
        }
    }
}
