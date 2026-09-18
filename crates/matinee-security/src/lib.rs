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
    ChannelSigner, ChannelSigningError, ClientHandshake, ClientHandshakeConfig,
    SECURE_CHANNEL_CONTEXT, ServerHandshake, ServerHandshakeConfig,
};
pub use crate::events::{
    EndpointClass, EventBoundary, EventOutcome, MetadataEntry, SafeNextAction as EventNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink, SecurityEventSinkResult,
};
pub use crate::failures::{FailureBoundary, FailureCode, SafeNextAction, SecurityFailure};

#[cfg(test)]
#[path = "../tests/support/channel.rs"]
mod test_support_channel;
#[cfg(test)]
#[path = "../tests/support/fakes.rs"]
mod test_support_fakes;

use core::fmt;

use crate::identity::{IdempotencyKey, TransitionOperation};

/// The enrollment lifecycle a host process drives: create a bounded one-time
/// enrollment, seal its one-time key to one authenticated channel, consume the
/// pairing proof once, then reconnect, update custody, or revoke the registered
/// principal. Transcript assembly, budgets, quarantine, and event emission stay
/// behind this boundary.
pub use crate::enrollment::{
    enrollment_proof_message, ChromeCapability, ChromeReconnectOutcome,
    DevelopmentIdentityAllowance, EncryptedKeyOutput, EnrollmentBinding, EnrollmentBundle,
    EnrollmentChannel, EnrollmentClock, EnrollmentConsumeError, EnrollmentConsumptionService,
    EnrollmentCreateError, EnrollmentCreation, EnrollmentCustodyError, EnrollmentProof,
};
pub use crate::identity::{
    Capability, CapabilityAction, ConnectionId, ExpiryResult, Fingerprint, IdentityId, PublicKey,
    TransitionId, UNCOMPRESSED_KEY_BYTES,
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
    pub fn new(
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

    pub fn connection(&self) -> ConnectionId {
        self.connection
    }
    pub fn principal(&self) -> IdentityId {
        self.principal
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn requested(&self) -> &Capability {
        &self.requested
    }
    pub fn kind(&self) -> PayloadKind {
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
    payload_offset: u8,
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
            payload_offset: 0,
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

    pub(crate) fn from_wire(
        context: &SessionInput,
        plaintext: Vec<u8>,
    ) -> Result<Self, SecurityFailure> {
        let (&code, payload) = plaintext
            .split_first()
            .ok_or(SecurityFailure::new(FailureCode::MalformedInput))?;
        if PayloadKind::from_wire(code)? != context.kind() {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        if payload.len() > context.kind().max_bytes() {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        Ok(Self {
            connection: context.connection(),
            principal: context.principal(),
            epoch: context.epoch(),
            granted: context.requested().clone(),
            kind: context.kind(),
            payload: plaintext,
            payload_offset: 1,
        })
    }

    /// The authorized payload, borrowed. The session owns the only copy.
    pub fn payload(&self) -> &[u8] {
        &self.payload[self.payload_offset as usize..]
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

/// Stateful payload boundary created only by a mutually authenticated handshake.
/// Raw transcript construction, traffic keys, framing values, and counters remain private.
#[derive(Debug)]
pub struct ChannelSession {
    connection: ConnectionId,
    principal: IdentityId,
    epoch: u64,
    contract: u16,
    endpoint: String,
    open: bool,
    channel: channel::ChannelState,
}

impl ChannelSession {
    pub(crate) fn new(
        connection: ConnectionId,
        principal: IdentityId,
        epoch: u64,
        contract: u16,
        endpoint: String,
        role: channel::Role,
        keys: channel::TrafficKeys,
    ) -> Result<Self, SecurityFailure> {
        Ok(Self {
            connection,
            principal,
            epoch,
            contract,
            endpoint,
            open: true,
            channel: channel::ChannelState::new(role, keys)?,
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

    pub fn principal(&self) -> IdentityId {
        self.principal
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

    fn binds(&self, context: &SessionInput) -> Result<(), SecurityFailure> {
        if !self.open {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        if context.connection() != self.connection || context.principal() != self.principal {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        if context.epoch() != self.epoch {
            return Err(SecurityFailure::new(FailureCode::StaleEpoch));
        }
        Ok(())
    }

    /// Seal an already-filtered payload. Callers cannot choose headers, nonces, or counters.
    pub fn send(
        &mut self,
        output: &AuthorizedOutput,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<Vec<u8>, SecurityFailure> {
        if !self.open {
            let failure = SecurityFailure::new(FailureCode::AuthenticationFailed);
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

    /// Authenticate and decrypt one exact v1 frame before returning typed plaintext.
    pub fn receive(
        &mut self,
        frame: &[u8],
        context: &SessionInput,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<AuthorizedInput, SecurityFailure> {
        if let Err(failure) = self.binds(context) {
            return Err(self.fail(sink, failure));
        }
        let (payload, counter) =
            match self
                .channel
                .open(frame, self.connection, self.epoch, self.contract)
            {
                Ok(opened) => opened,
                Err(failure) => return Err(self.fail(sink, failure)),
            };
        match AuthorizedInput::from_wire(context, payload) {
            Ok(input) => {
                self.channel.commit_receive(counter);
                Ok(input)
            }
            Err(failure) => Err(self.fail(sink, failure)),
        }
    }

    fn fail(
        &mut self,
        sink: &mut dyn SecurityEventSink,
        failure: SecurityFailure,
    ) -> SecurityFailure {
        let projected = channel::emit_session_failure(
            sink,
            failure,
            self.principal,
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
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::identity::CapabilityAction;

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
            assert!(commands[..index]
                .iter()
                .all(|prior| prior.idempotency() != command.idempotency()));
        }
    }
}
