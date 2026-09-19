//! Stateful authorization policy for the authenticated channel boundary.
//!
//! Every decision reads the principal snapshot the channel authenticated at
//! establishment, never a value the current operation supplied. An operation therefore
//! names object facts only: what it requests, which shape it carries, who owns the object
//! the daemon resolved, and which extension grant it presents. The principal, the
//! authentication epoch, the negotiated contract, and the state directory are not
//! expressible per operation, so no call can widen them.

use crate::events::{
    EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry,
    SafeNextAction as EventNextAction, SecurityCode, SecurityEvent, SecurityEventSink,
    emit_required,
};
use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{
    Capability, CapabilityAction, ConnectionId, GrantLifecycle, IdentityId, Principal,
    PrincipalKind, PrincipalLifecycle,
};
use crate::{ObjectOwner, SessionInput};

/// The authorization facts one mutually authenticated channel fixed at establishment.
///
/// A daemon session owns exactly one of these for its whole life. The authentication
/// epoch and the state directory are read off the principal snapshot rather than accepted
/// from a caller, so a channel cannot be bound to an epoch or a state directory the
/// principal does not carry.
#[derive(Clone, Debug)]
pub(crate) struct AuthorizationContext {
    principal: Principal,
    contract: u16,
    contract_min: u16,
    contract_max: u16,
    state_directory: IdentityId,
}

impl AuthorizationContext {
    pub(crate) fn new(
        principal: Principal,
        contract: u16,
        contract_min: u16,
        contract_max: u16,
    ) -> Self {
        let state_directory = principal.credential().state_directory();
        Self {
            principal,
            contract,
            contract_min,
            contract_max,
            state_directory,
        }
    }

    pub(crate) fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The authentication epoch this channel is bound to. It is the principal's epoch, so
    /// a session can never run at an epoch its principal did not hold.
    pub(crate) fn epoch(&self) -> u64 {
        self.principal.epoch()
    }

    pub(crate) fn contract(&self) -> u16 {
        self.contract
    }

    pub(crate) fn state_directory(&self) -> IdentityId {
        self.state_directory
    }
}

/// One authorization decision: the channel's fixed facts, the connection it runs on, and
/// the object facts this operation supplied.
pub(crate) struct AuthorizationRequest<'a> {
    context: &'a AuthorizationContext,
    connection: ConnectionId,
    operation: &'a SessionInput<'a>,
    event_time: EventTime,
}

impl<'a> AuthorizationRequest<'a> {
    pub(crate) fn new(
        context: &'a AuthorizationContext,
        connection: ConnectionId,
        operation: &'a SessionInput<'a>,
        event_time: EventTime,
    ) -> Self {
        Self {
            context,
            connection,
            operation,
            event_time,
        }
    }
}

/// Decide one operation and record the decision.
///
/// `payload_bytes` is the payload the operation would disclose or accept. The decision
/// event is required: it must be accepted before the caller mints a typed value, advances
/// a counter, or serializes a frame. An unavailable sink is therefore a failure, not a
/// silent allow.
pub(crate) fn authorize<S>(
    request: AuthorizationRequest<'_>,
    payload_bytes: usize,
    sink: Option<&mut S>,
) -> Result<(), SecurityFailure>
where
    S: SecurityEventSink + ?Sized,
{
    let context = request.context;
    let principal = context.principal();
    let operation = request.operation;
    let decision = if principal.lifecycle() != PrincipalLifecycle::Active {
        Err(FailureCode::AuthorizationDenied)
    } else if context.contract == 0
        || context.contract < context.contract_min
        || context.contract > context.contract_max
    {
        Err(FailureCode::CompatibilityUnsupported)
    } else if !principal_kind_allows_action(principal.kind(), operation.requested().action()) {
        Err(FailureCode::AuthorizationDenied)
    } else if operation.owner() != ObjectOwner::Owned(principal.owner()) {
        // An unknown object, a cross-owner object, and a filtered object are one outcome.
        Err(FailureCode::ObjectNotFound)
    } else if !ceiling_allows(principal, operation.requested())
        || !grant_allows(principal, operation)
    {
        Err(FailureCode::AuthorizationDenied)
    } else if payload_bytes > operation.kind().max_bytes() {
        Err(FailureCode::ResourceLimit)
    } else {
        Ok(())
    };
    if let Err(code) = decision {
        emit_decision(
            sink,
            request.event_time,
            context.state_directory(),
            principal,
            request.connection,
            SecurityCode::AuthorizationDenied,
            EventOutcome::Rejected,
            EventNextAction::FailClosed,
            reason(code),
        )?;
        return Err(SecurityFailure::with_safe_ids(
            code,
            Some(principal.id().get()),
            Some(request.connection.get()),
        ));
    }
    emit_decision(
        sink,
        request.event_time,
        context.state_directory(),
        principal,
        request.connection,
        SecurityCode::AuthorizationAccepted,
        EventOutcome::Accepted,
        EventNextAction::Continue,
        "accepted".to_owned(),
    )
}

/// The bounded reason class an event may carry. It names the failure class only: no object
/// identifier, count, title, origin, or payload byte reaches a decision event.
fn reason(code: FailureCode) -> String {
    code.as_str()
        .replace("authorization.", "")
        .replace('.', "-")
}

fn principal_kind_allows_action(kind: PrincipalKind, action: &CapabilityAction) -> bool {
    match action {
        CapabilityAction::ManagePrincipals
        | CapabilityAction::Rotate
        | CapabilityAction::Revoke
        | CapabilityAction::Administer => kind == PrincipalKind::NativeAdmin,
        CapabilityAction::Read | CapabilityAction::Write | CapabilityAction::Execute => true,
    }
}

fn ceiling_allows(principal: &Principal, requested: &Capability) -> bool {
    principal
        .ceiling()
        .iter()
        .any(|ceiling| capability_covers(ceiling, requested))
}

fn grant_allows(principal: &Principal, operation: &SessionInput<'_>) -> bool {
    let grant = operation.grant();
    if principal.kind() != PrincipalKind::BrowserExtension {
        return grant.is_none();
    }
    let Some(grant) = grant else { return false };
    grant.lifecycle() == GrantLifecycle::Active
        && grant.extension() == principal.id()
        && grant.owner() == principal.owner()
        && grant.epoch() == principal.epoch()
        && grant
            .capabilities()
            .iter()
            .all(|capability| ceiling_allows(principal, capability))
        && grant
            .capabilities()
            .iter()
            .any(|capability| capability_covers(capability, operation.requested()))
}

fn capability_covers(ceiling: &Capability, requested: &Capability) -> bool {
    if ceiling.action() != requested.action() {
        return false;
    }
    let scope = ceiling.resource_scope();
    let requested_scope = requested.resource_scope();
    scope == "global"
        || scope == requested_scope
        || requested_scope
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The class of endpoint one principal kind connects from. An event reports the class
/// only, never an address, a route, or an Origin.
pub(crate) const fn endpoint_class(kind: PrincipalKind) -> EndpointClass {
    match kind {
        PrincipalKind::BrowserExtension => EndpointClass::Extension,
        PrincipalKind::NativeAdmin => EndpointClass::Native,
        PrincipalKind::McpClient => EndpointClass::Loopback,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_decision<S>(
    sink: Option<&mut S>,
    time: EventTime,
    state_directory: IdentityId,
    principal: &Principal,
    connection: ConnectionId,
    event_code: SecurityCode,
    outcome: EventOutcome,
    next_action: EventNextAction,
    reason: String,
) -> Result<(), SecurityFailure>
where
    S: SecurityEventSink + ?Sized,
{
    let event = SecurityEvent::new(
        connection.get(),
        EventBoundary::Authorization,
        event_code,
        outcome,
        next_action,
        Some(principal.id().get()),
        Some(connection.get()),
        endpoint_class(principal.kind()),
        time,
        state_directory.get(),
        vec![MetadataEntry {
            key: "reason".into(),
            value: reason,
        }],
    )
    .map_err(|_| SecurityFailure::new(FailureCode::EventSinkUnavailable))?;
    emit_required(sink, event)
        .map(|_| ())
        .map_err(|_| SecurityFailure::new(FailureCode::EventSinkUnavailable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{SecurityEvent, SecurityEventSinkResult};
    use crate::identity::CapabilityAction;
    use crate::identity::{ConnectionId, CredentialReference, Fingerprint, PublicKey};
    use crate::{PayloadKind, SessionInput};
    use uuid::Uuid;

    struct Sink {
        unavailable: bool,
        events: Vec<SecurityEvent>,
    }
    impl SecurityEventSink for Sink {
        fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
            if self.unavailable {
                SecurityEventSinkResult::Unavailable
            } else {
                self.events.push(event);
                SecurityEventSinkResult::Accepted
            }
        }
    }
    fn key() -> PublicKey {
        PublicKey::from_uncompressed([
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ])
        .unwrap()
    }
    fn principal(id: IdentityId, ceiling: Vec<Capability>) -> Principal {
        principal_under(id, id, ceiling)
    }
    fn principal_under(
        id: IdentityId,
        state_directory: IdentityId,
        ceiling: Vec<Capability>,
    ) -> Principal {
        let mut principal = Principal::new(
            id,
            PrincipalKind::McpClient,
            key(),
            Fingerprint::new("a".repeat(64)).unwrap(),
            id,
            ceiling,
            CredentialReference::new("s", "k", id, state_directory).unwrap(),
        )
        .unwrap();
        principal.activate().unwrap();
        principal
    }
    fn setup() -> (AuthorizationContext, SessionInput<'static>, Capability) {
        let id = IdentityId::new(Uuid::from_u128(1));
        let capability = Capability::new(CapabilityAction::Read, "owned").unwrap();
        let context = AuthorizationContext::new(principal(id, vec![capability.clone()]), 1, 1, 1);
        let operation = SessionInput::new(
            capability.clone(),
            PayloadKind::Event,
            ObjectOwner::Owned(id),
            None,
        );
        (context, operation, capability)
    }
    fn connection() -> ConnectionId {
        ConnectionId::new(Uuid::from_u128(2))
    }
    fn request<'a>(
        context: &'a AuthorizationContext,
        operation: &'a SessionInput<'a>,
    ) -> AuthorizationRequest<'a> {
        AuthorizationRequest::new(context, connection(), operation, EventTime(1))
    }
    fn recording_sink() -> Sink {
        Sink {
            unavailable: false,
            events: Vec::new(),
        }
    }

    #[test]
    fn missing_and_foreign_objects_are_redacted_as_object_not_found() {
        let (context, operation, capability) = setup();
        for owner in [
            ObjectOwner::Unknown,
            ObjectOwner::Owned(IdentityId::new(Uuid::from_u128(99))),
        ] {
            let foreign = SessionInput::new(
                capability.clone(),
                operation.kind(),
                owner,
                operation.grant(),
            );
            let mut sink = recording_sink();
            let failure = authorize(request(&context, &foreign), 1, Some(&mut sink)).unwrap_err();
            assert_eq!(failure.code(), FailureCode::ObjectNotFound);
            assert_eq!(sink.events.len(), 1);
            assert_eq!(sink.events[0].outcome, EventOutcome::Rejected);
            assert_eq!(sink.events[0].code, SecurityCode::AuthorizationDenied);
            assert_eq!(sink.events[0].next_action, EventNextAction::FailClosed);
            assert_eq!(sink.events[0].metadata[0].value, "object-not_found");
        }
    }

    #[test]
    fn unauthorized_input_is_rejected_without_accepted_event() {
        let (context, operation, _) = setup();
        let denied = SessionInput::new(
            Capability::new(CapabilityAction::Write, "owned").unwrap(),
            operation.kind(),
            operation.owner(),
            None,
        );
        let mut sink = recording_sink();
        assert_eq!(
            authorize(request(&context, &denied), 1, Some(&mut sink))
                .unwrap_err()
                .code(),
            FailureCode::AuthorizationDenied
        );
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].outcome, EventOutcome::Rejected);
        assert_ne!(sink.events[0].code, SecurityCode::AuthorizationAccepted);
    }

    #[test]
    fn revoked_principal_is_denied_without_input() {
        let id = IdentityId::new(Uuid::from_u128(1));
        let capability = Capability::new(CapabilityAction::Read, "owned").unwrap();
        let mut revoked = principal(id, vec![capability.clone()]);
        revoked.revoke();
        let context = AuthorizationContext::new(revoked, 1, 1, 1);
        let operation =
            SessionInput::new(capability, PayloadKind::Event, ObjectOwner::Owned(id), None);
        let mut sink = recording_sink();
        assert_eq!(
            authorize(request(&context, &operation), 1, Some(&mut sink))
                .unwrap_err()
                .code(),
            FailureCode::AuthorizationDenied
        );
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].code, SecurityCode::AuthorizationDenied);
    }

    #[test]
    fn oversized_payload_is_rejected_before_acceptance_event() {
        let (context, operation, _) = setup();
        let mut sink = recording_sink();
        let failure = authorize(
            request(&context, &operation),
            operation.kind().max_bytes() + 1,
            Some(&mut sink),
        )
        .expect_err("oversized payload");
        assert_eq!(failure.code(), FailureCode::ResourceLimit);
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].code, SecurityCode::AuthorizationDenied);
        assert_eq!(sink.events[0].outcome, EventOutcome::Rejected);
        assert_eq!(sink.events[0].next_action, EventNextAction::FailClosed);
        assert_eq!(sink.events[0].metadata[0].value, "resource_limit");
    }

    #[test]
    fn successful_authorization_emits_neutral_event_before_one_input() {
        let (context, operation, _) = setup();
        let mut sink = recording_sink();
        authorize(request(&context, &operation), 1, Some(&mut sink)).expect("authorized operation");
        assert_eq!(sink.events.len(), 1);
        let event = &sink.events[0];
        assert_eq!(event.boundary, EventBoundary::Authorization);
        assert_eq!(event.code, SecurityCode::AuthorizationAccepted);
        assert_eq!(event.outcome, EventOutcome::Accepted);
        assert_eq!(event.next_action, EventNextAction::Continue);
        assert_eq!(
            event.metadata,
            vec![MetadataEntry {
                key: "reason".into(),
                value: "accepted".into()
            }]
        );
    }

    #[test]
    fn unavailable_required_decision_event_fails_closed_without_input() {
        let (context, operation, _) = setup();
        let mut sink = Sink {
            unavailable: true,
            events: Vec::new(),
        };
        assert_eq!(
            authorize(request(&context, &operation), 1, Some(&mut sink))
                .unwrap_err()
                .code(),
            FailureCode::EventSinkUnavailable
        );
        assert!(sink.events.is_empty());
    }

    #[test]
    fn the_state_directory_and_epoch_come_from_the_principal_snapshot() {
        let id = IdentityId::new(Uuid::from_u128(1));
        let state_directory = IdentityId::new(Uuid::from_u128(42));
        let capability = Capability::new(CapabilityAction::Read, "owned").unwrap();
        let mut value = principal_under(id, state_directory, vec![capability.clone()]);
        value.begin_rotation().unwrap();
        value
            .complete_rotation(
                key(),
                Fingerprint::new("b".repeat(64)).unwrap(),
                CredentialReference::new("s", "k2", id, state_directory).unwrap(),
            )
            .unwrap();
        let context = AuthorizationContext::new(value, 1, 1, 1);
        assert_eq!(context.epoch(), 1);
        assert_eq!(context.state_directory(), state_directory);

        let operation =
            SessionInput::new(capability, PayloadKind::Event, ObjectOwner::Owned(id), None);
        let mut sink = recording_sink();
        authorize(request(&context, &operation), 1, Some(&mut sink)).expect("authorized operation");
        assert_eq!(sink.events[0].state_directory_id, state_directory.get());
    }
}
