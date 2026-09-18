//! Stateful authorization policy for the authenticated channel boundary.
use crate::events::{
    emit_required, EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry,
    SafeNextAction as EventNextAction, SecurityCode, SecurityEvent, SecurityEventSink,
};
use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{
    Capability, ExtensionGrant, GrantLifecycle, IdentityId, Principal, PrincipalKind,
    PrincipalLifecycle,
};
use crate::{AuthorizedInput, SessionInput};

/// Inputs evaluated as one authorization decision. The object owner is an authorization fact.
pub(crate) struct AuthorizationRequest<'a> {
    pub(crate) principal: &'a Principal,
    pub(crate) context: &'a SessionInput,
    pub(crate) negotiated_contract: u16,
    pub(crate) contract_min: u16,
    pub(crate) contract_max: u16,
    pub(crate) object_owner: Option<IdentityId>,
    pub(crate) extension_grant: Option<&'a ExtensionGrant>,
    pub(crate) state_directory: IdentityId,
    pub(crate) event_time: EventTime,
}

impl<'a> AuthorizationRequest<'a> {
    pub(crate) fn new(
        principal: &'a Principal,
        context: &'a SessionInput,
        negotiated_contract: u16,
        contract_min: u16,
        contract_max: u16,
        object_owner: Option<IdentityId>,
        extension_grant: Option<&'a ExtensionGrant>,
        state_directory: IdentityId,
        event_time: EventTime,
    ) -> Self {
        Self {
            principal,
            context,
            negotiated_contract,
            contract_min,
            contract_max,
            object_owner,
            extension_grant,
            state_directory,
            event_time,
        }
    }
}

pub(crate) fn authorize<S>(
    request: AuthorizationRequest<'_>,
    payload: Vec<u8>,
    sink: Option<&mut S>,
) -> Result<AuthorizedInput, SecurityFailure>
where
    S: SecurityEventSink,
{
    let principal = request.principal;
    let context = request.context;
    let decision = if principal.id() != context.principal()
        || principal.lifecycle() != PrincipalLifecycle::Active
    {
        Err(FailureCode::AuthorizationDenied)
    } else if context.epoch() != principal.epoch() {
        Err(FailureCode::StaleEpoch)
    } else if request.negotiated_contract == 0
        || request.negotiated_contract < request.contract_min
        || request.negotiated_contract > request.contract_max
    {
        Err(FailureCode::CompatibilityUnsupported)
    } else if request.object_owner != Some(principal.owner()) {
        Err(FailureCode::ObjectNotFound)
    } else if !ceiling_allows(principal, context.requested()) {
        Err(FailureCode::AuthorizationDenied)
    } else if !grant_allows(principal, context, request.extension_grant) {
        Err(FailureCode::AuthorizationDenied)
    } else {
        Ok(())
    };
    if let Err(code) = decision {
        emit_decision(
            sink,
            request.event_time,
            request.state_directory,
            principal,
            context,
            SecurityCode::AuthorizationDenied,
            EventOutcome::Rejected,
            EventNextAction::FailClosed,
            code.as_str()
                .replace("authorization.", "")
                .replace('.', "-"),
        )?;
        return Err(SecurityFailure::with_safe_ids(
            code,
            Some(principal.id().get()),
            Some(context.connection().get()),
        ));
    }
    if payload.len() > context.kind().max_bytes() {
        emit_decision(
            sink,
            request.event_time,
            request.state_directory,
            principal,
            context,
            SecurityCode::AuthorizationDenied,
            EventOutcome::Rejected,
            EventNextAction::FailClosed,
            FailureCode::ResourceLimit
                .as_str()
                .replace("authorization.", "")
                .replace('.', "-"),
        )?;
        return Err(SecurityFailure::with_safe_ids(
            FailureCode::ResourceLimit,
            Some(principal.id().get()),
            Some(context.connection().get()),
        ));
    }
    // The event is required and must be accepted before the typed value is minted.
    emit_decision(
        sink,
        request.event_time,
        request.state_directory,
        principal,
        context,
        SecurityCode::AuthorizationAccepted,
        EventOutcome::Accepted,
        EventNextAction::Continue,
        "accepted".to_owned(),
    )?;
    Ok(AuthorizedInput::from_prevalidated(context, payload))
}

fn ceiling_allows(principal: &Principal, requested: &Capability) -> bool {
    principal
        .ceiling()
        .iter()
        .any(|ceiling| capability_covers(ceiling, requested))
}

fn grant_allows(
    principal: &Principal,
    context: &SessionInput,
    grant: Option<&ExtensionGrant>,
) -> bool {
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
            .any(|capability| capability_covers(capability, context.requested()))
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

fn emit_decision<S>(
    sink: Option<&mut S>,
    time: EventTime,
    state_directory: IdentityId,
    principal: &Principal,
    context: &SessionInput,
    event_code: SecurityCode,
    outcome: EventOutcome,
    next_action: EventNextAction,
    reason: String,
) -> Result<(), SecurityFailure>
where
    S: SecurityEventSink,
{
    let event = SecurityEvent::new(
        context.connection().get(),
        EventBoundary::Authorization,
        event_code,
        outcome,
        next_action,
        Some(principal.id().get()),
        Some(context.connection().get()),
        match principal.kind() {
            PrincipalKind::BrowserExtension => EndpointClass::Extension,
            PrincipalKind::NativeAdmin => EndpointClass::Native,
            PrincipalKind::McpClient => EndpointClass::Loopback,
        },
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
    use crate::identity::CapabilityAction;
    use uuid::Uuid;
    use super::*;
    use crate::events::{SecurityEvent, SecurityEventSinkResult};
    use crate::identity::{ConnectionId, CredentialReference, Fingerprint, PublicKey};
    use crate::{PayloadKind, SessionInput};

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
    fn principal(id: IdentityId, ceiling: Vec<Capability>) -> Principal {
        let key = [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
            0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
            0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut principal = Principal::new(
            id,
            PrincipalKind::McpClient,
            PublicKey::from_uncompressed(key).unwrap(),
            Fingerprint::new("a".repeat(64)).unwrap(),
            id,
            ceiling,
            CredentialReference::new("s", "k", id, id).unwrap(),
        )
        .unwrap();
        principal.activate().unwrap();
        principal
    }
    fn setup() -> (Principal, SessionInput, Capability) {
        let id = IdentityId::new(Uuid::from_u128(1));
        let capability = Capability::new(CapabilityAction::Read, "owned").unwrap();
        let principal = principal(id, vec![capability.clone()]);
        let context = SessionInput::new(
            ConnectionId::new(Uuid::from_u128(2)),
            id,
            0,
            capability.clone(),
            PayloadKind::Event,
        );
        (principal, context, capability)
    }
    fn request<'a>(
        principal: &'a Principal,
        context: &'a SessionInput,
        owner: Option<IdentityId>,
    ) -> AuthorizationRequest<'a> {
        AuthorizationRequest::new(
            principal,
            context,
            1,
            1,
            1,
            owner,
            None,
            principal.owner(),
            EventTime(1),
        )
    }

    #[test]
    fn missing_and_foreign_objects_are_redacted_as_object_not_found() {
        let (principal, context, _) = setup();
        for owner in [None, Some(IdentityId::new(Uuid::from_u128(99)))] {
            let mut sink = Sink {
                unavailable: false,
                events: Vec::new(),
            };
            let failure = authorize(
                request(&principal, &context, owner),
                vec![1],
                Some(&mut sink),
            )
            .unwrap_err();
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
        let (principal, context, _) = setup();
        let denied = Capability::new(CapabilityAction::Write, "owned").unwrap();
        let denied_context = SessionInput::new(
            context.connection(),
            principal.id(),
            0,
            denied,
            PayloadKind::Event,
        );
        let mut sink = Sink {
            unavailable: false,
            events: Vec::new(),
        };
        assert_eq!(
            authorize(
                request(&principal, &denied_context, Some(principal.owner())),
                vec![1],
                Some(&mut sink)
            )
            .unwrap_err()
            .code(),
            FailureCode::AuthorizationDenied
        );
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].outcome, EventOutcome::Rejected);
        assert_ne!(sink.events[0].code, SecurityCode::AuthorizationAccepted);
    }

    #[test]
    fn stale_epoch_is_rejected_without_input() {
        let (principal, context, _) = setup();
        let stale = SessionInput::new(
            context.connection(),
            principal.id(),
            1,
            context.requested().clone(),
            PayloadKind::Event,
        );
        let mut sink = Sink {
            unavailable: false,
            events: Vec::new(),
        };
        assert_eq!(
            authorize(
                request(&principal, &stale, Some(principal.owner())),
                vec![1],
                Some(&mut sink)
            )
            .unwrap_err()
            .code(),
            FailureCode::StaleEpoch
        );
        assert_eq!(sink.events.len(), 1);
    }
    #[test]
    fn oversized_payload_is_rejected_before_acceptance_event() {
        let (principal, context, _) = setup();
        let mut sink = Sink {
            unavailable: false,
            events: Vec::new(),
        };
        let failure = authorize(
            request(&principal, &context, Some(principal.owner())),
            vec![0; context.kind().max_bytes() + 1],
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
        let (principal, context, _) = setup();
        let mut sink = Sink {
            unavailable: false,
            events: Vec::new(),
        };
        let input = authorize(
            request(&principal, &context, Some(principal.owner())),
            vec![1],
            Some(&mut sink),
        )
        .unwrap();
        assert_eq!(input.payload(), &[1]);
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
        let (principal, context, _) = setup();
        let mut sink = Sink {
            unavailable: true,
            events: Vec::new(),
        };
        assert_eq!(
            authorize(
                request(&principal, &context, Some(principal.owner())),
                vec![1],
                Some(&mut sink)
            )
            .unwrap_err()
            .code(),
            FailureCode::EventSinkUnavailable
        );
        assert!(sink.events.is_empty());
    }
}
