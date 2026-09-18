macro_rules! authorization_privacy_tests {
    () => {
        use crate::authorization::{authorize, AuthorizationRequest};
        use crate::events::{EventTime, SecurityEvent, SecurityEventSink, SecurityEventSinkResult};
        use crate::identity::{Capability, CapabilityAction, CredentialReference, Fingerprint, IdentityId, Principal, PrincipalKind, PublicKey};
        use crate::{ConnectionId, PayloadKind, SessionInput};
        use uuid::Uuid;

        struct Sink { events: Vec<SecurityEvent> }
        impl SecurityEventSink for Sink {
            fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult { self.events.push(event); SecurityEventSinkResult::Accepted }
        }
        fn id(value: u128) -> IdentityId { IdentityId::new(Uuid::from_u128(value)) }
        fn key() -> PublicKey { PublicKey::from_uncompressed([
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
            0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
            0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ]).unwrap() }
        fn principal() -> Principal {
            let owner = id(7); let credential = CredentialReference::new("test-store", "principal-key", owner, owner).unwrap();
            let mut value = Principal::new(id(1), PrincipalKind::McpClient, key(), Fingerprint::new("a".repeat(64)).unwrap(), owner, vec![Capability::new(CapabilityAction::Read, "owned").unwrap()], credential).unwrap();
            value.activate().unwrap(); value
        }
        fn request<'a>(principal: &'a Principal, context: &'a SessionInput, owner: Option<IdentityId>) -> AuthorizationRequest<'a> { AuthorizationRequest::new(principal, context, 1, 1, 1, owner, None, id(99), EventTime(1)) }
        fn context(principal: &Principal, kind: PayloadKind) -> SessionInput { SessionInput::new(ConnectionId::new(Uuid::from_u128(80)), principal.id(), principal.epoch(), Capability::new(CapabilityAction::Read, "owned/object").unwrap(), kind) }

        #[test]
        fn unknown_cross_owner_filtered_and_unauthorized_reads_share_object_not_found() {
            let principal = principal(); let context = context(&principal, PayloadKind::Response);
            for owner in [None, Some(id(8))] {
                let mut sink = Sink { events: Vec::new() };
                let failure = authorize(request(&principal, &context, owner), b"protected-object".to_vec(), Some(&mut sink)).unwrap_err();
                assert_eq!(failure.code(), crate::failures::FailureCode::ObjectNotFound);
                assert_eq!(failure.safe_next_action(), crate::failures::SafeNextAction::DoNotInferObjectExistence);
                assert_eq!(sink.events.len(), 1);
                assert_eq!(sink.events[0].metadata()[0].value, "object-not_found");
            }
            let denied = SessionInput::new(context.connection(), principal.id(), 0, Capability::new(CapabilityAction::Write, "owned/object").unwrap(), PayloadKind::Response);
            let mut sink = Sink { events: Vec::new() };
            let failure = authorize(request(&principal, &denied, Some(id(7))), b"protected-object".to_vec(), Some(&mut sink)).unwrap_err();
            assert_eq!(failure.code(), crate::failures::FailureCode::AuthorizationDenied);
            assert!(!format!("{failure}").contains("protected-object"));
        }

        #[test]
        fn authorization_precedes_payload_acceptance_for_every_typed_output_class() {
            let principal = principal();
            for kind in [PayloadKind::Command, PayloadKind::Response, PayloadKind::Event] {
                let context = context(&principal, kind); let mut sink = Sink { events: Vec::new() };
                assert!(authorize(request(&principal, &context, Some(id(7))), b"redacted-value".to_vec(), Some(&mut sink)).is_ok());
                assert_eq!(sink.events.len(), 1);
                assert_eq!(sink.events[0].boundary, crate::events::EventBoundary::Authorization);
                assert!(!sink.events[0].metadata().iter().any(|entry| entry.value.contains("redacted")));
            }
        }

        #[test]
        fn authorization_event_and_failure_projections_reject_protected_identifiers() {
            let failure = crate::failures::SecurityFailure::with_safe_ids(crate::failures::FailureCode::AuthorizationDenied, Some(Uuid::from_u128(1)), Some(Uuid::from_u128(2)));
            assert!(!failure.to_string().contains("object"));
            assert_eq!(failure.redacted().1, crate::failures::FailureCode::AuthorizationDenied);
            assert!(crate::events::SecurityEvent::new(Uuid::from_u128(3), crate::events::EventBoundary::Authorization, crate::events::SecurityCode::AuthorizationDenied, crate::events::EventOutcome::Rejected, crate::events::SafeNextAction::FailClosed, None, None, crate::events::EndpointClass::Loopback, crate::events::EventTime(1), id(99).get(), vec![crate::events::MetadataEntry { key: "reason".into(), value: "artifact-payload".into() }]).is_err());
        }
    };
}
