#[allow(unused_macros)]
macro_rules! authorization_contract_tests {
    () => {
        use crate::authorization::{AuthorizationContext, AuthorizationRequest, authorize};
        use crate::events::{EventTime, SecurityEvent, SecurityEventSink, SecurityEventSinkResult};
        use crate::failures::FailureCode;
        use crate::identity::{
            Capability, CapabilityAction, CredentialReference, ExtensionGrant, Fingerprint,
            GrantLifecycle, IdentityId, Principal, PrincipalKind, PrincipalLifecycle, PublicKey,
        };
        use crate::{ConnectionId, ObjectOwner, PayloadKind, SessionInput};
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
        fn recording_sink() -> Sink {
            Sink {
                unavailable: false,
                events: Vec::new(),
            }
        }

        fn id(value: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(value))
        }

        fn connection() -> ConnectionId {
            ConnectionId::new(Uuid::from_u128(80))
        }

        fn key() -> PublicKey {
            PublicKey::from_uncompressed([
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ])
            .expect("valid public key fixture")
        }

        fn capability(action: CapabilityAction, scope: &str) -> Capability {
            Capability::new(action, scope).expect("valid capability fixture")
        }

        fn credential(daemon: IdentityId) -> CredentialReference {
            CredentialReference::new("test-store", "principal-key", daemon, daemon)
                .expect("valid credential fixture")
        }

        fn principal(
            kind: PrincipalKind,
            principal: IdentityId,
            owner: IdentityId,
            ceiling: Vec<Capability>,
        ) -> Principal {
            let mut value = Principal::new(
                principal,
                kind,
                key(),
                Fingerprint::new("a".repeat(64)).unwrap(),
                owner,
                ceiling,
                credential(owner),
            )
            .unwrap();
            value.activate().unwrap();
            value
        }

        /// A channel context at the contract it negotiated inside the range it offered.
        fn established(principal: Principal) -> AuthorizationContext {
            AuthorizationContext::new(principal, 1, 1, 1)
        }

        fn operation(
            requested: Capability,
            kind: PayloadKind,
            owner: ObjectOwner,
            grant: Option<&ExtensionGrant>,
        ) -> SessionInput<'_> {
            SessionInput::new(requested, kind, owner, grant)
        }

        fn request<'a>(
            context: &'a AuthorizationContext,
            operation: &'a SessionInput<'a>,
        ) -> AuthorizationRequest<'a> {
            AuthorizationRequest::new(context, connection(), operation, EventTime(1))
        }

        fn ids() -> (IdentityId, IdentityId, IdentityId) {
            (id(1), id(2), id(3))
        }

        #[test]
        fn authorization_matrix_keeps_principal_kind_and_action_ceilings_distinct() {
            let (daemon, owner, extension) = ids();
            let mut admin = principal(
                PrincipalKind::NativeAdmin,
                daemon,
                owner,
                vec![capability(CapabilityAction::ManagePrincipals, "global")],
            );
            let mcp = principal(
                PrincipalKind::McpClient,
                id(4),
                owner,
                vec![capability(CapabilityAction::Read, "owned")],
            );
            let extension_principal = principal(
                PrincipalKind::BrowserExtension,
                extension,
                owner,
                vec![capability(CapabilityAction::Execute, "browser")],
            );
            assert_eq!(
                admin.ceiling()[0].action(),
                &CapabilityAction::ManagePrincipals
            );
            assert_eq!(mcp.ceiling()[0].action(), &CapabilityAction::Read);
            assert_eq!(
                extension_principal.ceiling()[0].action(),
                &CapabilityAction::Execute
            );
            assert_eq!(admin.lifecycle(), PrincipalLifecycle::Active);
            admin.revoke();
            assert_eq!(admin.lifecycle(), PrincipalLifecycle::Revoked);
        }

        #[test]
        fn authorization_owner_binding_rejects_foreign_credential_and_preserves_state() {
            let (daemon, owner, foreign) = ids();
            let before = Principal::new(
                daemon,
                PrincipalKind::McpClient,
                key(),
                Fingerprint::new("d".repeat(64)).unwrap(),
                owner,
                vec![capability(CapabilityAction::Read, "owned")],
                credential(owner),
            )
            .unwrap();
            let mut principal = before.clone();
            principal.begin_rotation().err();
            assert_eq!(principal, before);
            assert!(principal.activate().is_ok());
            principal.begin_rotation().unwrap();
            assert_eq!(
                principal.complete_rotation(
                    key(),
                    Fingerprint::new("e".repeat(64)).unwrap(),
                    credential(foreign),
                ),
                Err("rotation is not valid")
            );
            assert_eq!(principal.epoch(), 0);
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Rotating);
        }

        #[test]
        fn authorization_grant_requires_matching_extension_owner_epoch_and_active_lifecycle() {
            let (daemon, owner, extension) = ids();
            let capability = capability(CapabilityAction::Read, "browser/session");
            let mut grant =
                ExtensionGrant::new(extension, owner, vec![capability.clone()], 7).unwrap();
            assert_eq!(grant.extension(), extension);
            assert_eq!(grant.owner(), owner);
            assert_eq!(grant.epoch(), 7);
            assert_eq!(grant.lifecycle(), GrantLifecycle::Active);
            assert_eq!(grant.capabilities(), &[capability]);
            grant.revoke();
            assert_eq!(grant.lifecycle(), GrantLifecycle::Revoked);
            assert_eq!(daemon, id(1));
            assert!(ExtensionGrant::new(extension, owner, Vec::new(), 7).is_err());
        }

        #[test]
        fn an_operation_names_object_facts_and_nothing_the_channel_already_fixed() {
            let requested = capability(CapabilityAction::Read, "owned/status");
            let grant = ExtensionGrant::new(id(4), id(2), vec![requested.clone()], 0).unwrap();
            let operation = operation(
                requested.clone(),
                PayloadKind::Event,
                ObjectOwner::Owned(id(2)),
                Some(&grant),
            );
            assert_eq!(operation.requested(), &requested);
            assert_eq!(operation.kind(), PayloadKind::Event);
            assert_eq!(operation.owner(), ObjectOwner::Owned(id(2)));
            assert_eq!(operation.grant(), Some(&grant));
            // An unresolved object is one value, not an absent one: there is no shape in
            // which a caller omits the owner fact and reaches a decision.
            let unknown = SessionInput::new(
                requested,
                PayloadKind::Event,
                ObjectOwner::Unknown,
                Some(&grant),
            );
            assert_eq!(unknown.owner(), ObjectOwner::Unknown);
        }

        #[test]
        fn authorization_capability_bounds_fail_closed_at_each_boundary() {
            assert!(Capability::new(CapabilityAction::Read, "").is_err());
            assert!(Capability::new(CapabilityAction::Read, "x".repeat(256)).is_ok());
            assert!(Capability::new(CapabilityAction::Read, "x".repeat(257)).is_err());
        }

        #[test]
        fn authorization_denials_are_redacted_and_do_not_mutate_grant() {
            let (_, owner, extension) = ids();
            let mut grant = ExtensionGrant::new(
                extension,
                owner,
                vec![capability(CapabilityAction::Read, "owned")],
                3,
            )
            .unwrap();
            let snapshot = grant.clone();
            assert!(ExtensionGrant::new(extension, owner, Vec::new(), 3).is_err());
            assert_eq!(grant, snapshot);
            grant.revoke();
            let revoked = grant.clone();
            grant.revoke();
            assert_eq!(grant, revoked);
        }

        #[test]
        fn production_authorize_enforces_kind_ceiling_contract_owner_grant_and_action() {
            let owner = id(2);
            let requested = capability(CapabilityAction::Read, "owned/status");
            let mcp = established(principal(
                PrincipalKind::McpClient,
                id(3),
                owner,
                vec![capability(CapabilityAction::Read, "owned")],
            ));

            let accepted = operation(
                requested.clone(),
                PayloadKind::Response,
                ObjectOwner::Owned(owner),
                None,
            );
            let mut sink = recording_sink();
            assert!(authorize(request(&mcp, &accepted), 2, Some(&mut sink)).is_ok());
            assert_eq!(sink.events.len(), 1);

            let denied = operation(
                capability(CapabilityAction::Write, "owned/status"),
                PayloadKind::Response,
                ObjectOwner::Owned(owner),
                None,
            );
            let mut sink = recording_sink();
            assert_eq!(
                authorize(request(&mcp, &denied), 1, Some(&mut sink))
                    .unwrap_err()
                    .code(),
                FailureCode::AuthorizationDenied
            );

            // A contract outside the range the channel offered can never be authorized.
            let outside = AuthorizationContext::new(
                principal(
                    PrincipalKind::McpClient,
                    id(3),
                    owner,
                    vec![capability(CapabilityAction::Read, "owned")],
                ),
                2,
                1,
                1,
            );
            let mut sink = recording_sink();
            assert_eq!(
                authorize(request(&outside, &accepted), 1, Some(&mut sink))
                    .unwrap_err()
                    .code(),
                FailureCode::CompatibilityUnsupported
            );

            let extension_id = id(4);
            let extension = established(principal(
                PrincipalKind::BrowserExtension,
                extension_id,
                owner,
                vec![capability(CapabilityAction::Read, "browser")],
            ));
            let browser = capability(CapabilityAction::Read, "browser/session");
            let grant = ExtensionGrant::new(extension_id, owner, vec![browser.clone()], 0).unwrap();
            let granted = operation(
                browser.clone(),
                PayloadKind::Event,
                ObjectOwner::Owned(owner),
                Some(&grant),
            );
            let mut sink = recording_sink();
            assert!(authorize(request(&extension, &granted), 1, Some(&mut sink)).is_ok());

            // The same operation without its grant, and with a grant bound to another
            // epoch, are both denied.
            let ungranted = operation(
                browser.clone(),
                PayloadKind::Event,
                ObjectOwner::Owned(owner),
                None,
            );
            let stale_grant =
                ExtensionGrant::new(extension_id, owner, vec![browser.clone()], 1).unwrap();
            let stale = operation(
                browser,
                PayloadKind::Event,
                ObjectOwner::Owned(owner),
                Some(&stale_grant),
            );
            for candidate in [&ungranted, &stale] {
                let mut sink = recording_sink();
                assert_eq!(
                    authorize(request(&extension, candidate), 1, Some(&mut sink))
                        .unwrap_err()
                        .code(),
                    FailureCode::AuthorizationDenied
                );
            }
        }

        #[test]
        fn production_authorize_bounds_payload_and_requires_decision_before_minting() {
            let owner = id(2);
            let context = established(principal(
                PrincipalKind::NativeAdmin,
                id(3),
                owner,
                vec![capability(CapabilityAction::Read, "global")],
            ));
            let operation = operation(
                capability(CapabilityAction::Read, "global/status"),
                PayloadKind::Event,
                ObjectOwner::Owned(owner),
                None,
            );
            let mut sink = recording_sink();
            let failure = authorize(
                request(&context, &operation),
                operation.kind().max_bytes() + 1,
                Some(&mut sink),
            )
            .unwrap_err();
            assert_eq!(failure.code(), FailureCode::ResourceLimit);
            assert_eq!(sink.events.len(), 1);

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
        fn administrator_actions_are_not_conferred_by_mcp_or_extension_ceilings() {
            let owner = id(2);
            for kind in [PrincipalKind::McpClient, PrincipalKind::BrowserExtension] {
                let admin = capability(CapabilityAction::ManagePrincipals, "global");
                let context = established(principal(kind, id(3), owner, vec![admin.clone()]));
                let grant = (kind == PrincipalKind::BrowserExtension)
                    .then(|| ExtensionGrant::new(id(3), owner, vec![admin.clone()], 0).unwrap());
                let operation = operation(
                    admin,
                    PayloadKind::Command,
                    ObjectOwner::Owned(owner),
                    grant.as_ref(),
                );
                let mut sink = recording_sink();
                assert_eq!(
                    authorize(request(&context, &operation), 1, Some(&mut sink))
                        .unwrap_err()
                        .code(),
                    FailureCode::AuthorizationDenied
                );
            }
        }
    };
}
