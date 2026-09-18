macro_rules! authorization_contract_tests {
    () => {
        use crate::identity::{
            Capability, CapabilityAction, CredentialReference, ExtensionGrant, Fingerprint,
            GrantLifecycle, IdentityId, Principal, PrincipalKind, PublicKey,
        };
        use crate::{AuthorizedInput, ConnectionId, PayloadKind, SessionInput};
        use uuid::Uuid;

        fn ids() -> (IdentityId, IdentityId, IdentityId) {
            (
                IdentityId::new(Uuid::from_u128(1)),
                IdentityId::new(Uuid::from_u128(2)),
                IdentityId::new(Uuid::from_u128(3)),
            )
        }

        fn key() -> PublicKey {
            let bytes = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
                0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
                0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            PublicKey::from_uncompressed(bytes).expect("valid public key fixture")
        }

        fn capability(action: CapabilityAction, scope: &str) -> Capability {
            Capability::new(action, scope).expect("valid capability fixture")
        }

        fn credential(daemon: IdentityId) -> CredentialReference {
            CredentialReference::new("test-store", "principal-key", daemon, daemon)
                .expect("valid credential fixture")
        }

        #[test]
        fn authorization_matrix_keeps_principal_kind_and_action_ceilings_distinct() {
            let (daemon, owner, extension) = ids();
            let admin_ceiling = vec![capability(CapabilityAction::ManagePrincipals, "global")];
            let mcp_ceiling = vec![capability(CapabilityAction::Read, "owned")];
            let extension_ceiling = vec![capability(CapabilityAction::Execute, "browser")];
            let mut admin = Principal::new(
                daemon,
                PrincipalKind::NativeAdmin,
                key(),
                Fingerprint::new("a".repeat(64)).unwrap(),
                owner,
                admin_ceiling,
                credential(owner),
            )
            .unwrap();
            let mcp = Principal::new(
                IdentityId::new(Uuid::from_u128(4)),
                PrincipalKind::McpClient,
                key(),
                Fingerprint::new("b".repeat(64)).unwrap(),
                owner,
                mcp_ceiling,
                credential(owner),
            )
            .unwrap();
            let extension_principal = Principal::new(
                extension,
                PrincipalKind::BrowserExtension,
                key(),
                Fingerprint::new("c".repeat(64)).unwrap(),
                owner,
                extension_ceiling,
                credential(owner),
            )
            .unwrap();
            assert_eq!(admin.kind(), PrincipalKind::NativeAdmin);
            assert_eq!(mcp.kind(), PrincipalKind::McpClient);
            assert_eq!(extension_principal.kind(), PrincipalKind::BrowserExtension);
            assert_eq!(
                admin.ceiling()[0].action(),
                &CapabilityAction::ManagePrincipals
            );
            assert_eq!(mcp.ceiling()[0].action(), &CapabilityAction::Read);
            assert_eq!(
                extension_principal.ceiling()[0].action(),
                &CapabilityAction::Execute
            );
            admin.activate().unwrap();
            assert_eq!(
                admin.lifecycle(),
                crate::identity::PrincipalLifecycle::Active
            );
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
                    Fingerprint::new("e".repeat(64)).unwrap(),
                    credential(foreign),
                ),
                Err("rotation is not valid")
            );
            assert_eq!(principal.epoch(), 0);
            assert_eq!(
                principal.lifecycle(),
                crate::identity::PrincipalLifecycle::Rotating
            );
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
            assert_eq!(daemon, IdentityId::new(Uuid::from_u128(1)));
            assert!(ExtensionGrant::new(extension, owner, Vec::new(), 7).is_err());
        }

        #[test]
        fn authorization_context_binds_connection_principal_epoch_contract_action_and_kind() {
            let (_, owner, _) = ids();
            let requested = capability(CapabilityAction::Read, "owned/status");
            let context = SessionInput::new(
                ConnectionId::new(Uuid::from_u128(8)),
                owner,
                12,
                requested.clone(),
                PayloadKind::Event,
            );
            assert_eq!(context.connection(), ConnectionId::new(Uuid::from_u128(8)));
            assert_eq!(context.principal(), owner);
            assert_eq!(context.epoch(), 12);
            assert_eq!(context.requested(), &requested);
            assert_eq!(context.kind(), PayloadKind::Event);
        }

        #[test]
        fn authorization_capability_and_input_bounds_fail_closed_at_each_boundary() {
            assert!(Capability::new(CapabilityAction::Read, "").is_err());
            assert!(Capability::new(CapabilityAction::Read, "x".repeat(256)).is_ok());
            assert!(Capability::new(CapabilityAction::Read, "x".repeat(257)).is_err());
            let (_, owner, _) = ids();
            let context = SessionInput::new(
                ConnectionId::new(Uuid::from_u128(9)),
                owner,
                1,
                capability(CapabilityAction::Read, "owned"),
                PayloadKind::Event,
            );
            assert!(AuthorizedInput::authorized(&context, vec![0; 1_048_535]).is_ok());
            assert_eq!(
                AuthorizedInput::authorized(&context, vec![0; 1_048_536])
                    .unwrap_err()
                    .code(),
                crate::failures::FailureCode::ResourceLimit
            );
        }

        #[test]
        fn authorization_admin_only_actions_have_explicit_non_admin_ceiling_controls() {
            let non_admin = [
                CapabilityAction::ManagePrincipals,
                CapabilityAction::Rotate,
                CapabilityAction::Revoke,
            ];
            let mcp = capability(CapabilityAction::Read, "owned");
            let extension = capability(CapabilityAction::Execute, "browser");
            assert!(non_admin.iter().all(|action| action != mcp.action()));
            assert!(non_admin.iter().all(|action| action != extension.action()));
            assert_eq!(CapabilityAction::Administer, CapabilityAction::Administer);
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
    };
}
